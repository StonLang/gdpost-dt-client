"""
透明代理处理器 - 匹配规则并关联请求/响应后上报
"""
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

from .api_client import APIClient, CaptureRule
from .config import ClientConfig
from .logger import log_matched_request

logger = logging.getLogger(__name__)


class TransparentProxyHandler:
    """透明抓包处理器（不拦截，只做匹配、关联、上报）"""

    def __init__(self, config: ClientConfig, api_client: APIClient):
        self.config = config
        self.api_client = api_client
        self._pending_requests = {}
        self._pending_lock = threading.Lock()
        # 上传放到单线程 executor，避免阻塞解析线程/抓包线程
        self._upload_executor = ThreadPoolExecutor(max_workers=1)

    def handle_request(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int,
                       payload: bytes, http_info: dict, packet: object) -> bool:
        """
        处理抓到的报文（请求或响应）
        Returns:
            bool: 是否属于可识别的 HTTP 事务
        """
        message_type = http_info.get("message_type", "request")
        if message_type == "response":
            return self._handle_http_response(src_addr, src_port, dst_addr, dst_port, payload, http_info)
        return self._handle_http_request(src_addr, src_port, dst_addr, dst_port, payload, http_info)

    def _handle_http_request(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int, payload: bytes, http_info: dict) -> bool:
        method = http_info.get("method", "GET")
        protocol = (http_info.get("protocol", "http") or "http").lower()
        host = self._normalize_host(http_info.get("host") or str(dst_addr))
        path = http_info.get("path", "/")
        path_for_rule = self._normalize_request_path_for_match(path)

        # 仅当与接口1 规则完全一致（主机/端口/协议/方法/路径）时才建会话并抓包上报
        rule = self.api_client.find_matching_rule(
            method, protocol, host, dst_port, path_for_rule
        )

        # 用于日志可读；同时也会构建 request_data 里需要的真正 URL（不带 method）
        url = self._format_request_url(method, protocol, host, dst_port, path)
        # 避免对每个 HTTP 包都写日志导致抓包线程被 I/O 拖慢
        # logger.info(f"[地址] {url}")
        
        if not rule:
            # 未命中规则：不写 matched 日志、不上报、不建会话
            return False

        logger.info(f"[成功匹配地址] {url}")

        request_headers_raw, request_body_bytes = self._split_http_payload(payload)
        request_headers = self._headers_text_to_dict(request_headers_raw or http_info.get("headers", ""))
        request_body_text = self._decode_body(request_body_bytes)
        # 限制上传体积，避免同步上传大响应导致浏览器超时/卡转
        max_body_for_upload = 200 * 1024  # 200KB
        if len(request_body_text) > max_body_for_upload:
            request_body_text = request_body_text[:max_body_for_upload] + "...[truncated]"
        request_query = self._extract_query_params(path)
        request_body_params = self._extract_body_params(request_headers, request_body_text)

        # 组装给 API2 的 request_data（用于唯一追踪一次请求的上下文）
        default_port = 80 if protocol == "http" else 443
        if dst_port and dst_port != default_port:
            url_only = f"{protocol}://{host}:{dst_port}{path}"
        else:
            url_only = f"{protocol}://{host}{path}"

        request_data = {
            "method": method,
            "url": url_only,
            "headers": request_headers,
            "body": request_body_params,
            "query_params": request_query,
            "path_params": {},
        }

        # logger.info(f"request_headers={request_headers}")
        # logger.info(f"request_body_text={request_body_text}")
        # logger.info(f"request_query={request_query}")
        # logger.info(f"request_body_params={request_body_params}")

        # 当前请求唯一标识，用于与后续响应配对，并随同上报发送给 API2
        tracking_id = uuid.uuid4().hex

        flow_key = self._build_flow_key(src_addr, src_port, dst_addr, dst_port)
        with self._pending_lock:
            self._pending_requests[flow_key] = {
                "rule": rule,
                "tracking_id": tracking_id,
                "request": {
                    "line": {
                        "method": method,
                        "protocol": protocol,
                        "host": host,
                        "port": dst_port,
                        "path": path_for_rule,
                    },
                    "headers": request_headers,
                    "params": {
                        "query": request_query,
                        "body": request_body_params,
                    },
                    "body": request_body_text,
                    "payload_size": len(payload),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                },
                "request_data": request_data,
            }
        return True

    def _handle_http_response(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int, payload: bytes, http_info: dict) -> bool:
        # 响应方向的连接键与请求方向相反
        flow_key = self._build_flow_key(dst_addr, dst_port, src_addr, src_port)
        with self._pending_lock:
            pending = self._pending_requests.pop(flow_key, None)

        if not pending:
            return False

        rule: CaptureRule = pending["rule"]
        request_obj = pending["request"]
        tracking_id = pending.get("tracking_id")
        request_data = pending.get("request_data", request_obj)

        response_headers_raw, response_body_bytes = self._split_http_payload(payload)
        response_headers = self._headers_text_to_dict(response_headers_raw or http_info.get("headers", ""))
        response_body_text = self._decode_body(response_body_bytes if response_body_bytes else http_info.get("body", b""))


        # aaa = http_info.get("body", b"")
        # logger.info("1111111111111111")
        # logger.info(f"response_body_bytes={response_body_bytes}")
        # logger.info(f"response_body_text={response_body_text}")
        # logger.info(f"aaa={aaa}")

        # 组装给 API2 的 response_data（按你要求的顶层结构）
        content_type = response_headers.get("Content-Type", "").lower()
        # 按你要求 response_data.body 必须是“对象”。
        # - 若能解析出 JSON：用解析结果
        # - 否则：放入 {"raw": "..."}，避免上传字段类型不一致
        # 按你的要求：非 JSON 响应 body 直接置空（空对象）
        response_body_parsed = {}
        if "application/json" in content_type:
            try:
                response_body_parsed = json.loads(response_body_text) if response_body_text else {}
            except Exception:
                response_body_parsed = {}

        response_data = {
            "status_code": http_info.get("status_code", 0),
            "headers": response_headers,
            "body": response_body_parsed,
        }

        req_line = request_obj["line"]
        # 异步上传（并在完成后写 matched 日志）
        def _upload_task():
            upload_status = "FAILED"
            try:
                success = self.api_client.upload_capture_data(
                    rule.api_id,
                    request_data=request_data,
                    response_data=response_data,
                    tracking_id=tracking_id,
                )
                upload_status = "SUCCESS" if success else "FAILED"
            except Exception as e:
                logger.error(f"Upload failed: {e}")
            log_matched_request(
                req_line["method"],
                req_line["protocol"],
                req_line["host"],
                req_line["port"],
                req_line["path"],
                rule.api_id,
                upload_status,
            )

        self._upload_executor.submit(_upload_task)
        return True

    @staticmethod
    def _build_flow_key(src_addr: str, src_port: int, dst_addr: str, dst_port: int) -> str:
        return f"{src_addr}:{src_port}->{dst_addr}:{dst_port}"

    @staticmethod
    def _normalize_host(host: str) -> str:
        """去掉 Host 头中的端口（若存在），便于与规则中的 req_host 一致。"""
        if not host:
            return host
        host = host.strip()
        if host.startswith("["):
            return host
        if ":" in host:
            tail = host.rsplit(":", 1)[-1]
            if tail.isdigit():
                return host.rsplit(":", 1)[0]
        return host

    @staticmethod
    def _normalize_request_path_for_match(path: str) -> str:
        """绝对 URL 请求行时只取 path 部分；查询串不参与路径匹配。"""
        if not path:
            return "/"
        if path.startswith("http://") or path.startswith("https://"):
            p = urlparse(path)
            return p.path or "/"
        return path.split("?", 1)[0]

    @staticmethod
    def _format_request_url(method: str, protocol: str, host: str, port: int, path: str) -> str:
        """用于未匹配时仅打印的可读请求地址。"""
        default_port = 80 if protocol == "http" else 443
        if port and port != default_port:
            return f"{method} {protocol}://{host}:{port}{path}"
        return f"{method} {protocol}://{host}{path}"

    @staticmethod
    def _split_http_payload(payload: bytes):
        if not payload:
            return "", b""
        header_end = payload.find(b"\r\n\r\n")
        if header_end == -1:
            return payload.decode("utf-8", errors="ignore"), b""
        headers = payload[:header_end].decode("utf-8", errors="ignore")
        body = payload[header_end + 4:]
        return headers, body

    @staticmethod
    def _headers_text_to_dict(headers_text: str) -> dict:
        headers = {}
        if not headers_text:
            return headers
        lines = headers_text.split("\r\n")
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers

    @staticmethod
    def _extract_query_params(path: str) -> dict:
        parsed = urlparse(path if path else "/")
        return {k: v if len(v) > 1 else v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    @staticmethod
    def _extract_body_params(headers: dict, body_text: str):
        if not body_text:
            return {}
        content_type = headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            try:
                return json.loads(body_text)
            except Exception:
                return {}
        if "application/x-www-form-urlencoded" in content_type:
            parsed = parse_qs(body_text, keep_blank_values=True)
            return {k: v if len(v) > 1 else v[0] for k, v in parsed.items()}
        return {}

    @staticmethod
    def _decode_body(body: bytes) -> str:
        if body is None:
            return ""
        if isinstance(body, str):
            return body
        # 只做轻量解码，避免二进制或超大正文影响性能
        if len(body) > 1024 * 1024:
            body = body[:1024 * 1024]
        return body.decode("utf-8", errors="ignore")
