"""
透明代理处理器 - 匹配规则并关联请求/响应后上报
"""
import json
import logging
import threading
import time
from urllib.parse import parse_qs, urlparse

from .api_client import APIClient, CaptureRule
from .config import ClientConfig
from .logger import log_matched_request, log_unmatched_request

logger = logging.getLogger(__name__)


class TransparentProxyHandler:
    """透明抓包处理器（不拦截，只做匹配、关联、上报）"""

    def __init__(self, config: ClientConfig, api_client: APIClient):
        self.config = config
        self.api_client = api_client
        self._pending_requests = {}
        self._pending_lock = threading.Lock()

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

    def _handle_http_request(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int,
                             payload: bytes, http_info: dict) -> bool:
        method = http_info.get("method", "GET")
        protocol = http_info.get("protocol", "http")
        host = http_info.get("host", dst_addr)
        path = http_info.get("path", "/")

        # 仅对接口1规则命中的请求建会话
        rule = self.api_client.find_matching_rule(method, protocol, host, dst_port, path)
        if not rule:
            log_unmatched_request(method, protocol, host, dst_port, path)
            return False

        request_headers_raw, request_body_bytes = self._split_http_payload(payload)
        request_headers = self._headers_text_to_dict(request_headers_raw or http_info.get("headers", ""))
        request_body_text = self._decode_body(request_body_bytes)
        request_query = self._extract_query_params(path)
        request_body_params = self._extract_body_params(request_headers, request_body_text)

        flow_key = self._build_flow_key(src_addr, src_port, dst_addr, dst_port)
        with self._pending_lock:
            self._pending_requests[flow_key] = {
                "rule": rule,
                "request": {
                    "line": {
                        "method": method,
                        "protocol": protocol,
                        "host": host,
                        "port": dst_port,
                        "path": path,
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
            }
        return True

    def _handle_http_response(self, src_addr: str, src_port: int, dst_addr: str, dst_port: int,
                              payload: bytes, http_info: dict) -> bool:
        # 响应方向的连接键与请求方向相反
        flow_key = self._build_flow_key(dst_addr, dst_port, src_addr, src_port)
        with self._pending_lock:
            pending = self._pending_requests.pop(flow_key, None)

        if not pending:
            return False

        rule: CaptureRule = pending["rule"]
        request_obj = pending["request"]

        response_headers_raw, response_body_bytes = self._split_http_payload(payload)
        response_headers = self._headers_text_to_dict(response_headers_raw or http_info.get("headers", ""))
        response_body_text = self._decode_body(response_body_bytes if response_body_bytes else http_info.get("body", b""))

        response_obj = {
            "line": {
                "version": http_info.get("version", "HTTP/1.1"),
                "status_code": http_info.get("status_code", 0),
                "reason": http_info.get("reason", ""),
            },
            "headers": response_headers,
            "body": response_body_text,
            "payload_size": len(payload),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

        capture_json = {
            "api_id": rule.api_id,
            "api_code": rule.api_code,
            "api_name": rule.api_name,
            "network": {
                "request": request_obj,
                "response": response_obj,
            }
        }

        upload_status = "FAILED"
        try:
            success = self.api_client.upload_capture_data(
                rule.api_id,
                request_data=request_obj,
                response_data=response_obj,
                capture_data=capture_json,
            )
            upload_status = "SUCCESS" if success else "FAILED"
        except Exception as e:
            logger.error(f"Upload failed: {e}")

        req_line = request_obj["line"]
        log_matched_request(
            req_line["method"],
            req_line["protocol"],
            req_line["host"],
            req_line["port"],
            req_line["path"],
            rule.api_id,
            upload_status,
        )
        return True

    @staticmethod
    def _build_flow_key(src_addr: str, src_port: int, dst_addr: str, dst_port: int) -> str:
        return f"{src_addr}:{src_port}->{dst_addr}:{dst_port}"

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
