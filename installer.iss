; GDPost DT Client 安装脚本 - Inno Setup
; 使用方法：
; 1. 先运行 PyInstaller 生成 GdpostClient.exe
; 2. 下载并安装 Inno Setup: https://jrsoftware.org/isinfo.php
; 3. 在 Inno Setup 中打开此文件并编译

#define MyAppName "GDPost DT Client"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Your Company"
#define MyAppURL "http://100.194.2.74:9909"
#define MyAppExeName "GdpostClient.exe"

[Setup]
; 基本信息
AppId={{GDPOST-DT-CLIENT-2024}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\GdpostClient
DisableProgramGroupPage=yes
LicenseFile=LICENSE.txt
InfoBeforeFile=README.md
OutputDir=installer_output
OutputBaseFilename=GDPost_DT_Client_Setup_v{#MyAppVersion}
SetupIconFile=icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern

; 权限要求（管理员权限）
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Windows 版本要求
MinVersion=6.1sp1
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "installservice"; Description: "安装为 Windows 服务（开机自动启动）"; GroupDescription: "服务配置:"; Flags: checkablealone
Name: "startservice"; Description: "立即启动服务"; GroupDescription: "服务配置:"; Flags: unchecked

[Files]
; 主程序
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; 配置文件
Source: ".env.example"; DestDir: "{app}"; DestName: ".env"; Flags: onlyifdoesntexist
; 说明文档
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
; 许可证（如果有）
; Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; 创建日志目录
Name: "{app}\logs"; Permissions: everyone-modify

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "run"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "run"; Tasks: desktopicon

[Run]
; 安装后打开配置目录
Filename: "{winexplorer}"; Parameters: "{app}"; Description: "打开安装目录"; Flags: postinstall skipifsilent
; 安装并启动服务
Filename: "{app}\{#MyAppExeName}"; Parameters: "install"; Description: "安装 Windows 服务"; Flags: runhidden; Tasks: installservice
Filename: "{app}\{#MyAppExeName}"; Parameters: "run"; Description: "立即启动"; Flags: nowait; Tasks: startservice

[UninstallRun]
; 卸载前停止并移除服务
Filename: "{app}\{#MyAppExeName}"; Parameters: "uninstall"; Flags: runhidden

[Registry]
; 可选：写入注册表卸载信息
Root: HKLM; Subkey: "SOFTWARE\{#MyAppName}"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey

[UninstallDelete]
; 卸载时删除的文件（注意：.env 配置文件会被保留）
Type: filesandordirs; Name: "{app}\logs"
Type: dirifempty; Name: "{app}"

[Code]
// 安装前检查
function InitializeSetup(): Boolean;
begin
  // 检查 .NET Framework（如果需要）
  // 检查管理员权限
  if not IsAdminLoggedOn then begin
    MsgBox('安装程序需要管理员权限，请右键点击选择"以管理员身份运行"。', mbError, MB_OK);
    Result := false;
    exit;
  end;
  
  Result := true;
end;

// 安装后提示
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    // 安装完成后提示用户配置
    if WizardIsTaskSelected('installservice') then begin
      MsgBox('服务已安装并设置为开机自动启动。' + #13#10 + #13#10 +
             '请编辑安装目录下的 .env 文件配置服务器地址，然后重启服务。' + #13#10 +
             '管理命令：net start GdpostClient / net stop GdpostClient', 
             mbInformation, MB_OK);
    end else begin
      MsgBox('安装完成。' + #13#10 + #13#10 +
             '请编辑安装目录下的 .env 文件配置服务器地址。' + #13#10 +
             '然后运行：GdpostClient.exe install 安装为服务',
             mbInformation, MB_OK);
    end;
  end;
end;
