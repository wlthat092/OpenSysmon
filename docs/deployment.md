# 安装部署

## 文档范围

本文档说明 OpenSysmon 的构建、签名、安装、升级、卸载、事件描述资源安装和远程部署流程。正文优先描述稳定的通用流程，文末和示例部分补充当前项目正在使用的目标环境。

## 构建前提

- Windows 主机具备管理员权限。
- 已安装 Visual Studio 2022 或对应的 Build Tools。
- 已安装 Windows SDK / WDK。
- 用户态构建依赖 Windows Message Compiler，也就是 `mc.exe`。
- Event 24 剪贴板 RPC helper 依赖 MIDL 编译器 `midl.exe` 生成 `SysmonClipboard.idl` 的客户端/服务端 stub。
- 驱动态构建依赖本机可用的 `cl.exe`、`link.exe`、内核头文件和 `fltMgr.lib` 等库。
- 如需远程部署，当前脚本默认依赖本机可直接使用 `ssh` 和 `scp` 连接目标机。

## 本地编译

### 编译 `SysmonUser`

`SysmonUser/build.ps1` 会先定位 `mc.exe`，根据 `SysmonUser/resources/sysmon_provider.man` 生成消息资源；随后定位 `midl.exe`，为 `SysmonClipboard.idl` 生成 RPC stub；最后用 MSBuild 重建 `SysmonUser.vcxproj`。

常用命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\SysmonUser\build.ps1
```

如果需要显式指定配置：

```powershell
powershell -ExecutionPolicy Bypass -File .\SysmonUser\build.ps1 -Configuration Debug -Platform x64
powershell -ExecutionPolicy Bypass -File .\SysmonUser\build.ps1 -Configuration Release -Platform x64
```

默认输出位置：

- `SysmonUser\x64\Debug\Sysmon.exe`
- `SysmonUser\x64\Release\Sysmon.exe`，当显式指定 `-Configuration Release` 时生成

### 编译 `SysmonDrv`

`SysmonDrv/build.ps1` 当前直接调用本机 `CL.exe` 和 `link.exe`，逐个编译 `SysmonDrv/src/*.c`，最终链接出内核驱动。

常用命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Rebuild
```

辅助命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Clean
powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Configuration Release -Rebuild
powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Release -Rebuild
```

默认输出位置：

- `SysmonDrv\x64\Debug\SysmonDrv.sys`
- `SysmonDrv\x64\Release\SysmonDrv.sys`，当显式指定 Release 时生成

驱动 Debug 构建会定义 `DBG=1`，FileCreate / FileBlock 的 minifilter 调试计数器可被 `Probe-SysmonStats.ps1` 观察；Release 构建定义 `NDEBUG`，这些热路径调试计数器不累加，查询时对应字段为 0。

## 驱动签名与证书

项目里同时保留了手工签名脚本和自动部署时的内联签名逻辑。

相关脚本包括：

- `create_cert.ps1`
- `sign_driver.ps1`
- `setup_cert.ps1`

当前 `deploy.ps1` 的行为是：

- 将 `SysmonDrv.sys` 拷贝到目标机 `C:\Windows\System32\drivers\SysmonDrv.sys`
- 在目标机上查找或创建 `CN=SysmonTest` 代码签名证书
- 将证书补入 `LocalMachine\Root` 和 `LocalMachine\TrustedPublisher`
- 使用 `Set-AuthenticodeSignature` 对驱动重新签名

如果远程部署失败，优先检查：

- 证书是否成功创建
- 目标机是否允许测试签名环境
- 驱动文件是否被占用

## 安装、升级与卸载

### 命令行入口

用户态程序的核心安装命令与原版 Sysmon 保持同类入口：

- `Sysmon.exe -i [config.xml]`
  安装服务与驱动，并可选加载配置。
- `Sysmon.exe -c <config.xml>`
  重新编译并热更新配置。
- `Sysmon.exe -u [force]`
  卸载服务与驱动。
- `Sysmon.exe -m`
  安装事件描述资源和 manifest。
- `Sysmon.exe -s`
  输出 schema / 帮助相关信息。

### `deploy.ps1` 的推荐用途

根目录 `deploy.ps1` 是当前最完整的自动化部署入口。它默认使用 `DriverConfiguration=Release` 和 `UserConfiguration=Release`，也就是读取：

- `SysmonDrv\x64\Release\SysmonDrv.sys`
- `SysmonUser\x64\Release\Sysmon.exe`

默认流程为：

1. 本地重建 `SysmonDrv`。
2. 本地重建 `SysmonUser`。
3. 将 `SysmonDrv.sys`、`Sysmon.exe`、配置文件拷贝到远程暂存目录；未指定 `-RemoteRoot` 时该目录是目标机桌面下的 `sysmon`，示例命令中显式指定为 `C:\ProgramData\OpenSysmon`。
4. 停止目标机上的 `Sysmon` / `SysmonDrv` 服务。
5. 将二进制复制到 `C:\Windows\System32` 与 `C:\Windows\System32\drivers`。
6. 签名驱动。
7. 创建或更新 `SysmonDrv` 服务。
8. 首次安装时执行 `Sysmon.exe -i <config>`，已安装时执行 `Sysmon.exe -c <config>`。
9. 启动 `SysmonDrv` 与 `Sysmon`，并等待状态变为 `Running`。

常用命令：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon
```

可选参数：

- `-SkipBuild`
  使用现有产物直接部署。
- `-ConfigPath <path>`
  指定要下发的配置文件。
- `-RemoteRoot <path>`
  指定远程暂存目录。
- `-Target <user@host>`
  指定 SSH 目标。
- `-DriverConfiguration Debug|Release`
  指定驱动构建和部署配置，默认 `Release`。
- `-UserConfiguration Debug|Release`
  指定用户态构建和部署配置，默认 `Release`。

### `full_install.ps1`

`full_install.ps1` 适合在目标机本地手工执行，必须显式传入本机已有的驱动、用户态程序和可选配置路径：

- 从指定源路径复制 `SysmonDrv.sys` 与 `Sysmon.exe`
- 使用已有 `SysmonTest` 证书对驱动签名
- 注册 minifilter 实例
- 创建并启动 `SysmonDrv` 服务
- 执行 `C:\Windows\System32\Sysmon.exe -i`

这个脚本适合确认“远程下发无问题，但本机安装步骤是否仍有异常”。

示例：

```powershell
powershell -ExecutionPolicy Bypass -File .\full_install.ps1 `
  -DriverSourcePath .\SysmonDrv\x64\Release\SysmonDrv.sys `
  -SysmonSourcePath .\SysmonUser\x64\Release\Sysmon.exe `
  -ConfigPath .\sysmon_config.xml
```

## 事件描述资源安装

如果事件查看器提示“无法找到来自源 Microsoft-Windows-Sysmon 的事件 ID 描述”，通常不是事件没发出来，而是 Provider manifest 或消息资源没有正确安装。

推荐执行：

```powershell
Sysmon.exe -m
```

相关资源来自：

- `SysmonUser/resources/sysmon_provider.man`
- `SysmonUser/resources/MSG00001.bin`
- `SysmonUser/resources/sysmon_provider.rc`
- `SysmonUser/resources/sysmon_manifest.rc`

安装完成后，应再次检查：

- 事件查看器中的 `Microsoft-Windows-Sysmon/Operational`
- 事件标题和字段描述是否恢复正常

## 远程部署示例

### 通用部署环境

- 目标机和凭据由调用者提供
- 推荐远程暂存目录（显式传入 `-RemoteRoot`）：`C:\ProgramData\OpenSysmon`
- 事件测试默认目录：`C:\ProgramData\OpenSysmon\tests`
- 未指定 `-RemoteRoot` 时，`deploy.ps1` 使用目标机桌面下的 `sysmon` 暂存目录

推荐流程：

1. 在本地仓库执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon
```

2. 使用 SSH 登录目标机，确认以下文件已经落地：

- `C:\ProgramData\OpenSysmon\Sysmon.exe`
- `C:\ProgramData\OpenSysmon\SysmonDrv.sys`
- `C:\ProgramData\OpenSysmon\sysmon_config.xml`

3. 确认系统目录中的文件已更新：

- `C:\Windows\System32\Sysmon.exe`
- `C:\Windows\System32\drivers\SysmonDrv.sys`

4. 在目标机执行：

```powershell
Sysmon.exe -m
```

5. 再执行套件的 Event 22 最小验证：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 22
```

## 构建后回归入口

本地静态守卫用于防止关键对齐点退化，建议在提交前运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1
```

Event 27 / 29 专项回归用于验证 FileBlockExecutable 阻止、归档退化和 detect-only 行为：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-FileBlockExecutableRegression.ps1
```

## 回滚与快照恢复

如果部署后出现蓝屏、自动重启或系统长时间卡死，优先恢复快照，而不是在失稳系统上继续尝试修复。

VMware 快照恢复命令需要根据本机虚拟机路径自行提供；仓库不包含具体主机路径或快照名称。

恢复后建议重新执行：

1. `deploy.ps1`
2. `Sysmon.exe -m`
3. 最小烟雾测试

## 部署后最小检查清单

- `SysmonDrv` 服务是否存在并处于 `Running`
- `Sysmon` 服务是否存在并处于 `Running`
- `C:\Windows\System32\Sysmon.exe` 是否为最新构建
- `C:\Windows\System32\drivers\SysmonDrv.sys` 是否已重新签名
- `Sysmon.exe -c <config>` 是否能成功更新配置
- `Sysmon.exe -m` 后事件描述是否恢复正常
