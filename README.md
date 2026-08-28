# OpenSysmon

语言：中文 | [English](README.en.md)

本项目采用 [MIT License](LICENSE) 发布。`third_party/` 下的第三方依赖仍受其各自许可证约束，请同时遵守对应的版权和 NOTICE 要求。

OpenSysmon 基于原版 `Sysmon64.exe` 和 `SysmonDrv.sys` 的逆向结果实现，包含用户态服务/CLI、内核驱动、配置兼容层、部署脚本、事件测试脚本，以及原版对照验证资产。项目实现借助 AI 辅助逆向分析、代码生成、测试编排和文档整理完成，不代表 Microsoft 官方实现或产品。

## 当前状态

- 目标是尽量对齐原版 Sysmon 的配置语法、过滤语义、驱动侧事件结构、注册表持久化和命令行行为。
- 仓库已经同时包含实现代码、标准事件 XML、远程部署脚本、原版/OpenSysmon 对照测试脚本。
- 根目录 `deploy.ps1` 默认构建并部署 Release 产物；单独运行 `SysmonUser/build.ps1` 或 `SysmonDrv/build.ps1` 时默认仍是 Debug。
- 正式文档采用 `README + docs/*` 分层结构，过程性设计稿和计划稿不再作为正式文档入口。
- 本项目仅供学习、研究和测试使用；当前动态验证仅在 Windows 10 2021 LTSC 环境完成，不代表对其他 Windows 版本的兼容性承诺。

## 快速开始

克隆仓库时请使用 `git clone --recurse-submodules <repository-url>`；如果已经完成普通克隆，请先运行 `git submodule update --init --recursive`。

1. 运行静态回归守卫：
   `powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1`
2. 编译用户态 Release：
   `powershell -ExecutionPolicy Bypass -File .\SysmonUser\build.ps1 -Configuration Release`
3. 编译驱动态 Release：
   `powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Configuration Release -Rebuild`
4. 部署当前构建产物到目标机：
   `powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon`
5. 在目标机安装并加载配置：
   `Sysmon.exe -i <config.xml>`
6. 运行最小模拟器事件验证：
   `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 22`

## 下载 Release 包并本机安装

GitHub Release 包是可直接部署的 Windows x64 ZIP，仅包含 `Sysmon.exe`、`SysmonDrv.sys`、`sysmon_config.xml`、`install.ps1` 和 `uninstall.ps1`。解压后，以管理员身份打开 PowerShell，在包目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

安装脚本会将文件复制到系统目录和 `C:\ProgramData\OpenSysmon`，创建或更新服务并加载包内配置。卸载时执行 `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1`。驱动使用本机测试证书签名；请在允许测试签名的隔离测试机上运行，Release 包不适合生产部署。

维护者可在 GitHub Actions 手动运行 `build` 工作流；填写 `release_tag`（例如 `v0.1.0`）会自动创建对应 GitHub Release 并上传 ZIP。不填写时仅生成可下载的 Actions 工件。

## 依赖与许可证

### 构建依赖

- Windows 10/11 x64。
- Visual Studio 2022 或 Build Tools，包含 MSVC、MSBuild 和 C++ 工具集。
- Windows 10 SDK / WDK（驱动脚本默认使用 `10.0.26100.0` 头文件和库），其中需要 `mc.exe` 和 `midl.exe`。
- CMake 和 Git；`third_party/SymCrypt` 作为源码依赖参与静态库构建。
- PowerShell 5.1 或更高版本；运行 Pester 测试需要 Pester 5。

### 运行与远程测试依赖

- 目标 Windows x64 机器需要管理员权限，并已安装、运行 `Sysmon` 和 `SysmonDrv`。
- 远程部署需要本机 OpenSSH Client（`ssh`、`scp`）以及目标机可用的 SSH 服务。
- 事件测试需要外部提供 [`SysmonSimulator.exe`](https://github.com/ScarredMonk/SysmonSimulator)。该文件不包含在仓库中，请从其上游项目获取并放置到 `tests/sysmon-events/tools/SysmonSimulator.exe`，部署脚本会随测试目录上传。

### 许可证

- 本项目原创代码和文档采用 [MIT License](LICENSE)。
- `third_party/SymCrypt` 遵循其自身的 [LICENSE](third_party/SymCrypt/LICENSE.txt) 和 [NOTICE](third_party/SymCrypt/NOTICE.txt)，分发时必须保留对应声明。
- Visual Studio、Windows SDK/WDK、PowerShell、OpenSSH 和来自 [ScarredMonk/SysmonSimulator](https://github.com/ScarredMonk/SysmonSimulator) 的 `SysmonSimulator.exe` 等外部工具不由本项目分发，分别遵循其供应方或原作者的许可证。

### 参考配置来源

根目录 `sysmon_config.xml` 是默认主配置，参考了 [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) 的规则组织和配置内容。相关配置的版权、许可证和上游声明以该项目为准；本项目不声称拥有其原始规则内容的独立版权。

## 安全警告

- **本项目不适合生产环境。** 当前实现仍在持续对齐和验证中，不应直接作为生产监控、阻断或安全防护组件部署。
- **仅供学习和测试使用。** 目前仅在 Windows 10 2021 LTSC 环境完成过动态测试，其他系统版本和硬件组合需要使用者自行验证。
- 本项目包含内核驱动和系统服务，安装、升级、卸载及配置变更需要管理员权限；驱动或规则错误可能导致系统不稳定、事件丢失或性能下降。
- 首次运行前请使用隔离的测试虚拟机并创建快照，不要直接在生产主机或承载重要数据的设备上安装、加载驱动或运行回归脚本。
- `SysmonSimulator.exe` 会主动生成进程、文件、网络、注册表、WMI、管道或剪贴板活动。请仅在专用测试环境运行，并先审查要加载的 Sysmon 配置和测试脚本。
- 远程部署脚本会通过 SSH/SCP 上传文件并在目标机执行 PowerShell 命令。请使用专用测试账户和密钥认证，限制目标主机权限，不要把私钥、密码、内部地址或测试日志提交到仓库。
- 发布或部署前应验证二进制来源、代码签名和哈希；项目不提供 Microsoft Sysmon 或第三方模拟器的安全保证，也不保证与原版 Sysmon 完全等价。

## 测试前置条件

运行 `tests/sysmon-events/Deploy-EventTests.ps1` 前，请确认：

- 本机已完成 `SysmonUser` 构建，并存在 `SysmonUser/x64/Release/Sysmon.exe` 或 `SysmonUser/x64/Debug/Sysmon.exe`。
- 本机仓库根目录存在待加载的 `sysmon_config.xml`，并已将 [`SysmonSimulator.exe`](https://github.com/ScarredMonk/SysmonSimulator) 放置到 `tests/sysmon-events/tools/SysmonSimulator.exe`。
- 目标机是 Windows x64，已完成驱动和服务部署，且 `Sysmon`、`SysmonDrv` 服务均处于 `Running` 状态；目标账户具备执行测试和读取 Sysmon 事件日志的权限。
- 本机可使用 `ssh` 和 `scp` 无交互连接目标机，目标机 SSH 服务可用；远程 PowerShell 可执行测试脚本。
- 测试运行在隔离虚拟机或专用测试主机中，已创建可回滚的快照或备份。

只运行本地 Pester 测试时，还需要安装 Pester 5；该测试不需要连接远程目标机。

## 文档导航

- [软件架构](docs/architecture.md)
- [配置过滤](docs/configuration.md)
- [安装部署](docs/deployment.md)
- [测试验证](docs/testing.md)
- [故障排查](docs/troubleshooting.md)
- [事件矩阵](docs/events.md)

## 仓库概览

- `SysmonUser/`
  用户态 `Sysmon.exe`，负责 CLI、服务、配置编译、驱动通信、事件输出和 manifest 相关逻辑。
- `SysmonDrv/`
  内核态 `SysmonDrv.sys`，负责事件采集、驱动侧过滤、事件队列和 IOCTL 通信。
- `events/`
  Event ID 1-29 的标准 XML 事件结构样例，用于字段对齐和事件矩阵核对。
- `scripts/`
  保留的诊断、状态、性能和专项非模拟器回归工具。
- `tests/sysmon-events/`
  固定的基于模拟器的 Sysmon 事件测试套件；使用 `Deploy-EventTests.ps1` 上传并运行选定事件。
- `schema_events.xml`
  当前内置 schema / manifest 对齐使用的事件定义。
- `third_party/`
  外部依赖源码，当前主要用于 SymCrypt 静态库构建。

## 常用命令速查

- 安装：
  `Sysmon.exe -i [config.xml]`
- 卸载：
  `Sysmon.exe -u [force]`
- 更新配置：
  `Sysmon.exe -c <config.xml>`
- 查看当前配置：
  `Sysmon.exe -c`
  或
  `Sysmon.exe -s`
- 打印 schema / 配置帮助：
  `Sysmon.exe -s [-a]`
  或
  `Sysmon.exe -h config`
- 安装事件描述资源：
  `Sysmon.exe -m`
- 运行 OpenSysmon 单边验证：
  `powershell -ExecutionPolicy Bypass -File .\scripts\Remote-ReloadDriver.ps1 -RemoteRoot C:\ProgramData\OpenSysmon`
- 运行单事件验证：
  `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 1`
- 运行完整模拟器事件测试套件：
  `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host`
- 运行静态回归守卫：
  `powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1`
- 运行 FileBlockExecutable / FileExecutableDetected 回归：
  `powershell -ExecutionPolicy Bypass -File .\scripts\Test-FileBlockExecutableRegression.ps1`

## 环境参数

事件测试脚本不包含固定 IP、用户名或桌面目录，只需传入 `-Target` 和可选的 `-EventIds`；其远程默认上传目录为 `C:\ProgramData\OpenSysmon\tests`。根目录 `deploy.ps1` 若未指定 `-RemoteRoot`，会使用目标机桌面下的 `sysmon` 暂存目录；建议显式指定 `-RemoteRoot C:\ProgramData\OpenSysmon`。本机测试套件固定使用 `tests\sysmon-events`，工具放在 `tests\sysmon-events\tools`，构建产物和主配置从仓库固定位置查找并随套件上传。

## 当前限制

- 与原版 Sysmon 的完全对齐工作仍在继续，具体差异按主题记录在 `docs/` 各文档中。
- 部分说明会同时给出通用步骤和当前项目环境示例，避免文档被单一实验环境绑死。
- 历史过程文档不再作为正式说明入口；如需追溯设计与执行过程，请直接查看 Git 历史。
