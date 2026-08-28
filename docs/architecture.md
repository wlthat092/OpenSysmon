# 软件架构

## 总体架构

本项目由两个核心二进制组成：

- `Sysmon.exe`
  用户态服务与 CLI，负责命令行入口、服务生命周期、配置编译、注册表持久化、驱动通信、事件消费和事件输出。
- `SysmonDrv.sys`
  内核态驱动，负责进程、文件、注册表、管道、进程访问和篡改检测等事件的采集与驱动侧过滤。Network、DNS、WMI 和 Clipboard 的主生产者位于用户态；驱动对应文件只保留协议/schema 兼容框架和启停状态。

两者通过 `\\.\Sysmon` 设备和 `0x8340xxxx` IOCTL 协议交互，整体目标是尽量贴近原版 Sysmon 的行为模型，而不是仅靠用户态做二次渲染。

## 用户态职责

`SysmonUser/src/` 中的主要职责可以概括为几层：

- 入口与 CLI
  `main.cpp` 和 `cli.cpp` 负责在服务模式、调试模式、剪贴板 helper 模式和安装/配置命令之间分发。
- 安装与资源
  `installer.cpp` 负责服务安装、驱动服务注册、manifest 安装、schema 输出和帮助文本。
- 配置与规则编译
  `xml_config.cpp` 负责解析原版 Sysmon XML，`rules.cpp` 负责规则序列化与反序列化，`config.cpp` 负责注册表持久化和热更新监控。
- 协议与服务循环
  `protocol.cpp` 负责握手、事件拉取、配置通知和重连，`service.cpp` 负责服务主循环、后台线程和按规则启停可选用户态事件源。
- 输出层
  `output.cpp`、`output_enrichment.inc` 和 `event_schema.cpp` 负责控制台渲染、ETW 输出、字段富化、事件描述资源和内部事件发射。
- 用户态事件源
  `clipboard_monitor.cpp` 负责 Event 24 的窗口消息监听、跨会话 helper、RPC 回传、剪贴板哈希和归档。

## 驱动态职责

`SysmonDrv/src/` 侧主要分成四类模块：

- 驱动入口与运行时
  `driver.c` 负责驱动初始化、全局上下文、配置加载、回调注册与卸载。
- 通信与队列
  `communication.c`、`queue.c` 负责 IOCTL、CSQ、事件队列和调试统计。
- 事件采集器
  `process.c`、`thread.c`、`image.c`、`registry.c`、`pipe.c`、`obcallback.c`、`tampering.c`、`minifilter.c` 负责内核事件源；`network.c`、`dns.c`、`wmi.c`、`clipboard.c` 当前仅保留兼容/schema 框架，不是对应用户态事件的运行时生产者。
- 配置与匹配
  `registry_data.c` 和 `rules.c` 负责从注册表读取 `Rules` / `Options` 等配置并构建驱动侧规则运行时。

## 配置生命周期

当前实现中的配置生命周期是：

1. `Sysmon.exe -i` 或 `Sysmon.exe -c` 读取 XML 配置文件。
2. `xml_config.cpp` 将 XML 解析为顶层配置项和规则模型。
3. `rules.cpp` 将规则模型序列化为 `Rules` 二进制 blob。
4. `config.cpp` 将 `ConfigFile`、`ConfigHash`、`Rules`、`Options`、`HashingAlgorithm`、`CheckRevocation`、`DnsLookup`、`ArchiveDirectory`、`CopyOnDelete*`、`SigningQueueSize`、`SigningWorkerCount`、`ProcessAccessNames`、`ProcessAccessMasks` 等值写入注册表。
5. 用户态通过 `IOCTL_SYSMON_CONFIG_NOTIFY` 通知驱动刷新配置。
6. 驱动重新加载规则运行时，并同步内核监控回调的启停状态；用户态服务根据规则运行时独立启停并监督 Network / DNS / WMI / Clipboard 等可选源。

这意味着配置兼容性的关键不只是 XML 能不能解析，还包括持久化格式、驱动热更新和运行时匹配三者的一致性。

## 事件链路

当前主链路可以概括为：

1. 内核回调或过滤器捕获到事件源。
2. 对应采集模块构造标准化事件字段。
3. 驱动侧规则运行时决定事件是否需要保留、是否需要延迟到用户态补充信息。
4. 通过过滤的事件进入驱动队列，或者直接完成挂起 IRP。
5. 用户态通过异步 `DeviceIoControl` 拉取事件。
6. `output.cpp` 按 schema 渲染控制台输出，或写入 ETW / 调试通道。

FileBlockExecutable 是当前最特殊的文件链路：`minifilter.c` 会在写入/关闭路径维护 stream context，清理前重新确认当前文件仍是 PE；命中 Event 27 时尝试按 `<卷根>\<ArchiveDirectory>\<hash>[.<ext>]` 归档，再退化到复制归档或仅删除原文件。只启用 Event 29 时进入 detect-only 路径，原文件保留。

现在的实现重点强调“先在驱动侧决定是否产生日志”，而不是把所有数据都上送后再由用户态补筛。

## 通信协议

当前协议实现围绕 `0x8340xxxx` IOCTL：

- `0x83400000`
  初始化握手
- `0x83400004`
  拉取事件
- `0x83400008`
  配置刷新通知
- `0x8340000c`
  进程缓存查询
- `0x83400010`
  查询应答
- `0x83400014`
  停止通信
- `0x83400018`
  调试统计拉取

用户态和驱动态都依赖这套协议维持运行时同步，因此它既是功能协议，也是排障入口。当前 minifilter 的 FileCreate / FileBlock 调试计数器只在 `DBG` 驱动构建中累加；Release 构建仍保留 ABI 字段，但这些计数字段读出为 0。

## 事件描述资源与 Manifest

事件查看器能否正确显示 “Microsoft-Windows-Sysmon” 的事件描述，依赖用户态资源文件：

- `SysmonUser/resources/sysmon_provider.man`
  Provider、Task、Template 和事件描述字符串的正式定义。
- `SysmonUser/resources/MSG00001.bin`
  事件消息资源。
- `SysmonUser/resources/sysmon_provider.rc`
  Provider 与消息资源打包入口。
- `SysmonUser/resources/sysmon_manifest.rc`
  Manifest 资源打包入口。
- `installer.cpp`
  负责 `-m` 相关安装逻辑和 schema / config help 输出。

如果这些资源没有安装或注册不完整，事件查看器就会出现“无法找到来自源 Microsoft-Windows-Sysmon 的事件 ID 描述”的提示。

## 规则与过滤架构

当前规则系统分成三层：

- XML 解析层
  从原版 Sysmon XML 读取顶层选项、事件节点、`RuleGroup`、字段条件。
- 规则模型层
  统一的规则枚举、关系、表达式和 blob 结构，供用户态与驱动态共享语义。
- 驱动运行时层
  驱动加载规则 blob 后在事件产生点直接做筛选，并在必要时标记“需要用户态补充信息再匹配”。

这套结构的好处是配置兼容、持久化格式和事件筛选不再各写一套逻辑。

## 部署环境约定

- 目标机：由部署命令的 `-Target` 指定
- 推荐部署暂存目录（显式传入 `-RemoteRoot`）：`C:\ProgramData\OpenSysmon`
- 事件测试默认目录：`C:\ProgramData\OpenSysmon\tests`
- `deploy.ps1` 未指定 `-RemoteRoot` 时使用目标机桌面下的 `sysmon` 暂存目录

## 原版行为 / 当前实现 / 当前差距

### 配置编译

- 原版行为
  XML 配置被编译并持久化为注册表配置，再由驱动和服务共同消费。
- 当前实现
  已有 XML 解析、规则序列化、注册表写入和驱动热加载链路。
- 当前差距
  仍需持续核对持久化格式和边界语义与原版是否完全一致。

### 事件输出

- 原版行为
  ETW Provider、事件模板和消息资源配合事件查看器显示完整描述。
- 当前实现
  已经内置 provider manifest 和消息资源，`-m` 路径存在。
- 当前差距
  仍需在真实环境中持续验证 manifest 安装、字段版本和资源注册细节。

### 事件字段对齐

- 原版行为
  事件字段结构以每个 Event ID 的标准 XML 为准。
- 当前实现
  `output.cpp` 已按 schema 渲染大量字段，驱动中也在补齐标准结构。
- 当前差距
  各事件字段是否与 `events/` 样例完全一致，仍需逐项核对，详见 [events.md](events.md)。
