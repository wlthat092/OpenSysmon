# OpenSysmon 与原版 Sysmon 差异审查

审查日期：2026-08-13；修复实施复核：2026-08-23

> 本文的“现状/修复建议”保留原始审查证据，便于逐项追踪。截至 2026-08-23，所列静态代码问题均已实施修复；仍需按第 7 节在虚拟机完成动态验收。

## 1. 审查范围与结论

本次审查以仓库中的原版 Sysmon 逆向代码 `ida_code/ida_sysmon/` 为行为基线，对当前 `SysmonUser/`、`SysmonDrv/`、事件测试和相关文档进行静态对照。重点检查事件来源、字段语义、进程关联、去重、配置选项、安全边界和事件源生命周期。

总体结论：当前项目已经具备 1-29 号事件的大部分采集和输出框架。原审查确认的 6 组高优先级缺陷及 P2/P3 代码问题已完成实现修复；本轮 VM 复测也关闭了驱动停止卡死和 DNS ETW 外部停止恢复两项动态缺陷，但仍不能在没有原版并行差分的情况下宣称行为完全等价。

本结论属于静态源码与逆向代码对照。它不等同于 29 类事件已经通过原版/当前版并行动态差分测试。

## 2. 事件层级基线纠正

Event 3、22、24 没有在当前驱动内核侧实现，**本身不是缺陷**。逆向代码表明原版也主要在 `Sysmon.exe` 用户态完成这三类事件：

- Event 3：用户态消费 Microsoft-Windows-Kernel-Network ETW，再关联进程、去重和富化。
- Event 22：用户态创建并消费 `SysmonDnsEtwSession`。
- Event 24：用户态剪贴板窗口、跨会话 helper 和本地 RPC 配合完成。
- Event 19/20/21：原版用户态连接 `ROOT\\Subscription` 并执行 WQL 订阅。

因此，真正需要修复的是当前用户态实现与原版在事件语义、安全校验和生命周期管理上的差异，而不是把这几类事件迁移到内核。

## 3. P1：应优先修复的问题

### 3.1 Event 24 丢失剪贴板所有者 PID（已修复）

**现状**

helper 已通过 `GetClipboardOwner` 和 `GetWindowThreadProcessId` 取得所有者 PID，并尝试收集进程元数据：

- `SysmonUser/src/clipboard_monitor.cpp:1113-1137`

但 `SysmonClipboardHelperSend` 将 `OwnerProcessId` 和 `Metadata` 标记为未使用，RPC 实际只发送 `SessionId` 和文本：

- `SysmonUser/src/clipboard_monitor.cpp:955-975`
- `SysmonUser/SysmonClipboard.idl:12-16`

服务端随后固定用 PID 0 构造事件：

- `SysmonUser/src/clipboard_monitor.cpp:1314-1325`

**原版证据**

- `ida_code/ida_sysmon/sub_1400A5490_1400a5490.c:31-40` 获取剪贴板所有者 PID。
- `ida_code/ida_sysmon/sub_1400A51F0_1400a51f0.c:107-117` 将 PID 写入待发送数据。
- `ida_code/ida_sysmon/sub_1400A5080_1400a5080.c:39-40` 通过 RPC 发送该 PID。

**影响**

跨会话 helper 产生的 Event 24 会把 `ProcessId` 写为 0，`ProcessGuid`、`Image` 和 `User` 只能退化为占位值或会话级推断，无法准确标识修改剪贴板的进程。

**修复建议**

扩展 IDL，将 owner PID 作为 RPC 参数传输；服务端只信任 RPC 安全回调已鉴权 helper 提交的 PID，并在事件时间附近重新解析进程元数据。不要传输并直接信任 helper 构造的路径、用户和 GUID。

**验收标准**

在两个交互会话中分别由唯一命名进程写入剪贴板，Event 24 的 `ProcessId`、`ProcessGuid`、`Image`、`Session` 和 `User` 均与实际所有者一致，且伪造 RPC 调用仍被拒绝。

### 3.2 Event 24 归档目录缺少原版安全校验（已修复）

**现状**

`SysmonArchiveClipboardText` 仅调用 `CreateDirectoryW`，随后按路径调用 `CreateFileW`：

- `SysmonUser/src/clipboard_monitor.cpp:511-580`

该路径没有拒绝 reparse point，也没有验证目录 owner、DACL 和完整性标签。

**原版证据**

`ida_code/ida_sysmon/sub_1400A4810_1400a4810.c:22-77` 会拒绝 reparse point，并要求归档目录满足 SYSTEM owner、仅 SYSTEM 的 DACL、System 完整性标签。当前驱动文件归档已经实现相近的安全语义，可参考：

- `SysmonDrv/src/minifilter.c:1102-1475`

**影响**

当仅启用 ClipboardChange，或归档目录被低权限用户预先创建、替换或重定向时，剪贴板内容可能被读取、篡改，或写入攻击者控制的位置。

**修复建议**

以句柄为中心创建和打开目录，创建时应用 SYSTEM-only 安全描述符；打开后验证 reparse 属性、owner、DACL 和 SACL，再以目录句柄为根创建归档文件。验证失败时不得继续归档，并记录可诊断错误。

**验收标准**

普通用户预建目录、弱 DACL 目录、junction/symlink 和非 System 完整性目录均被拒绝；合法目录生成的剪贴板归档仅 SYSTEM 可访问。

### 3.3 Event 3 缺少原版连接去重（已修复）

**现状**

当前代码对 Kernel Network ETW 的 ID 12/15/28/31/42/43/58/59 逐条解析并直接发布 Event 3：

- `SysmonUser/src/network_trace.cpp:253-354`
- `SysmonUser/src/network_trace.cpp:485-495`

代码中没有按连接键维护去重缓存。

**原版证据**

`ida_code/ida_sysmon/sub_14008F2A0_14008f2a0.c:21-112` 按 PID、源/目的地址和端口维护连接记录；相同连接约 900 秒内去重，缓存上限约 1100 条。

**影响**

同一连接对应的多条内核记录可能生成重复 Event 3，增加日志量，并破坏基于事件计数的检测逻辑。

**修复建议**

在用户态 Network source 增加有界、可过期的连接键缓存。键至少包含 PID、协议、方向、源/目的地址和端口；应明确与原版一致的过期窗口、容量和逐出策略。

**验收标准**

同一连接触发多条底层记录时只输出一条 Event 3；不同 PID、端口、协议或方向的连接不能被错误合并；高连接量下缓存保持有界。

### 3.4 Event 3 未按事件时间关联进程（已修复）

**现状**

Network source 使用当前时刻查询进程元数据：

- `SysmonUser/src/network_trace.cpp:415-418`

相比之下，DNS source 已调用 `SysmonCollectProcessMetadataAtTime`：

- `SysmonUser/src/dns_trace.cpp:299-304`

**原版证据**

`ida_code/ida_sysmon/sub_14008F550_14008f550.c` 保留网络事件时间并与进程生命周期缓存关联，而不是仅按当前 PID 查询。

**影响**

短命进程在 ETW 消费前退出，或 PID 已被重用时，Event 3 可能关联到错误进程，或退化为 `ProcessGuid/Image/User` 占位值。

**修复建议**

将 ETW 时间戳传给 `SysmonCollectProcessMetadataAtTime`，复用 DNS 的时间关联路径；必要时短暂等待尚未进入 process store 的进程创建事件，但等待队列必须有界。

**验收标准**

高速创建、联网并退出的短命进程，以及刻意制造 PID 重用的压力场景中，Event 3 始终关联到事件发生时的进程生命周期。

### 3.5 Network/DNS 的 `ProcessTrace` 异常退出后不会恢复（已修复）

**现状**

历史版本的两个消费线程在 `ProcessTrace` 返回后只记录 warning 并退出：

- `SysmonUser/src/network_trace.cpp:498-520`
- `SysmonUser/src/dns_trace.cpp:365-388`

`ServiceContext->NetworkTrace` / `DnsTrace` 仍保持非空；`SysmonApplyOptionalSourceMask` 只在指针为空时启动 source：

- `SysmonUser/src/service.cpp:115-165`

**原版证据**

`ida_code/ida_sysmon/sub_140090520_140090520.c` 包含按配置重新建立 Network/DNS source 的控制路径。

**影响**

修复前，ETW session 被外部停止、provider 失效或消费线程异常返回后，服务仍显示运行，但 Event 3/22 会永久停止，直到配置切换或服务重启。

**修复建议**

当前实现已增加 source fault 标志、服务线程健康刷新、资源回收和带退避的重启；消费线程只要服务未主动停止，无论 `ProcessTrace` 返回成功还是错误都会标记 source 失效。

**验收标准**

VM 复测中外部停止 DNS ETW session 后 10 秒内自动重建并重新捕获 Event 22；仍需在 Network session、连续失败和高负载条件下补充压力验证。

### 3.6 WMI 同时存在用户态正确生产者和驱动占位生产者（已修复）

**现状**

用户态已按原版方式连接 `ROOT\\Subscription`，订阅 `__EventConsumer`、`__EventFilter` 和 `__FilterToConsumerBinding`：

- `SysmonUser/src/wmi_trace.cpp:16-19`
- `SysmonUser/src/wmi_trace.cpp:578-726`

驱动仍根据注册表路径猜测并发布 Event 19/20/21：

- `SysmonDrv/src/registry.c:875-885`
- `SysmonDrv/src/wmi.c:222-365`

驱动注释已承认无法获得完整 WMI 对象字段，却仍用空值构造事件。WMI 规则还会同时启用驱动 registry producer 和用户态 source：

- `SysmonDrv/src/registry_data.c:726-732`
- `SysmonUser/src/service.cpp:67-104`

**原版证据**

`ida_code/ida_sysmon/sub_140098FC0_140098fc0.c:38-80` 显示原版由用户态连接 `ROOT\\Subscription` 并执行相同类型的 WQL 订阅。

**影响**

同一组 Event ID 存在两个语义不同的生产者，可能产生空 `Query`、`Destination`、`Consumer`、`Filter` 的伪事件，也可能造成重复或规则行为不一致。

**修复建议**

删除或彻底禁用驱动 WMI event producer，从 `g_RegistryNotifyEvents` 中移除 19/20/21，仅保留用户态 WMI source。若保留 `wmi.c` 作为 schema 参考，必须确保没有运行时调用路径。

**验收标准**

创建、修改、删除永久 WMI filter/consumer/binding 时，每次只出现来源一致的事件；关键字段与 WMI 对象值一致，不出现由普通 WMI 控制注册表操作触发的占位事件。

## 4. P2：兼容性与可靠性问题

### 4.1 Event 3 的 `DnsLookup` 和端口服务名富化（已修复）

`SysmonUser/src/network_trace.cpp:419-461` 只设置本机 hostname，远端 hostname 和 `SourcePortName` / `DestinationPortName` 基本固定为 `-`，也没有读取当前配置的 `DnsLookup`。原版在 `ida_code/ida_sysmon/sub_14008F910_14008f910.c` 中根据该选项进行地址和服务名富化。

建议实现带缓存、超时和负缓存的异步解析，禁止在 `ProcessTrace` 回调热路径同步阻塞。关闭 `DnsLookup` 时保持 `-`，开启时与原版字段语义对齐。

### 4.2 ETW session 所有权（已修复）

Network 和 DNS 在 `StartTraceW` 返回 `ERROR_ALREADY_EXISTS` 后都会调用 `ControlTraceW(...STOP)` 再重建：

- `SysmonUser/src/network_trace.cpp:567-577`
- `SysmonUser/src/dns_trace.cpp:423-437`

这可能打断另一个 OpenSysmon 实例、官方 Sysmon 或诊断工具拥有的同名 session。原版 Network 启动路径 `ida_code/ida_sysmon/sub_140090720_140090720.c` 接受错误 183，而不是无条件停止已有 session。

建议明确 session 所有权：可附加时只作为 consumer 附加；不能安全附加时启动失败并报告冲突；只有能够证明 session 由本服务创建时才允许停止。DNS 是否允许附加应单独验证，但同样不应抢占未知 owner。

### 4.3 Network ETW payload 版本兼容性（已修复）

`SysmonUser/src/network_trace.cpp:59-123` 使用 `pack(1)` 固定结构解析 Kernel Network payload。现有长度检查可以发现部分布局变化，但对长度相同、字段偏移或语义变化的情况无能为力。原版存在基于 ETW 元数据的解析路径，例如 `ida_code/ida_sysmon/sub_140001FE0_140001fe0.c`。

建议优先使用 TDH/MOF 元数据按属性名解析；若为性能保留快速路径，至少按 provider、event ID、version 和操作系统 build 建立白名单，并在未知组合上拒绝生成事件而不是猜测。

### 4.4 DNS 长字段和追加错误（已修复）

DNS 使用固定 `QueryResults[1024]` 和 4096 字节事件缓冲：

- `SysmonUser/src/dns_trace.cpp:24-25`
- `SysmonUser/src/dns_trace.cpp:223-237`

构造事件时连续调用 `SysmonAddStringField`，但没有检查任何返回值：

- `SysmonUser/src/dns_trace.cpp:323-330`

`SysmonAddStringField` 在空间不足时会返回 `ERROR_BUFFER_OVERFLOW`（`SysmonUser/src/event.cpp:425-470`）。原版 DNS 元数据读取会在 `ERROR_INSUFFICIENT_BUFFER` 时动态扩容（`ida_code/ida_sysmon/sub_140073D30_140073d30.c`）。

建议两阶段计算所需大小并动态分配事件缓冲；所有字段追加都必须检查结果。若配置要求裁剪，应显式按 `FieldSizes` 裁剪并保留有效终止符，不能静默丢失后续字段。

### 4.5 `FieldSizes` 输出裁剪（已修复）

当前 `FieldSizes` 只出现在配置结构、XML 解析、注册表持久化和 CLI 展示中：

- `SysmonUser/src/xml_config.cpp:2157-2160`
- `SysmonUser/src/config.cpp:565,860-861`
- `SysmonUser/src/installer.cpp:1308,1685-1686`

事件构造和输出路径没有读取该配置。原版 `ida_code/ida_sysmon/sub_140084B00_140084b00.c` 会校验字段名和长度，并保存每事件字段限制；`sub_140086F80_140086f80.c` 会读取持久化配置。

建议在加载配置时将字符串编译为按 Event ID/field index 索引的只读表，并在最终渲染前统一裁剪。未知字段、非正数和溢出值应拒绝配置更新，而不是接受后无效。

## 5. P3：测试和文档缺口

### 5.1 事件测试断言不足（已修复）

`tests/sysmon-events/shared/Invoke-EventTest.ps1:36-44` 只检查事件是否存在和 required field 名称是否出现，不验证字段值、占位值、进程归属、唯一触发标记、布尔语义或重复数量。

这会使 Event 24 PID=0、Event 3 重复、错误进程关联和 DNS 字段截断仍然通过测试。建议扩展测试描述，至少支持：

- `ExpectedFields`：精确值或正则匹配。
- `NotPlaceholderFields`：拒绝空字符串、`-`、零 GUID 和 PID 0。
- `CorrelationToken`：只选择本次触发产生的事件。
- `ExpectedCount`：验证去重和无重复事件。
- 原版 Sysmon 与当前版本的同配置、同触发器差分采集。

### 5.2 事件生产者和架构文档（已修复）

`docs/events.md` 现在将 Event 3/22/24 分别指向用户态 Kernel-Network ETW、DNS Client ETW 和 Clipboard RPC；Event 19/20/21 指向用户态 `ROOT\\Subscription` WMI watcher。`docs/architecture.md` 同步说明驱动只保留 Network/DNS/WMI/Clipboard 的兼容/schema 框架，运行时生产者位于用户态。

### 5.3 驱动占位模块说明（已修复）

驱动的 `network.c`、`dns.c`、`clipboard.c` 和 `wmi.c` 文件头已标明其兼容/schema 角色，初始化路径对未实现的内核 producer 明确记录并跳过；DNS 注释也已改为“服务消费 DNS Client ETW provider”，不再描述为拦截 DLL 调用。

## 6. 已确认修复的旧问题

以下历史问题在当前代码中已有明确修复，不应继续作为未解决缺陷重复报告：

- 签名富化 pending event 和 work item 均受 `SigningQueueSize` 限制。
- 私有事件归档扩展名已从容易混淆的 `.evtx` 改为 `.bin`。
- Clipboard RPC 已通过 `RPC_QUERY_CLIENT_PID` 只允许服务创建的 helper 调用。
- ProcessGuid 生成失败会降级为零 GUID，不再丢弃整条事件。
- 长规则 token 已改为动态分配，不再因固定栈缓冲改变规则语义。
- 仓库已有 `.github/workflows/build.yml`，不能再描述为“没有 CI”。

## 7. 仍需动态验证的风险

### 7.1 驱动停止和卸载生命周期

`docs/superpowers/specs/2026-08-04-project-quality-review.md:325-334` 记录过 VM 中 `SysmonDrv` 长时间停留在 `STOP_PENDING` 的现象。当前版本增加了 image worker 停止期间的待处理项清理，并在目标 VM 完成了重复重载复测。

2026-08-23 使用 Release 驱动连续重载 3 次，每次均在约 2-3 秒内进入 `STOPPED` 并重新 `Running`，未复现原先的 `STOP_PENDING`/错误 1056。仍需在并发事件负载、服务强制终止、休眠恢复和 Driver Verifier 条件下继续验证。

### 7.2 尚未完成全事件原版差分

现有测试资产覆盖 23 个模拟器支持的事件，但“能产生事件并包含字段名”不能证明行为等价。剩余事件及关键边界仍需要以相同 XML、相同触发器分别运行原版和当前版，比较：

- 事件数量与去重行为。
- 字段值、占位策略和时间语义。
- include/exclude 规则结果。
- 配置热更新和 source 启停。
- 高负载、短命进程、PID 重用和失败恢复。

## 8. 历史修复顺序

1. 修复 Event 24 owner PID RPC 链路和归档目录安全校验。
2. 为 Event 3 增加连接去重、按事件时间关联进程，并补对应差分测试。
3. 建立 Network/DNS source 状态机和异常退出自动恢复。
4. 删除驱动 WMI 占位生产者，只保留用户态 `ROOT\\Subscription` 链路。
5. 实现 `DnsLookup`/端口名富化、`FieldSizes` 和 DNS 动态缓冲。
6. 明确 ETW session 所有权并改进 Network payload 版本解析。
7. 强化事件测试断言，完成 1-29 号事件的原版并行差分矩阵。
8. 修正文档中的事件生产者和架构描述，删除或重命名误导性占位模块。

## 9. 本次静态验证

本次审查复核了当前源码、逆向函数、测试脚本和相关文档。此前针对当前工作树执行的以下检查均通过：

- `scripts/Test-StaticRegressionGuards.ps1`
- `tests/sysmon-events/Test-EventTestAssets.ps1`：23 个事件用例资产有效。
- `tests/sysmon-events/tests` Pester：15 passed，0 failed。

2026-08-23 已完成 VM 部署、远程事件套件、驱动重复重载和 DNS ETW 外部停止恢复测试，但尚未运行原版/当前版并行事件差分，详见下方补充。

### 9.1 2026-08-23 VM 动态验证补充

- `deploy.ps1 -SkipBuild` 成功，主配置最终恢复；重启后 `Sysmon` 与 `SysmonDrv` 均为 `Running`。
- 事件测试 helper 已将配置重载后的时间窗口作为触发起点，默认断言改为至少 1 条；仅 manifest 显式设置 `ExpectedCount` 时才要求精确数量。最新完整 23 用例中 13 个通过（1、5、8、9、10、11、12、13、15、17、22、25、26），10 个失败。
- 剩余失败来自有效触发不足或测试前置条件：Event 2/3/6/7/14/19/20/21/24 未捕获事件；Event 18 在该次远程自动化调用中返回退出码 `-1073740940`。随后在目标机交互式命令行直接执行 `SysmonSimulator.exe -eid 18` 已成功创建 `\\.\pipe\sysmontestconnectpipe` 的连接事件（2026-08-24 23:18:28），因此当前证据只支持“自动化执行上下文待复现”，不能判定模拟器或 Event 18 产品链路故障。这些结果仍不能替代 Event 3/24/WMI 的交互桌面和原版差分测试。
- 外部停止 `SysmonDnsEtwSession` 后 10 秒内自动重建，随后 Event 22 再次捕获成功。
- `Probe-SysmonStats.ps1` 返回 616 bytes；`ProcessCreateFailureCount`、`EventQueueDropCount`、`QueryQueueDropCount` 和 `ObRegisterLastStatus` 均为 0。

2026-08-24 在隔离测试目标上复测后，独立 Kernel-Network ETW 已捕获模拟器 Event 12（测试目标端口为 `31337`）。Event 3 套件最初未捕获的原因是测试 XML 使用空 `NetworkConnect onmatch="include"`，当前规则运行时会将其解释为禁用 Network source；改为匹配端口 `31337` 的非空 include 后，`Deploy-EventTests.ps1 -EventIds 3` 已通过。该结果说明 Event 3 失败与外网访问能力无关，连接尝试本身即可产生内核 ETW 记录。

2026-08-25 复测 Event 18：连续复现发现模拟器在 Event 18 配置加载后以隐藏窗口启动时可能返回 `0xC0000374`，而交互式命令行可成功创建 `\\.\pipe\sysmontestconnectpipe`。事件测试入口已改为普通窗口启动，并对该已知模拟器瞬时退出码最多重试 3 次；`Deploy-EventTests.ps1 -EventIds 18` 已通过，捕获 `ConnectPipe`、`PipeName`、`ProcessId`、`Image` 和 `User` 字段。该问题归类为测试模拟器启动稳定性，不是 OpenSysmon Event 18 采集链路缺陷。

## 10. 修复实施状态（2026-08-23）

- Event 24：RPC 已传递 owner PID；服务端按事件时间重新收集元数据；归档目录和归档文件已增加 SYSTEM owner/DACL/SACL、完整性级别及 reparse point 校验。
- Event 3：已增加 1100 条有界、900 秒过期去重缓存；按 ETW 事件时间关联进程；`DnsLookup` 解析改为有界后台工作项和正/负缓存；未知 owner 的同名 Network/DNS ETW session 不再被强制停止；Network payload 现在要求 provider、version 和精确长度匹配，未知布局直接丢弃并记录诊断。
- Network/DNS：消费线程现在无论 `ProcessTrace` 返回成功还是错误，只要服务未主动停止就标记 fault；VM 外部停止 DNS session 后 10 秒内自动重建并重新捕获 Event 22。
- WMI：驱动注册表回调不再产生 19/20/21 占位事件，运行时仅保留用户态 `ROOT\\Subscription` 生产者。
- DNS/FieldSizes：DNS 属性按 TDH 返回长度分配，事件缓冲按实际字段大小动态计算并检查字段追加结果；`FieldSizes` 在 XML 和注册表加载时均校验字段名、格式、范围，并应用于输出渲染。
- 注册与哈希一致性：镜像通知注册现在返回并聚合 `NTSTATUS`；驱动和用户态都将 `HashingAlgorithm=0` 解释为“不哈希”。
- 测试/文档：事件测试支持非占位字段、触发后时间窗口和可选精确数量断言；部署脚本规范化带尾随空格的 Desktop 路径，事件生产者文档已更新。

以上静态修复已通过用户态和驱动 Debug/Release 构建；VM 动态复测已关闭驱动停止和 DNS ETW 恢复缺陷，剪贴板安全目录攻击场景及原版并行差分仍需执行。

## 11. 最终结论

截至 2026-08-23，本审查文档中可由源码直接验证的缺陷均已关闭：

| 范围 | 状态 | 关键修复 |
|---|---|---|
| Event 24 owner PID、RPC 注入和归档目录安全 | 已修复 | RPC 传递 owner PID；接口回调仅允许服务创建的 helper；目录/文件执行 SYSTEM owner、DACL、SACL、完整性和 reparse 校验，并启用 `SeSecurityPrivilege` 读取 SACL |
| Event 3 去重、进程时间关联和富化 | 已修复 | 有界去重缓存；`SysmonCollectProcessMetadataAtTime`；后台主机名/端口服务名解析及正/负缓存 |
| Network/DNS ETW session 抢占和异常恢复 | 已修复，仍需压力验证 | 未抢占未知 owner；外部停止 DNS session 后可自动重建，连续失败有退避 |
| Network ETW 兼容性 | 已修复 | provider、version、event ID 和精确 payload 长度白名单；未知布局拒绝解析 |
| DNS 长字段、FieldSizes | 已修复 | TDH 实际长度分配、动态事件缓冲、追加错误检查；XML/注册表双路径校验并在渲染时裁剪 |
| WMI 双生产者 | 已修复 | 驱动注册表回调不再发布 Event 19/20/21，仅保留用户态 `ROOT\\Subscription` producer |
| 队列、GUID、哈希和进程富化历史问题 | 已修复 | pending event 有界、GUID 失败降级零 GUID、HashingAlgorithm=0 统一为不哈希、PID 负缓存 |
| 镜像通知注册失败可观测性 | 已修复 | `SysmonRegisterImageNotify` 返回 `NTSTATUS`，初始化和热同步路径记录并聚合失败 |
| 动态验收 | 部分完成，仍有环境缺口 | 部署、重复驱动重载和 ETW 外部停止恢复已通过；事件 3/24/WMI 交互触发、剪贴板攻击场景和原版并行差分尚未完成 |

本地验证结果：Pester 15/15 通过，23 个事件资产通过，静态回归护栏通过，SysmonUser/SysmonDrv Debug 和 Release 构建通过。VM 动态验收已通过驱动生命周期和 DNS ETW 恢复，但当前仍不能宣称所有事件与原版完全等价。
