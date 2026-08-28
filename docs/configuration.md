# 配置过滤

## 配置模型

当前项目的目标配置格式是原版 Sysmon XML。当前实现已经能解析并持久化以下几类信息：

- 顶层 `Sysmon` 节点和 `schemaversion`
- 顶层选项，如 `HashAlgorithms`、`CheckRevocation`、`DnsLookup`、`ArchiveDirectory`、`CopyOnDeletePE`、`CopyOnDeleteSIDs`、`CopyOnDeleteExtensions`、`CopyOnDeleteProcesses`、`FieldSizes`
- 数值项，如 `DriverQueueSize`、`SigningQueueSize`、`SigningWorkerCount`
- `EventFiltering`
- `RuleGroup`
- 事件过滤节点
- 字段级条件表达式

文档中的“兼容”指三件事一起成立：

1. XML 能被解析
2. 规则能被编译并写入注册表
3. 驱动运行时能按同样语义使用这些规则

## 顶层配置项

当前代码已经显式处理的顶层配置项包括：

- `HashAlgorithms`
- `CheckRevocation`
- `DnsLookup`
- `ArchiveDirectory`
- `CopyOnDeletePE`
- `CopyOnDeleteSIDs`
- `CopyOnDeleteExtensions`
- `CopyOnDeleteProcesses`
- `FieldSizes`
- `DriverQueueSize`
- `SigningQueueSize`
- `SigningWorkerCount`
- `EventFiltering`

其中：

- `CheckRevocation`、`DnsLookup` 和 `CopyOnDeletePE` 使用布尔值
- `DriverQueueSize`、`SigningQueueSize` 和 `SigningWorkerCount` 使用数值
- `ArchiveDirectory`、`CopyOnDeleteSIDs`、`CopyOnDeleteExtensions`、`CopyOnDeleteProcesses`、`FieldSizes` 使用字符串
- `HashAlgorithms` 支持 `MD5`、`SHA1`、`SHA256`、`IMPHASH` 和 `*`
- `ArchiveDirectory` 必须是单个目录组件，不能包含盘符、反斜杠、斜杠或相对路径段
- `CopyOnDeleteSIDs`、`CopyOnDeleteExtensions`、`CopyOnDeleteProcesses` 是逗号分隔风格字符串，驱动加载时会规范化为小写 `MULTI_SZ`

当前默认值来自代码而不是推断：

- `HashingAlgorithm = 0x00`
- `CheckRevocation = true`
- `DnsLookup = true`
- `CopyOnDeletePE = false`
- `SigningQueueSize = 1000`
- `SigningWorkerCount = 0`，表示由用户态签名 worker 逻辑自动决定

## 事件过滤结构

当前实现支持以下结构组合：

```xml
<Sysmon schemaversion="...">
  <HashAlgorithms>*</HashAlgorithms>
  <CheckRevocation>true</CheckRevocation>
  <DnsLookup>true</DnsLookup>
  <EventFiltering>
    <RuleGroup groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="end with">cmd.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

支持的关键层级是：

- `EventFiltering`
- `RuleGroup`
- 事件节点，例如 `ProcessCreate`、`NetworkConnect`、`RegistryEvent`
- 事件节点下的字段条件
- 事件节点下的嵌套 `Rule`

## 事件节点映射

当前 XML 解析层会把一些通用节点映射到多个 Event ID：

- `RegistryEvent`
  映射到 12 / 13 / 14
- `PipeEvent`
  映射到 17 / 18
- `WmiEvent`
  映射到 19 / 20 / 21

此外也支持单独的：

- `RegistryValueSet`
- `RegistryRename`
- `ProcessCreate`
- `FileCreateTime`
- `NetworkConnect`
- `ProcessTerminate`
- `DriverLoad`
- `ImageLoad`
- `CreateRemoteThread`
- `RawAccessRead`
- `ProcessAccess`
- `FileCreate`
- `FileCreateStreamHash`
- `DnsQuery`
- `FileDelete`
- `ClipboardChange`
- `ProcessTampering`
- `FileDeleteDetected`
- `FileBlockExecutable`
- `FileBlockShredding`
- `FileExecutableDetected`

## `include` / `exclude` 语义

当前实现中：

- `onmatch="include"`
  规则命中时记录，未命中时丢弃
- `onmatch="exclude"`
  规则命中时丢弃，未命中时保留

如果某个事件存在 `exclude` 命中，排除优先级高于 `include`。

驱动运行时会先判断事件是否落在配置中，再决定是否进入队列，因此“没有命中任何事件规则”和“事件产生了但被排除”在调试上是两个不同阶段。

## `groupRelation` 与规则组合

当前实现支持：

- `groupRelation="or"`
- `groupRelation="and"`

组合层级有两层：

- `RuleGroup`
  决定同组中多个事件规则如何组合
- `Rule`
  决定同一条规则内多个表达式如何组合

如果事件节点本身没有显式 `Rule`，字段条件会先被折叠成一条隐式规则，再参与组合判断。

## 条件匹配语义

当前规则解析层支持的主要条件包括：

- `is`
- `is not`
- `contains`
- `contains any`
- `is any`
- `contains all`
- `excludes`
- `excludes any`
- `excludes all`
- `begin with`
- `end with`
- `not begin with`
- `not end with`
- `less than`
- `more than`
- `image`

当前实现的语义特征：

- 文本比较默认不区分大小写
- `contains any` / `contains all` / `is any` 等使用 `;` 分隔值列表
- `image` 语义按镜像路径后缀匹配，而不是必须全路径完全相等
- 一部分路径类字段会在解析时进行路径规范化和分隔符统一

## 注册表持久化

用户态会将配置统一写入：

`HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters`

当前实现显式写入或读取的键值包括：

- `Options`
- `HashingAlgorithm`
- `Rules`
- `FieldSizes`
- `ConfigFile`
- `ConfigHash`
- `ArchiveDirectory`
- `CopyOnDeletePE`
- `CopyOnDeleteSIDs`
- `CopyOnDeleteExtensions`
- `CopyOnDeleteProcesses`
- `CheckRevocation`
- `DnsLookup`
- `DriverQueueSize`
- `SigningQueueSize`
- `SigningWorkerCount`
- `ProcessAccessNames`
- `ProcessAccessMasks`
- `PendingConfigEventConfiguration`
- `PendingConfigEventHash`
- `Stop`

其中：

- `Rules` 是规则 blob
- `ConfigHash` 当前由配置文件内容计算得出
- `PendingConfigEvent*` 用于 Event ID 16 的配置变更事件暂存
- `ProcessAccessNames` 是 `REG_MULTI_SZ`，`ProcessAccessMasks` 是对应的二进制掩码表
- `DriverQueueSize` 只有非 0 时写入；为 0 时用户态会删除该值，让驱动使用默认队列大小

## FileBlock 与 CopyOnDelete

Event 27 `FileBlockExecutable` 和 Event 29 `FileExecutableDetected` 共用文件过滤路径，但行为不同：

- `FileBlockExecutable`
  命中后会在 cleanup 阶段重新确认当前文件仍是 PE，再执行阻止收口。若满足 `CopyOnDeletePE` 或 `CopyOnDeleteSIDs` / `CopyOnDeleteExtensions` / `CopyOnDeleteProcesses` 任一匹配，会优先尝试归档。
- `FileExecutableDetected`
  是 detect-only 路径，只记录可执行文件检测事件，原文件保留。

归档路径由驱动按卷根拼接：

```text
<卷根>\<ArchiveDirectory>\<hash>[.<ext>]
```

如果未配置 `ArchiveDirectory`、目录组件无效、归档目录校验失败或归档动作失败，但原文件已经成功移除，Event 27 仍按阻止成功收口。copy fallback 会比较复制前后的源文件身份，源文件发生变化时会删除不可信归档输出并阻止删除 fallback。

## `Options` 位语义

当前 `config.h` 中的位定义为：

- `0x01`
  `NetworkConnect`
- `0x02`
  `ImageLoad`
- `0x04`
  `PipeMonitoring`
- `0x08`
  `DriverName`

这些位来自当前实现，而不是文档推断。使用时应以代码为准。

## `HashingAlgorithm` 位语义

当前实现支持：

- `0x01`
  `MD5`
- `0x02`
  `SHA1`
- `0x04`
  `SHA256`
- `0x08`
  `IMPHASH`

当前代码中的 `SYSMON_HASH_DEFAULT` 为 `0x00`。这点与一些旧说明中的 “默认 MD5+SHA1” 表述并不一致，因此需要把“原版行为”和“当前实现”分开看。

## 命令行为

### `Sysmon.exe -i [config]`

- 安装用户态服务和驱动服务
- 可选读取并持久化配置文件
- 配置安装路径应复用与 `-c` 相同的编译和写注册表逻辑

### `Sysmon.exe -u [force]`

- 停止并删除服务
- 删除驱动服务
- 清理注册表和相关安装状态

### `Sysmon.exe -c <config>`

- 解析 XML
- 编译规则
- 计算配置哈希
- 写入注册表
- 通知驱动热更新

### `Sysmon.exe -c`

当前实现支持不带文件路径时直接输出当前配置摘要。这一点和原版的使用习惯是一致的。

### `Sysmon.exe -s`

当前实现侧重输出内置 schema / manifest 片段，而不是简单复述注册表配置。

### `Sysmon.exe -m`

用于安装事件描述资源和相关 manifest，使事件查看器能显示 Provider 描述和字段模板。

## 当前项目环境示例

- 默认远程配置文件：
  `C:\ProgramData\OpenSysmon\sysmon_config.xml`
- 常见更新方式：
  `Sysmon.exe -c C:\ProgramData\OpenSysmon\sysmon_config.xml`

## 原版行为 / 当前实现 / 当前差距

### 配置语法

- 原版行为
  支持完整 Sysmon XML 及其过滤语义。
- 当前实现
  已支持主要顶层项、常见事件节点、`RuleGroup`、嵌套 `Rule` 和多种条件类型。
- 当前差距
  仍需结合真实配置样本和逆向结果继续核对边角语义。

### 持久化格式

- 原版行为
  配置不仅要能解析，还要以原版注册表风格持久化。
- 当前实现
  已经使用统一路径写入 `Rules`、`ConfigHash`、`Options` 等关键值。
- 当前差距
  仍需继续比对 blob 细节、默认值和少量位定义是否与原版完全一致。

### 运行时过滤

- 原版行为
  驱动侧和服务侧围绕同一套过滤语义工作。
- 当前实现
  已具备共享规则模型和驱动侧规则运行时。
- 当前差距
  某些事件仍然依赖用户态补充信息后再做最终判断，完整对齐仍在推进中。
