# 故障排查

## 排查原则

建议始终按下面顺序收口：

1. 先确认构建产物是否正确。
2. 再确认部署、签名和服务状态是否正常。
3. 再看事件是否进入队列、是否被正确输出。
4. 最后再定位到具体事件类型或字段问题。

## 常用入口

### 重新部署

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon
```

### 重新加载驱动

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Remote-ReloadDriver.ps1 -RemoteRoot C:\ProgramData\OpenSysmon
```

### 查看驱动统计

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Probe-SysmonStats.ps1
```

### 运行静态守卫

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1
```

### 检查 ETW 和事件描述资源

```powershell
Sysmon.exe -m
powershell -ExecutionPolicy Bypass -File .\scripts\Remote-EtwPublisherDiag.ps1
```

### 检查进程缓存

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Remote-QueryProcessCache.ps1 -ProcessName notepad
```

## 常见问题

### 安装后没有日志

- 先执行 `Sysmon.exe -m`
- 再执行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 1`
- 检查 `Microsoft-Windows-Sysmon/Operational` 是否出现 Event 1

### 驱动重载失败

- 先执行 `scripts/Remote-ReloadDriver.ps1 -RemoteRoot C:\ProgramData\OpenSysmon`
- 如果仍失败，检查服务状态、过滤器实例和签名状态
- 必要时重新跑一次 `deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon`

### 事件描述缺失

- 先执行 `Sysmon.exe -m`
- 再执行 `scripts/Remote-EtwPublisherDiag.ps1`
- 确认 `MSG00001.bin` 和 provider 资源已正确安装

### 怀疑队列或统计异常

- 使用 `scripts/Probe-SysmonStats.ps1`
- 重点观察 callback、capture、drop、delivery 等相关计数是否异常增长
- 如果关注 FileCreate / FileBlock minifilter 调试计数器，确认目标机部署的是 Debug 驱动。Release 构建为了降低热路径开销，会让这些 DBG-only 字段保持为 0。

### Event 27 / 29 行为不符合预期

- 先运行 `scripts/Test-FileBlockExecutableRegression.ps1`，确认基础阻止和 detect-only 场景是否仍通过。
- Event 27 `FileBlockExecutable` 命中后应删除原文件；如果命中 CopyOnDelete 条件并且 `ArchiveDirectory` 有效，还应尝试在 `<卷根>\<ArchiveDirectory>\...` 下留下归档样本。
- Event 29 `FileExecutableDetected` 是 detect-only，预期是记录日志但保留原文件，也不应为同一样本产生 Event 27。
- `ArchiveDirectory` 必须是单个目录组件，例如 `Sysmon`；不能是 `C:\...`、包含 `\` / `/`、或包含相对路径段。
- 归档失败不一定表示 Event 27 失败。当前实现允许在归档目录无效或归档动作失败时退化为仅删除原文件。

### ClipboardChange 没有事件

- Event 24 当前主要由用户态 `clipboard_monitor.cpp` 的窗口消息/RPC helper 生产，不是单纯依赖 `SysmonDrv/src/clipboard.c`。
- 服务会根据当前规则运行时启停 clipboard monitor；如果配置里没有能产生日志的 `ClipboardChange` 规则，helper 可能不会启动。
- 先确认 `Sysmon.exe -c <config>` 已加载包含 `ClipboardChange` 的配置，再手工改变剪贴板内容并查看 `Microsoft-Windows-Sysmon/Operational`。

### 静态守卫失败

- `scripts/Test-StaticRegressionGuards.ps1` 覆盖 manifest/schema 版本、FileBlock 原版 bit 对齐、归档根目录构造、CopyOnDelete 安全退化和 DBG-only 调试计数器等关键点。
- 失败时优先按脚本输出的断言文本回到对应源码位置，不要只重跑构建；这些守卫通常表示对齐假设已经被源码改动破坏。

## 当前约束

- 根目录已经不再保留历史 `check_*`、`test_*`、`compare_*` 脚本。
- 如果旧文档或历史计划仍提到这些脚本，应视为归档信息，不再是当前支持的排障入口。
- 新增排障脚本请优先放到 `scripts/` 下。
