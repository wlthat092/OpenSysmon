# 测试验证

## 说明

仓库根目录现在只保留部署、签名、安装和清理相关入口；诊断和回归脚本统一位于 `scripts/`。

历史上的 `check_*`、`test_*`、`compare_*`、review 辅助脚本已经从根目录清理，不再作为当前支持的验证入口。如果旧的设计文档或过程文档还提到这些脚本，应以本页和 `README.md` 为准。

## 当前保留的入口

### 构建与部署

- `SysmonUser/build.ps1`
- `SysmonDrv/build.ps1`
- `deploy.ps1`
- `full_install.ps1`

### 远程事件验证

- `tests/sysmon-events/Deploy-EventTests.ps1`
- `scripts/Test-FileBlockExecutableRegression.ps1`

### 诊断、状态和性能工具

- `scripts/Test-StaticRegressionGuards.ps1`
- `scripts/Probe-SysmonStats.ps1`
- `scripts/Remote-EtwPublisherDiag.ps1`
- `scripts/Remote-QueryProcessCache.ps1`
- `scripts/Remote-ReloadDriver.ps1`
- `scripts/Remote-DumpEventFields.ps1`

## 推荐最小回归流程

1. 先运行本地静态守卫：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1
```

2. 本地重新构建：

```powershell
powershell -ExecutionPolicy Bypass -File .\SysmonUser\build.ps1 -Configuration Release
powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Configuration Release -Rebuild
```

单独运行构建脚本时默认是 Debug；`deploy.ps1` 默认构建和部署 Release。若要观察 FileCreate / FileBlock minifilter 调试计数器，应部署 Debug 驱动。

3. 部署到目标机：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon
```

4. 安装或刷新事件描述资源：

```powershell
Sysmon.exe -m
```

5. 跑最小烟雾场景：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 22
```

6. 如需看驱动统计或队列状态，再补充：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Probe-SysmonStats.ps1
```

7. 如本次改动涉及 FileBlock、schema、manifest、配置持久化或驱动调试统计，再补充：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-FileBlockExecutableRegression.ps1
```

## Sysmon 事件远程套件

`tests/sysmon-events/` 是事件测试脚本、配置和工具的固定目录。调用时只需传入远程目标和可选事件 ID，默认上传目录为 `C:\ProgramData\OpenSysmon\tests`；如有需要仍可通过 `-RemoteRoot` 覆盖。

`Deploy-EventTests.ps1` 是唯一的模拟器事件测试入口。完整运行 23 个当前模拟器支持的事件：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host
```

先运行 Event 22 单事件验证：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 22
```

在已有 PowerShell 会话中运行多个事件：

```powershell
& .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds @(1,8,22)
```

上传入口会先在本地校验完整的 23 个事件资产，然后使用 `scp -r` 把整个 `tests/sysmon-events` 目录上传到 `-RemoteRoot`，再把仓库构建出的 Sysmon、主配置和 `tools/SysmonSimulator.exe` 放入远程 `tools` 子目录。每个 `test.ps1` 都在虚拟机上调用这些已上传的副本；远程 `Run-All.ps1` 会为每个事件输出一行紧凑 JSON，并在末尾输出汇总结果。

事件套件只依赖远程 SSH/SCP 通道来传输文件；但运行测试前，目标机仍必须已安装并运行 `Sysmon` 与 `SysmonDrv` 服务。可先使用仓库根目录的 `deploy.ps1` 完成驱动和服务部署，再运行本套件。

远程编排器会在 `finally` 中通过远程 `tools\Sysmon.exe -c tools\sysmon_config.xml` 恢复配置。测试套件不会停止、卸载或删除 `Sysmon` / `SysmonDrv` 服务；单个事件失败后仍继续执行剩余事件，任一事件或配置恢复失败都会使套件最终返回非零退出码。

当前覆盖 ID 为 `1,2,3,5-15,17-22,24-26`。默认每个事件只要求触发窗口内至少出现 1 条记录；只有 `EventCases.psd1` 明确设置 `ExpectedCount` 时才做精确数量断言。Event 4、16、23、27、28、29 不在本套件中，因为当前 `SysmonSimulator.exe` 不提供对应触发器。

Event 18 在 Event 18 配置加载后使用 `Normal` 窗口启动模拟器，并对已观察到的模拟器堆崩溃退出码 `0xC0000374` 最多重试 3 次；每次成功仍需验证 Event 18 字段。该模拟器在此配置下使用 `Hidden` 窗口更容易触发该退出码，其他事件继续使用隐藏窗口启动。

2026-08-24 在隔离测试目标上单独复测 Event 3 已通过。Event 3 测试配置使用模拟器固定目标端口 `31337` 的非空 include 条件，避免空 include 被规则运行时解释为禁用 Network ETW source；该事件不要求目标主机能够完成外网连接，只要产生连接尝试即可。

## FileBlockExecutable 回归

1. 确保已经完成本地构建、部署和 `Sysmon.exe -m` 资源刷新。
2. 在目标机器上运行回归脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Test-FileBlockExecutableRegression.ps1
```

可用 `-Scenario Block` 只验证 Event 27 阻止路径，`-Scenario DetectOnly` 只验证 Event 29 检测路径，默认 `-Scenario All` 会依次覆盖两者。

3. 预期行为：
- `blocked.exe` 从原始落地点消失。
- `fake.exe` 仍然保留。
- 出现 `Event 27 FileBlockExecutable`。
- 不出现对应样本的 `Event 29 FileExecutableDetected`。
- 如果 `blocked.exe` 在追加 marker 之前就已被阻止并移除，也视为合法通过；这表示驱动在更早的 cleanup 时机完成了收口。

4. 归档分支预期：
- 未配置或未命中任何 `CopyOnDelete*` 时，允许退化为仅删除原文件；不要求归档目录下必须有样本。
- 命中 `CopyOnDeletePE=true` 或任一 `CopyOnDeleteSIDs / CopyOnDeleteExtensions / CopyOnDeleteProcesses` 时，还应在 `<卷根>\<ArchiveDirectory>\...` 下看到归档样本。
- 如果归档目录无效或归档动作失败，但原文件已被成功移除，仍按 `Event 27` 成功收口处理。

5. Detect-only 分支预期：
- 只启用 `FileExecutableDetected` 时，`detected.exe` 应保留。
- 出现 `Event 29 FileExecutableDetected`。
- 不出现对应样本的 `Event 27 FileBlockExecutable`。

6. 已知限制：
- 驱动内部仍使用 `SYSMON_MAX_PATH` 大小的事件路径缓冲；超过该上限的目标路径可能无法完成 PE 复检或事件构建，应作为长路径专项另行验证。

7. 原版对齐说明：
- FileBlock stream context 低位标志已按原版 Sysmon 15.20 live dump 对齐：`SAW_WRITE=0x08`、`HEADER_CHECKED=0x10`、`IS_PE=0x20`。复刻内部 `EVENT_REPORTED` 幂等状态使用高位私有 bit，不占用原版低位。
- FileBlockExecutable 清理前会重新读取当前 `FileObject` 的 PE 头；如果清理前已无法确认仍为 PE，则跳过删除/归档。copy fallback 会比较复制前后的源文件大小、时间戳和属性，源文件变化时删除不可信归档输出并阻止删除 fallback。该逻辑缓解检测到清理之间的窗口，但无法完全消除底层文件系统 rename/delete/copy 执行期间的并发写入竞态。

## 手工验证建议

- 所有模拟器支持的 Event 1、2、3、5-15、17-22、24-26 均通过 `tests/sysmon-events/Deploy-EventTests.ps1` 验证；单个或多个事件均使用 `-EventIds` 选择。
- 字段、ETW provider 或运行时诊断使用保留的 `scripts/Remote-DumpEventFields.ps1`、`scripts/Remote-EtwPublisherDiag.ps1`、`scripts/Probe-SysmonStats.ps1` 及类似工具，不使用事件专用 smoke/probe 脚本。
- Event 4、16、23、27、28、29 需要使用内部事件、专项回归或手工场景验证，不能计入当前模拟器套件覆盖。

## 工件与结果

当前验证流程默认依赖：

- `events/*.xml` 作为字段参考
- 目标机上的 `Microsoft-Windows-Sysmon/Operational` 日志
- 使用者自行生成的对照与抓取资料（例如本地 `artifacts/` 目录；该目录不随仓库分发）

如果需要新增事件套件资产，应放到 `tests/sysmon-events/event-XX/`；其他专项诊断脚本放到 `scripts/`，不要重新堆回仓库根目录。
