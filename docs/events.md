# 事件矩阵

## 使用说明

本表用于把当前实现与标准事件 XML、触发方式、验证脚本和当前对齐状态放到同一个视图里，便于逐项收口。表中“当前实现入口”描述的是当前仓库中最主要的采集或发射位置，不等同于完整调用链。

## 状态说明

- `部分对齐`
  已有主链路和基础字段，但仍在继续核对字段细节、过滤语义或稳定性。
- `已接入，待验证`
  代码路径和文档资产已存在，但需要更多现场回归验证。
- `已实现，回归通过`
  当前功能链路已实现，并有仓库内专项脚本或静态守卫覆盖关键退化点。
- `远程套件覆盖`
  当前 `SysmonSimulator.exe` 支持触发，并由 `tests/sysmon-events/event-XX/test.ps1` 在虚拟机上验证事件和字段。
- `当前模拟器不支持`
  当前 `SysmonSimulator.exe` 没有对应触发器，不计入远程事件套件覆盖。
- `内部事件`
  主要由服务或配置变更路径发出，不走常规驱动采集链。

## 部署环境约定

- 目标机和凭据由调用者提供
- 事件测试目录：`C:\ProgramData\OpenSysmon\tests`
- 模拟器由本机测试目录上传到目标机

## 事件总表

| ID | 名称 | 标准 XML | 当前实现入口 | 关键字段 | 触发 / 验证 | 当前状态 |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | ProcessCreate | `events/sysmon_event_01_process_creation.xml` | `SysmonDrv/src/process.c` | `Image` `CommandLine` `ParentImage` | `tests/sysmon-events/event-01/test.ps1` | 远程套件覆盖 |
| 2 | FileCreateTime | `events/sysmon_event_02_a_process_changed_a_file_creation_time.xml` | `SysmonDrv/src/minifilter.c` | `Image` `TargetFilename` `CreationUtcTime` | `tests/sysmon-events/event-02/test.ps1` | 远程套件覆盖 |
| 3 | NetworkConnect | `events/sysmon_event_03_network_connection_detected.xml` | `SysmonUser/src/network_trace.cpp`（Kernel-Network ETW） | `Image` `Protocol` `DestinationIp` `DestinationPort` | `tests/sysmon-events/event-03/test.ps1` | 远程套件覆盖 |
| 4 | SysmonServiceStateChange | `events/sysmon_event_04_sysmon_service_state_changed.xml` | `SysmonUser/src/service.cpp` | `State` `Version` `SchemaVersion` | 当前 `SysmonSimulator.exe` 不支持 Event 4；服务启停手工验证 | 当前模拟器不支持 |
| 5 | ProcessTerminate | `events/sysmon_event_05_process_terminated.xml` | `SysmonDrv/src/process.c` | `Image` `ProcessId` | `tests/sysmon-events/event-05/test.ps1` | 远程套件覆盖 |
| 6 | DriverLoad | `events/sysmon_event_06_driver_loaded.xml` | `SysmonDrv/src/image.c` | `ImageLoaded` `Hashes` `Signed` | `tests/sysmon-events/event-06/test.ps1` | 远程套件覆盖 |
| 7 | ImageLoad | `events/sysmon_event_07_image_loaded.xml` | `SysmonDrv/src/image.c` | `ImageLoaded` `Image` `Hashes` | `tests/sysmon-events/event-07/test.ps1` | 远程套件覆盖 |
| 8 | CreateRemoteThread | `events/sysmon_event_08_createremotethread.xml` | `SysmonDrv/src/thread.c` | `SourceImage` `TargetImage` `StartAddress` | `tests/sysmon-events/event-08/test.ps1` | 远程套件覆盖 |
| 9 | RawAccessRead | `events/sysmon_event_09_rawaccessread.xml` | `SysmonDrv/src/minifilter.c` | `Image` `Device` | `tests/sysmon-events/event-09/test.ps1` | 远程套件覆盖 |
| 10 | ProcessAccess | `events/sysmon_event_10_processaccess.xml` | `SysmonDrv/src/obcallback.c` | `SourceImage` `TargetImage` `GrantedAccess` `CallTrace` | `tests/sysmon-events/event-10/test.ps1` | 远程套件覆盖 |
| 11 | FileCreate | `events/sysmon_event_11_filecreate.xml` | `SysmonDrv/src/minifilter.c` | `Image` `TargetFilename` | `tests/sysmon-events/event-11/test.ps1` | 远程套件覆盖 |
| 12 | RegistryEvent | `events/sysmon_event_12_registryevent_object_create_and_delete.xml` | `SysmonDrv/src/registry.c` | `EventType` `TargetObject` | `tests/sysmon-events/event-12/test.ps1` | 远程套件覆盖 |
| 13 | RegistryValueSet | `events/sysmon_event_13_registryevent_value_set.xml` | `SysmonDrv/src/registry.c` | `TargetObject` `Details` | `tests/sysmon-events/event-13/test.ps1` | 远程套件覆盖 |
| 14 | RegistryRename | `events/sysmon_event_14_registryevent_key_and_value_rename.xml` | `SysmonDrv/src/registry.c` | `TargetObject` `NewName` | `tests/sysmon-events/event-14/test.ps1` | 远程套件覆盖 |
| 15 | FileCreateStreamHash | `events/sysmon_event_15_filecreatestreamhash.xml` | `SysmonDrv/src/minifilter.c` | `TargetFilename` `Hash` | `tests/sysmon-events/event-15/test.ps1` | 远程套件覆盖 |
| 16 | SysmonConfigStateChange | `events/sysmon_event_16_sysmon_config_state_changed.xml` | `SysmonUser/src/config.cpp` | `Configuration` `ConfigurationFileHash` | 当前 `SysmonSimulator.exe` 不支持 Event 16；配置变更手工验证 | 当前模拟器不支持 |
| 17 | PipeCreated | `events/sysmon_event_17_pipe_created.xml` | `SysmonDrv/src/pipe.c` | `PipeName` `Image` | `tests/sysmon-events/event-17/test.ps1` | 远程套件覆盖 |
| 18 | PipeConnected | `events/sysmon_event_18_pipe_connected.xml` | `SysmonDrv/src/pipe.c` | `PipeName` `Image` | `tests/sysmon-events/event-18/test.ps1` | 远程套件覆盖 |
| 19 | WmiEventFilter | `events/sysmon_event_19_wmieventfilter_activity_detected.xml` | `SysmonUser/src/wmi_trace.cpp`（ROOT\\Subscription） | `Name` `Query` `EventNamespace` | `tests/sysmon-events/event-19/test.ps1` | 远程套件覆盖 |
| 20 | WmiEventConsumer | `events/sysmon_event_20_wmieventconsumer_activity_detected.xml` | `SysmonUser/src/wmi_trace.cpp`（ROOT\\Subscription） | `Name` `Type` `Destination` | `tests/sysmon-events/event-20/test.ps1` | 远程套件覆盖 |
| 21 | WmiEventConsumerToFilter | `events/sysmon_event_21_wmieventconsumertofilter_activity_detected.xml` | `SysmonUser/src/wmi_trace.cpp`（ROOT\\Subscription） | `Consumer` `Filter` | `tests/sysmon-events/event-21/test.ps1` | 远程套件覆盖 |
| 22 | DnsQuery | `events/sysmon_event_22_dnsevent.xml` | `SysmonUser/src/dns_trace.cpp`（DNS Client ETW） | `QueryName` `QueryResults` `Image` | `tests/sysmon-events/event-22/test.ps1` | 远程套件覆盖 |
| 23 | FileDelete | `events/sysmon_event_23_filedelete.xml` | `SysmonDrv/src/minifilter.c` | `TargetFilename` `Archived` | 当前 `SysmonSimulator.exe` 不支持 Event 23；手工删除文件验证 | 当前模拟器不支持 |
| 24 | ClipboardChange | `events/sysmon_event_24_clipboardchange.xml` | `SysmonUser/src/clipboard_monitor.cpp` / `SysmonUser/src/service.cpp` | `Image` `Session` `ClientInfo` `Hashes` `Archived` `User` | `tests/sysmon-events/event-24/test.ps1` | 远程套件覆盖 |
| 25 | ProcessTampering | `events/sysmon_event_25_process_tampering.xml` | `SysmonDrv/src/tampering.c` | `Type` `SourceProcessGuid` `Image` | `tests/sysmon-events/event-25/test.ps1` | 远程套件覆盖 |
| 26 | FileDeleteDetected | `events/sysmon_event_26_file_delete_logged.xml` | `SysmonDrv/src/minifilter.c` | `TargetFilename` `Image` | `tests/sysmon-events/event-26/test.ps1` | 远程套件覆盖 |
| 27 | FileBlockExecutable | `events/sysmon_event_27_file_block_executable.xml` | `SysmonDrv/src/minifilter.c` | `TargetFilename` `Image` `Hashes` | 当前 `SysmonSimulator.exe` 不支持 Event 27；另由 `scripts/Test-FileBlockExecutableRegression.ps1` 覆盖 | 当前模拟器不支持（另有专项回归） |
| 28 | FileBlockShredding | `events/sysmon_event_28_file_block_shredding.xml` | `SysmonDrv/src/minifilter.c` | `TargetFilename` `Image` | 当前 `SysmonSimulator.exe` 不支持 Event 28；手工验证 | 当前模拟器不支持 |
| 29 | FileExecutableDetected | `events/sysmon_event_29_file_executable_detected.xml` | `SysmonDrv/src/minifilter.c` | `TargetFilename` `Hashes` `Image` | 当前 `SysmonSimulator.exe` 不支持 Event 29；另由 `scripts/Test-FileBlockExecutableRegression.ps1` 覆盖 | 当前模拟器不支持（另有专项回归） |

## 补充说明

- 事件 4、16、23、27、28、29 不在当前模拟器远程套件覆盖内；其中事件 4 和 16 更偏向服务 / 配置生命周期事件，不应与普通驱动回调事件混为一类。
- 事件 24 当前主要由 `clipboard_monitor.cpp` 的用户态窗口/RPC helper 生产；`SysmonDrv/src/clipboard.c` 仍是驱动侧兼容框架。
- 事件 27 与事件 29 共用 minifilter FileBlock 上下文。命中 27 时会尝试阻止并按 CopyOnDelete 条件归档，命中 29 时只检测并保留原文件。
- 事件 12、13、14 当前除字段存在性外，还需要重点核对 `TargetObject` 是否已经从内核路径转换为原版常见的 `HKLM` / `HKU` / `HKCR` 风格。
- 事件 1、10、22 当前是最值得持续盯紧的几类事件，因为它们分别覆盖进程创建、进程访问和 DNS 路径，既影响常用功能，也容易暴露驱动过滤与性能问题。
