# OpenSysmon

Languages: [中文](README.md) | English

This project is released under the [MIT License](LICENSE). Third-party dependencies under `third_party/` remain subject to their own licenses, copyright notices, and NOTICE requirements.

OpenSysmon is a Sysmon-compatible implementation based on reverse-engineering results from the original `Sysmon64.exe` and `SysmonDrv.sys`. It includes a user-mode service/CLI, kernel driver, configuration compatibility layer, deployment scripts, event-test scripts, and comparison assets. The implementation was developed with AI assistance for reverse-engineering analysis, code generation, test orchestration, and documentation; it is not an official Microsoft implementation or product.

## Current Status

- The project aims to align with the original Sysmon configuration syntax, filtering semantics, driver event structures, registry persistence, and command-line behavior.
- The repository contains implementation code, standard event XML samples, remote deployment scripts, and original-versus-OpenSysmon comparison assets.
- Root `deploy.ps1` builds and deploys Release artifacts by default. `SysmonUser/build.ps1` and `SysmonDrv/build.ps1` default to Debug when run separately.
- This project is for learning, research, and testing only. Dynamic validation has currently been performed only on Windows 10 2021 LTSC; compatibility with other Windows versions is not implied.

## Quick Start

Clone with `git clone --recurse-submodules <repository-url>`. For an existing clone, run `git submodule update --init --recursive` before building.

1. Run static regression guards:
   `powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1`
2. Build the user-mode Release binary:
   `powershell -ExecutionPolicy Bypass -File .\SysmonUser\build.ps1 -Configuration Release`
3. Build the kernel-driver Release binary:
   `powershell -ExecutionPolicy Bypass -File .\SysmonDrv\build.ps1 -Configuration Release -Rebuild`
4. Deploy the current artifacts:
   `powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Target user@host -RemoteRoot C:\ProgramData\OpenSysmon`
5. Install and load a configuration on the target:
   `Sysmon.exe -i <config.xml>`
6. Run a smoke event test:
   `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 22`

## Dependencies and Licensing

### Build Dependencies

- Windows 10/11 x64.
- Visual Studio 2022 or Build Tools with MSVC, MSBuild, and C++ tools.
- Windows 10 SDK/WDK. The driver script defaults to `10.0.26100.0`; `mc.exe` and `midl.exe` are required.
- CMake and Git. `third_party/SymCrypt` is built as a static-library source dependency.
- PowerShell 5.1 or later. Pester 5 is required for Pester tests.

### Runtime and Remote-Test Dependencies

- A Windows x64 target with administrator access and running `Sysmon` and `SysmonDrv` services.
- OpenSSH Client (`ssh` and `scp`) on the local machine and an SSH service on the target for remote deployment.
- An externally obtained [`SysmonSimulator.exe`](https://github.com/ScarredMonk/SysmonSimulator). It is not distributed in this repository. Place it at `tests/sysmon-events/tools/SysmonSimulator.exe`; the deployment script uploads it with the test suite.

### Licenses

- Original project code and documentation are released under the [MIT License](LICENSE).
- `third_party/SymCrypt` follows its own [LICENSE](third_party/SymCrypt/LICENSE.txt) and [NOTICE](third_party/SymCrypt/NOTICE.txt), which must be retained when redistributing it.
- Visual Studio, Windows SDK/WDK, PowerShell, OpenSSH, and `SysmonSimulator.exe` from [ScarredMonk/SysmonSimulator](https://github.com/ScarredMonk/SysmonSimulator) are not distributed by this project and remain subject to their suppliers' or authors' licenses.

### Reference Configuration Source

The default root configuration, `sysmon_config.xml`, references rule organization and configuration content from [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular). Copyright, licensing, and upstream notices for referenced rules remain with that project; this repository does not claim independent copyright in those original rules.

## Security Warning

- **This project is not suitable for production use.** The implementation is still being aligned and validated and must not be deployed directly as a production monitoring, blocking, or security-protection component.
- **For learning and testing only.** Dynamic tests have so far been run only on Windows 10 2021 LTSC. Other operating-system versions and hardware combinations require independent validation.
- The project includes a kernel driver and system service. Installation, upgrades, removal, and configuration changes require administrator rights; driver or rule errors can make a system unstable, lose events, or reduce performance.
- Use an isolated test VM and create a snapshot before first use. Do not install the driver or run regression scripts on production systems or devices containing important data.
- `SysmonSimulator.exe` deliberately generates process, file, network, registry, WMI, pipe, and clipboard activity. Run it only in a dedicated test environment after reviewing the configuration and test scripts.
- Remote deployment uploads files over SSH/SCP and executes PowerShell on the target. Use a dedicated test account and key authentication, restrict target privileges, and never commit private keys, passwords, internal addresses, or test logs.
- Verify binary provenance, signatures, and hashes before release or deployment. This project provides no security guarantee for Microsoft Sysmon or third-party tools and does not guarantee complete behavioral equivalence with the original Sysmon.

## Test Prerequisites

Before running `tests/sysmon-events/Deploy-EventTests.ps1`, confirm that:

- The user-mode binary has been built locally and `SysmonUser/x64/Release/Sysmon.exe` or `SysmonUser/x64/Debug/Sysmon.exe` exists.
- The repository root contains `sysmon_config.xml`, and `SysmonSimulator.exe` from the upstream project is present at `tests/sysmon-events/tools/SysmonSimulator.exe`.
- The target is Windows x64, driver and services are deployed, both `Sysmon` and `SysmonDrv` report `Running`, and the target account can execute tests and read the Sysmon event log.
- The local machine can connect to the target non-interactively with `ssh` and `scp`; remote PowerShell can execute the test scripts.
- Testing is performed on an isolated VM or dedicated test host with a rollback snapshot or backup.

Local Pester tests additionally require Pester 5 and do not require a remote target.

## Documentation

- [Software architecture](docs/architecture.md)
- [Configuration and filtering](docs/configuration.md)
- [Installation and deployment](docs/deployment.md)
- [Testing and validation](docs/testing.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Event matrix](docs/events.md)

The technical documents under `docs/` are currently maintained in Chinese. The English README provides the project entry point and operational requirements.

## Repository Overview

- `SysmonUser/`: user-mode `Sysmon.exe` for CLI, service, configuration compilation, driver communication, event output, and manifest logic.
- `SysmonDrv/`: kernel-mode `SysmonDrv.sys` for event collection, filtering, event queues, and IOCTL communication.
- `events/`: standard Event ID 1-29 XML samples for field alignment and event-matrix review.
- `scripts/`: diagnostic, status, performance, and specialized regression tools.
- `tests/sysmon-events/`: the fixed simulator-backed event-test suite, uploaded and run by `Deploy-EventTests.ps1`.
- `schema_events.xml`: event schema and manifest definitions.
- `third_party/`: external source dependencies, currently used primarily for SymCrypt static-library builds.

## Common Commands

- Install: `Sysmon.exe -i [config.xml]`
- Uninstall: `Sysmon.exe -u [force]`
- Update configuration: `Sysmon.exe -c <config.xml>`
- Show current configuration: `Sysmon.exe -c` or `Sysmon.exe -s`
- Print schema/configuration help: `Sysmon.exe -s [-a]` or `Sysmon.exe -h config`
- Install event-description resources: `Sysmon.exe -m`
- Run a single event test: `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host -EventIds 1`
- Run the complete simulator-backed suite: `powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\sysmon-events\Deploy-EventTests.ps1 -Target user@host`
- Run static regression guards: `powershell -ExecutionPolicy Bypass -File .\scripts\Test-StaticRegressionGuards.ps1`
- Run FileBlockExecutable/FileExecutableDetected regression: `powershell -ExecutionPolicy Bypass -File .\scripts\Test-FileBlockExecutableRegression.ps1`

## Environment Parameters

Event-test scripts contain no fixed IP address, username, or desktop path. They require only `-Target` and optional `-EventIds`; the default remote upload directory is `C:\ProgramData\OpenSysmon\tests`. If root `deploy.ps1` is run without `-RemoteRoot`, it stages files under the target user's Desktop\sysmon directory; use `-RemoteRoot C:\ProgramData\OpenSysmon` for an explicit staging path. The local suite is fixed at `tests\sysmon-events`, and tools are placed under `tests\sysmon-events\tools`.

## Limitations

- Complete behavioral equivalence with the original Sysmon is still being investigated; differences are documented under `docs/`.
- The repository focuses on reproducible, isolated testing and is not a production-ready security product.
