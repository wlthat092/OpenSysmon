# Event test tools

Download [`SysmonSimulator.exe`](https://github.com/ScarredMonk/SysmonSimulator) from the upstream project and place it in this directory before running `Deploy-EventTests.ps1`.
The deployment script uploads the complete `tests/sysmon-events` directory and copies the repository Sysmon build plus the main configuration into the remote `tools` directory.
