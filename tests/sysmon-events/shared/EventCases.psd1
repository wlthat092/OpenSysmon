@{
    1  = @{ Node = 'ProcessCreate'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','FileVersion','Description','Product','Company','OriginalFileName','CommandLine','CurrentDirectory','User','LogonGuid','LogonId','TerminalSessionId','IntegrityLevel','Hashes','ParentProcessGuid','ParentProcessId','ParentImage','ParentCommandLine','ParentUser') }
    2  = @{ Node = 'FileCreateTime'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','TargetFilename','CreationUtcTime','PreviousCreationUtcTime','User') }
    3  = @{ Node = 'NetworkConnect'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','User','Protocol','Initiated','SourceIsIpv6','SourceIp','SourceHostname','SourcePort','SourcePortName','DestinationIsIpv6','DestinationIp','DestinationHostname','DestinationPort','DestinationPortName'); NotPlaceholderFields = @('ProcessGuid','ProcessId','Image','Protocol','SourceIp','DestinationIp') }
    5  = @{ Node = 'ProcessTerminate'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','User') }
    6  = @{ Node = 'DriverLoad'; RequiredFields = @('RuleName','UtcTime','ImageLoaded','Hashes','Signed','Signature','SignatureStatus') }
    7  = @{ Node = 'ImageLoad'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','ImageLoaded','FileVersion','Description','Product','Company','OriginalFileName','Hashes','Signed','Signature','SignatureStatus','User') }
    8  = @{ Node = 'CreateRemoteThread'; RequiredFields = @('RuleName','UtcTime','SourceProcessGuid','SourceProcessId','SourceImage','TargetProcessGuid','TargetProcessId','TargetImage','NewThreadId','StartAddress','StartModule','StartFunction','SourceUser','TargetUser') }
    9  = @{ Node = 'RawAccessRead'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','Device','User') }
    10 = @{ Node = 'ProcessAccess'; RequiredFields = @('RuleName','UtcTime','SourceProcessGUID','SourceProcessId','SourceThreadId','SourceImage','TargetProcessGUID','TargetProcessId','TargetImage','GrantedAccess','CallTrace','SourceUser','TargetUser') }
    11 = @{ Node = 'FileCreate'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','TargetFilename','CreationUtcTime','User') }
    12 = @{ Node = 'RegistryEvent'; RequiredFields = @('RuleName','EventType','UtcTime','ProcessGuid','ProcessId','Image','TargetObject','User') }
    13 = @{ Node = 'RegistryEvent'; RequiredFields = @('RuleName','EventType','UtcTime','ProcessGuid','ProcessId','Image','TargetObject','Details','User') }
    14 = @{ Node = 'RegistryEvent'; RequiredFields = @('RuleName','EventType','UtcTime','ProcessGuid','ProcessId','Image','TargetObject','NewName','User') }
    15 = @{ Node = 'FileCreateStreamHash'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','TargetFilename','CreationUtcTime','Hash','Contents','User') }
    17 = @{ Node = 'PipeEvent'; RequiredFields = @('RuleName','EventType','UtcTime','ProcessGuid','ProcessId','PipeName','Image','User') }
    18 = @{ Node = 'PipeEvent'; RequiredFields = @('RuleName','EventType','UtcTime','ProcessGuid','ProcessId','PipeName','Image','User') }
    19 = @{ Node = 'WmiEvent'; RequiredFields = @('RuleName','EventType','UtcTime','Operation','User','EventNamespace','Name','Query') }
    20 = @{ Node = 'WmiEvent'; RequiredFields = @('RuleName','EventType','UtcTime','Operation','User','Name','Type','Destination') }
    21 = @{ Node = 'WmiEvent'; RequiredFields = @('RuleName','EventType','UtcTime','Operation','User','Consumer','Filter') }
    22 = @{ Node = 'DnsQuery'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','QueryName','QueryStatus','QueryResults','Image','User'); NotPlaceholderFields = @('ProcessGuid','ProcessId','QueryName','QueryStatus','Image') }
    24 = @{ Node = 'ClipboardChange'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','Session','ClientInfo','Hashes','Archived','User'); NotPlaceholderFields = @('ProcessGuid','ProcessId','Image','Session') }
    25 = @{ Node = 'ProcessTampering'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','Image','Type','User') }
    26 = @{ Node = 'FileDeleteDetected'; RequiredFields = @('RuleName','UtcTime','ProcessGuid','ProcessId','User','Image','TargetFilename','Hashes','IsExecutable') }
}
