param(
    [int]$EventId,
    [int]$MaxEvents = 50
)

$ErrorActionPreference = 'Stop'
$event = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents $MaxEvents |
    Where-Object { $_.Id -eq $EventId } |
    Select-Object -First 1

if (-not $event) {
    Write-Host "Event $EventId not found."
    exit 1
}

[xml]$xml = $event.ToXml()
Write-Host ("EventId={0} Version={1} TimeCreated={2:o}" -f $event.Id, $xml.Event.System.Version, $event.TimeCreated)
$ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
$ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
$dataNodes = $xml.SelectNodes('//e:Event/e:EventData/e:Data', $ns)
foreach ($data in $dataNodes) {
    Write-Host ("{0}={1}" -f $data.GetAttribute('Name'), $data.InnerText)
}

if ($dataNodes.Count -eq 0) {
    Write-Host 'No EventData nodes found.'
}
