<#
    Test-COM1.ps1
    Prueft den physischen seriellen Port, BEVOR eine VM ins Spiel kommt.

    Sinn: Wenn der LokProgrammer spaeter nicht antwortet, muss man wissen,
    ob es an der VM liegt oder am Port selbst. Dieses Skript klaert das
    auf der Host-Seite.

    Sendet nichts an angeschlossene Geraete ausser im optionalen
    Loopback-Test (-Loopback), der eine Bruecke Pin 2 <-> Pin 3 erwartet.
#>

[CmdletBinding()]
param(
    [string]$Port = 'COM1',
    [switch]$Loopback
)

$ErrorActionPreference = 'Continue'

function Line($t, $c = 'Gray') { Write-Host "  $t" -ForegroundColor $c }

Write-Host ''
Write-Host ('=' * 66) -ForegroundColor DarkCyan
Write-Host "  SERIELLE DIAGNOSE - $Port" -ForegroundColor Cyan
Write-Host ('=' * 66) -ForegroundColor DarkCyan
Write-Host ''

# ---------------------------------------------------------- 1. Existiert er?
$known = [System.IO.Ports.SerialPort]::GetPortNames()
Line "Gemeldete Ports: $($known -join ', ')"
if ($known -notcontains $Port) {
    Line "$Port ist dem System nicht bekannt. Abbruch." Red
    return
}

# ---------------------------------------------------------- 2. WMI-Eckdaten
$wmi = Get-CimInstance Win32_SerialPort -Filter "DeviceID='$Port'" -ErrorAction SilentlyContinue
if ($wmi) {
    Line "Beschreibung   : $($wmi.Description)"
    Line "Typ            : $($wmi.ProviderType)"
    Line "Max. Baudrate  : $($wmi.MaxBaudRate)"
}

$pnp = Get-PnpDevice -Class Ports -ErrorAction SilentlyContinue |
       Where-Object { $_.FriendlyName -like "*$Port*" }
if ($pnp) {
    $col = if ($pnp.Status -eq 'OK') { 'Green' } else { 'Red' }
    Line "PnP-Status     : $($pnp.Status)" $col
    Line "InstanceId     : $($pnp.InstanceId)"
    if ($pnp.InstanceId -like 'ACPI\PNP0501*') {
        Line "-> Onboard-UART (16550-kompatibel). Bestes Timing-Verhalten." Green
    } elseif ($pnp.InstanceId -like 'USB\*') {
        Line "-> USB-Seriell-Adapter. Achtung: hoehere Latenz, in VMs" Yellow
        Line "   besser den USB-Adapter direkt durchreichen statt den COM-Port." Yellow
    }
}

# ------------------------------------------------------ 3. Belegt jemand ihn?
Write-Host ''
Line 'Oeffne Port exklusiv ...' DarkGray
$sp = New-Object System.IO.Ports.SerialPort $Port, 9600, 'None', 8, 'One'
try {
    $sp.ReadTimeout  = 800
    $sp.WriteTimeout = 800
    $sp.Open()
    Line 'Port laesst sich oeffnen - er ist frei.' Green
} catch {
    Line "Port laesst sich NICHT oeffnen: $($_.Exception.Message)" Red
    Line 'Meist belegt ihn ein anderer Prozess, oder Rechte fehlen.' Yellow
    return
}

# ------------------------------------------------------------ 4. Leitungen
try {
    Line ''
    Line "CTS (Clear To Send) : $($sp.CtsHolding)"
    Line "DSR (Data Set Ready): $($sp.DsrHolding)"
    Line "CD  (Carrier Detect): $($sp.CDHolding)"
    if (-not $sp.CtsHolding -and -not $sp.DsrHolding) {
        Line '-> Keine Gegenstelle erkannt. Normal, wenn nichts angesteckt ist.' DarkGray
    }
} catch { }

# ------------------------------------------------------------ 5. Baudraten
Write-Host ''
Line 'Baudraten-Test:' DarkGray
foreach ($b in 9600, 19200, 38400, 57600, 115200) {
    try { $sp.BaudRate = $b; Line "  $b Baud  OK" Green }
    catch { Line "  $b Baud  abgelehnt" Yellow }
}
$sp.BaudRate = 9600

# ------------------------------------------------------------ 6. Loopback
if ($Loopback) {
    Write-Host ''
    Line 'LOOPBACK-TEST (Bruecke Pin 2 <-> Pin 3 noetig)' Cyan
    $probe = 'ESU-LOOPBACK-42'
    try {
        $sp.DiscardInBuffer(); $sp.DiscardOutBuffer()
        $sp.WriteLine($probe)
        Start-Sleep -Milliseconds 250
        $echo = $sp.ReadLine()
        if ($echo.Trim() -eq $probe) {
            Line "Echo korrekt empfangen: '$($echo.Trim())'" Green
            Line 'Sende- und Empfangspfad funktionieren physisch.' Green
        } else {
            Line "Echo abweichend: '$($echo.Trim())'" Yellow
        }
    } catch {
        Line "Kein Echo: $($_.Exception.Message)" Yellow
        Line 'Ohne Bruecke zwischen Pin 2 und 3 ist das zu erwarten.' DarkGray
    }
} else {
    Write-Host ''
    Line 'Loopback uebersprungen. Mit Bruecke Pin 2<->3 aufrufen als:' DarkGray
    Line '  .\Test-COM1.ps1 -Loopback' White
}

$sp.Close()
$sp.Dispose()

Write-Host ''
Write-Host ('=' * 66) -ForegroundColor DarkCyan
Line 'Port wieder freigegeben.' Green
Line 'Diesen Test WIEDERHOLEN, sobald die VM laeuft - dann aber' DarkGray
Line 'INNERHALB des Gastes. Gleiches Ergebnis = Passthrough ist in Ordnung.' DarkGray
Write-Host ''
