<#
    Get-LokProgrammer.ps1
    Laedt die Altsoftware von esu.eu - NUR innerhalb der Sandbox ausfuehren.
    Fragt vor dem Download nach. Fuehrt nichts aus.
#>

$ErrorActionPreference = 'Stop'
$dest = "$env:USERPROFILE\Downloads"

$items = @(
    @{ Name = 'LokProgrammer_v1.51_DE.exe'
       Hash = 'a7726bd70d8ab97ca0007cc26f4cfa1f'
       Info = 'Deutsch, Version 1.51, ca. 1,85 MB, .exe' }
    @{ Name = 'LokProgrammer_v1.42_EN.zip'
       Hash = 'c93cbc720c2b5f2dcf8bb988a28dd234'
       Info = 'English, Version 1.42, ca. 774 kB, .zip' }
)

Write-Host ''
Write-Host '  Download von www.esu.eu (LokProgrammer 50450, Stand 01.01.2002)' -ForegroundColor Cyan
Write-Host ''
for ($i = 0; $i -lt $items.Count; $i++) {
    Write-Host ("   [{0}] {1}  -  {2}" -f ($i + 1), $items[$i].Name, $items[$i].Info)
}
Write-Host '   [0] Abbrechen'
Write-Host ''

if ((Test-NetConnection -ComputerName www.esu.eu -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded -ne $true) {
    Write-Host '  Kein Netzwerk in dieser Sandbox.' -ForegroundColor Yellow
    Write-Host '  Diese .wsb-Datei laeuft offline. Nutze Sandbox-Analyse.wsb,' -ForegroundColor Yellow
    Write-Host '  oder lege die Datei auf dem Host in den Ordner "shared".' -ForegroundColor Yellow
    Write-Host ''
    return
}

$sel = Read-Host '  Auswahl'
if ($sel -notmatch '^[12]$') { Write-Host '  Abgebrochen.' -ForegroundColor Gray; return }

$item = $items[[int]$sel - 1]
$url  = 'https://www.esu.eu/download/software/fruehere-produkte/?no_cache=1&tx_esudownloads_pi1%5BdownloadItem%5D=' + $item.Hash
$out  = Join-Path $dest $item.Name

Write-Host ''
Write-Host "  Lade  $($item.Name) ..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -UserAgent 'Mozilla/5.0'

$f = Get-Item $out
Write-Host ("  Fertig: {0}  ({1:N0} Bytes)" -f $f.FullName, $f.Length) -ForegroundColor Green
Write-Host ''
Write-Host '  Jetzt analysieren (fuehrt nichts aus):' -ForegroundColor Cyan
Write-Host "  powershell -File $env:USERPROFILE\Desktop\tools\Inspect-Installer.ps1" -ForegroundColor White
Write-Host ''
