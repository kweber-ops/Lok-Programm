<#
    New-LegacyVM.ps1
    Legt eine VirtualBox-VM fuer einen 32-Bit-NT5-Gast an und reicht den
    PHYSISCHEN COM1 des Hosts durch.

    Warum VirtualBox und nicht Hyper-V:
    Hyper-V kann COM-Ports einer VM ausschliesslich an Named Pipes binden,
    NICHT an einen physischen Host-Port. Das gilt fuer Gen 1 und Gen 2 und
    steht so in der Set-VMComPort-Dokumentation. Fuer den LokProgrammer
    50450 braucht es aber einen echten UART. VirtualBox ("Host Device")
    und VMware ("serial0.fileType = device") koennen das.

    Das Skript laedt NICHTS herunter und installiert kein Betriebssystem.
    Das ISO musst du selbst stellen - siehe -IsoPath.

    Beispiel:
      .\New-LegacyVM.ps1 -IsoPath "D:\iso\win2000pro.iso"
      .\New-LegacyVM.ps1 -IsoPath "D:\iso\w2k.iso" -VMName "LokProg-W2K" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$IsoPath,

    [string]$VMName   = 'LokProgrammer-Win2000',
    [string]$BaseDir  = 'D:\VMs',
    [ValidateSet('Windows2000', 'WindowsXP', 'Windows98')]
    [string]$OsType   = 'Windows2000',
    [int]$MemoryMB    = 512,
    [int]$DiskMB      = 10240,
    [string]$HostCom  = 'COM1'
)

$ErrorActionPreference = 'Stop'

function Say($t, $c = 'Gray') { Write-Host "  $t" -ForegroundColor $c }
function Head($t) {
    Write-Host ''; Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

Head "VM-PROVISIONING - $VMName"

# ------------------------------------------------------- 1. VBoxManage da?
$vbox = @(
    "$env:ProgramFiles\Oracle\VirtualBox\VBoxManage.exe",
    "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VBoxManage.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $vbox) {
    Say 'VBoxManage.exe nicht gefunden - VirtualBox ist nicht installiert.' Red
    Say ''
    Say 'VirtualBox von der offiziellen Quelle installieren:' Yellow
    Say '  https://www.virtualbox.org/wiki/Downloads' White
    Say ''
    Say 'Danach dieses Skript erneut starten.' Yellow
    Say 'Ich lade bewusst nichts selbst herunter - Installation von' DarkGray
    Say 'Software ist deine Entscheidung.' DarkGray
    return
}
Say "VBoxManage : $vbox" Green
Say "Version    : $(& $vbox --version)" Green

# ------------------------------------------------------------- 2. ISO da?
if (-not (Test-Path $IsoPath)) {
    Say "ISO nicht gefunden: $IsoPath" Red
    Say ''
    Say 'Du brauchst ein eigenes, legal lizenziertes Installationsmedium.' Yellow
    Say 'Windows 2000 und XP sind seit Jahren nicht mehr neu erhaeltlich -' DarkGray
    Say 'legal bleibt nur die eigene Altlizenz oder eine gebrauchte' DarkGray
    Say 'Vollversion MIT Originaldatentraeger.' DarkGray
    Say ''
    Say 'Lizenzfreie Alternative zum Ausprobieren: ReactOS (weiterhin Alpha)' DarkGray
    Say '  https://reactos.org/download/' White
    return
}
Say "ISO        : $IsoPath" Green

# --------------------------------------------------------- 3. COM1 pruefen
$ports = [System.IO.Ports.SerialPort]::GetPortNames()
if ($ports -notcontains $HostCom) {
    Say "$HostCom existiert auf diesem Host nicht. Gefunden: $($ports -join ', ')" Red
    return
}
Say "Host-Port  : $HostCom (wird durchgereicht)" Green

# ------------------------------------------------------ 4. Namenskollision
$existing = & $vbox list vms
if ($existing -match [regex]::Escape("`"$VMName`"")) {
    Say "Es gibt bereits eine VM namens '$VMName'." Red
    Say 'Anderen Namen waehlen (-VMName) oder die alte zuerst entfernen:' Yellow
    Say "  & '$vbox' unregistervm '$VMName' --delete" White
    return
}

# ------------------------------------------------------------ 5. Vorschau
$vmDir = Join-Path $BaseDir $VMName
$vdi   = Join-Path $vmDir "$VMName.vdi"

Write-Host ''
Say 'Geplante Konfiguration:' Cyan
Say "  Gast-Typ        $OsType"
Say "  RAM             $MemoryMB MB"
Say "  Platte          $DiskMB MB  ($vdi)"
Say "  Chipsatz        PIIX3 + BIOS      (NT5 kennt nichts Neueres)"
Say "  CPU             1 vCPU            (mehr macht seriell schlechter)"
Say "  Grafik          VBoxVGA 32 MB, kein 3D"
Say "  Speicher-Ctrl   IDE/PIIX4         (kein SATA - keine Treiber im Gast)"
Say "  IO-APIC         aus               (nach Setup NIE aendern - HAL!)"
Say "  ACPI            an"
Say "  Paravirt        legacy"
Say "  Netzwerk        AUS               (ungepatchtes NT5 gehoert nicht ins Netz)"
Say "  USB / Audio     AUS"
Say "  Seriell         0x3F8 IRQ4 -> \\.\$HostCom  (Host Device)"

if (-not $PSCmdlet.ShouldProcess($VMName, 'VirtualBox-VM anlegen')) {
    Write-Host ''
    Say 'Nur Vorschau (-WhatIf). Es wurde nichts angelegt.' Yellow
    return
}

# ------------------------------------------------------------ 6. Anlegen
Head 'ANLEGEN'

& $vbox createvm --name $VMName --ostype $OsType --register --basefolder $BaseDir | Out-Null
Say 'VM registriert' Green

# Zwei Aufrufe: faellt einer wegen Versionsunterschieden, ist der Rest gesetzt.
& $vbox modifyvm $VMName `
    --chipset piix3 --firmware bios `
    --cpus 1 --memory $MemoryMB --vram 32 `
    --graphicscontroller vboxvga --accelerate3d off `
    --ioapic off --acpi on --pae off `
    --paravirtprovider legacy `
    --nic1 none --usb off --usbehci off --usbxhci off `
    --rtcuseutc off --mouse ps2 --keyboard ps2 | Out-Null
Say 'Grundeinstellungen gesetzt' Green

# Audio: VirtualBox 7 hat --audio durch --audio-driver ersetzt.
try   { & $vbox modifyvm $VMName --audio-driver none 2>&1 | Out-Null }
catch { & $vbox modifyvm $VMName --audio none        2>&1 | Out-Null }
Say 'Audio deaktiviert' Green

# Serieller Port: DAS ist der eigentliche Zweck der ganzen Uebung.
# \\.\COM1 ist die von Microsoft dokumentierte Form und gilt fuer jede
# Portnummer, nicht erst ab COM10.
& $vbox modifyvm $VMName --uart1 0x3F8 4 --uartmode1 "\\.\$HostCom" | Out-Null
Say "Serieller Port durchgereicht: 0x3F8 IRQ4 -> \\.\$HostCom" Green

& $vbox createmedium disk --filename $vdi --size $DiskMB --format VDI | Out-Null
& $vbox storagectl $VMName --name 'IDE' --add ide --controller PIIX4 --bootable on | Out-Null
& $vbox storageattach $VMName --storagectl 'IDE' --port 0 --device 0 --type hdd --medium $vdi | Out-Null
& $vbox storageattach $VMName --storagectl 'IDE' --port 1 --device 0 --type dvddrive --medium $IsoPath | Out-Null
Say 'Platte und ISO angehaengt' Green

& $vbox modifyvm $VMName --boot1 dvd --boot2 disk --boot3 none --boot4 none | Out-Null
Say 'Bootreihenfolge: DVD, dann Platte' Green

# -------------------------------------------------------------- 7. Fertig
Head 'FERTIG'
Say 'Starten:' Cyan
Say "  & '$vbox' startvm '$VMName'" White
Write-Host ''
Say 'Danach in dieser Reihenfolge:' Cyan
Say '  1. Gast installieren.'
Say '  2. SOFORT Snapshot ziehen:'
Say "     & '$vbox' snapshot '$VMName' take 'frisch-installiert'" White
Say '  3. Im Gast Test-COM1.ps1-Aequivalent fahren (HyperTerminal genuegt):'
Say '     Port oeffnen, Loopback mit Bruecke Pin 2<->3 pruefen.'
Say '  4. Erst wenn seriell sauber laeuft, die ESU-Software installieren.'
Write-Host ''
Say 'WICHTIG - IO-APIC und ACPI nach der Installation NIE mehr aendern.' Yellow
Say 'NT5 waehlt die HAL beim Setup anhand dieser Werte. Spaeteres' Yellow
Say 'Umstellen endet im Bluescreen.' Yellow
Write-Host ''
Say 'Beim Decoder: ERST auslesen, DANN schreiben - und zum Testen einen' Yellow
Say 'entbehrlichen Decoder nehmen. Ein Abbruch mitten im Schreibvorgang' Yellow
Say 'kann ihn in einen inkonsistenten Zustand bringen.' Yellow
Write-Host ''
