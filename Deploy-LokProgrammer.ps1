<#
    Deploy-LokProgrammer.ps1

    Bringt die ESU-Altsoftware auf Windows 10 x64 - mit dem einen Trick,
    der beide Hauptprobleme zugleich loest:

        Der Installer wird NICHT ausgefuehrt, sondern ENTPACKT.

    Warum das der richtige Weg ist:
    1) 16-Bit-Problem. Installer von 2002 haben oft einen 16-Bit-Stub.
       Auf 64-Bit-Windows gibt es kein NTVDM - so ein Stub kann gar nicht
       starten ("Diese App kann auf dem PC nicht ausgefuehrt werden").
       Die eigentliche ANWENDUNG ist aber meist 32-Bit und laeuft.
    2) Sicherheitsproblem. Entpacken fuehrt keinen Code aus. Der
       Malware-Verdacht wird damit weitgehend gegenstandslos.

    Das Skript laedt nur nach ausdruecklicher Bestaetigung.

    Aufruf:
      .\Deploy-LokProgrammer.ps1                    # kompletter Ablauf
      .\Deploy-LokProgrammer.ps1 -SkipDownload      # Datei liegt schon da
      .\Deploy-LokProgrammer.ps1 -WhatIf            # nur zeigen
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Bewusst NICHT unter Program Files: Programme von 2002 schreiben in
    # ihr eigenes Verzeichnis. Unter Program Files greift dann die
    # UAC-Virtualisierung und die Einstellungen landen woanders.
    [string]$InstallDir = 'C:\LokProgrammer',
    [string]$WorkDir    = "$env:USERPROFILE\Downloads\LokProgrammer-Deploy",
    [switch]$SkipDownload
)

$ErrorActionPreference = 'Stop'

# Die einzige vom Hersteller ableitbare Sollgroesse. ESU veroeffentlicht
# KEINE Pruefsummen - mehr als das gibt es nicht zum Abgleichen.
$EXPECTED_BYTES = 1944064
$DL_URL = 'https://www.esu.eu/download/software/fruehere-produkte/?no_cache=1&tx_esudownloads_pi1%5BdownloadItem%5D=a7726bd70d8ab97ca0007cc26f4cfa1f'
$DL_NAME = '50450_LoPro_V151.exe'

function Head($t) {
    Write-Host ''; Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}
function Say($t, $c = 'Gray') { Write-Host "  $t" -ForegroundColor $c }

# ===================================================== PE-Klassifizierung
function Get-Bitness([string]$path) {
    try {
        $fs = [IO.File]::OpenRead($path); $br = New-Object IO.BinaryReader($fs)
        try {
            if ($br.ReadUInt16() -ne 0x5A4D) { return 'kein MZ' }
            $fs.Position = 0x3C
            $off = $br.ReadInt32()
            if ($off -le 0 -or $off -gt ($fs.Length - 6)) { return 'DOS-Stub' }
            $fs.Position = $off
            $sig = -join ($br.ReadBytes(2) | ForEach-Object { [char]$_ })
            if ($sig -eq 'NE') { return '16-Bit (NE)' }
            if ($sig -ne 'PE') { return "unbekannt ($sig)" }
            $null = $br.ReadBytes(2)
            switch ($br.ReadUInt16()) {
                0x014c { return '32-Bit' }
                0x8664 { return '64-Bit' }
                default { return 'sonstige' }
            }
        } finally { $br.Close(); $fs.Close() }
    } catch { return "Fehler: $($_.Exception.Message)" }
}

Head 'LOKPROGRAMMER - DEPLOYMENT AUF WINDOWS 10 x64'
Say "Arbeitsordner : $WorkDir"
Say "Zielordner    : $InstallDir"
Say ''
Say 'Der Installer wird NICHT ausgefuehrt, sondern entpackt.' Green

$null = New-Item -ItemType Directory -Path $WorkDir -Force
$archive = Join-Path $WorkDir $DL_NAME

# ============================================================ 1. Download
Head '1. DATEI BESCHAFFEN'
if ($SkipDownload -or (Test-Path $archive)) {
    if (Test-Path $archive) { Say "Datei ist bereits da: $archive" Green }
    else { Say 'Download uebersprungen, aber Datei fehlt. Abbruch.' Red; return }
} else {
    Say "Quelle : esu.eu (HTTPS, direkt vom Hersteller)"
    Say "Datei  : $DL_NAME"
    Say "Groesse: ca. 1,85 MB (erwartet exakt $('{0:N0}' -f $EXPECTED_BYTES) Bytes)"
    Say ''
    if (-not $PSCmdlet.ShouldProcess($DL_NAME, 'Von esu.eu herunterladen')) {
        Say 'Abgebrochen - nichts geladen.' Yellow; return
    }
    $ok = Read-Host '  Herunterladen? (j/n)'
    if ($ok -notmatch '^[jJyY]') { Say 'Abgebrochen.' Yellow; return }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DL_URL -OutFile $archive -UseBasicParsing -UserAgent 'Mozilla/5.0'
    Say 'Geladen.' Green
}

$fi = Get-Item $archive
$sha = (Get-FileHash $archive -Algorithm SHA256).Hash
Say "Groesse : $('{0:N0}' -f $fi.Length) Bytes" $(if ($fi.Length -eq $EXPECTED_BYTES) { 'Green' } else { 'Yellow' })
if ($fi.Length -ne $EXPECTED_BYTES) {
    Say "ABWEICHUNG von der erwarteten Groesse ($('{0:N0}' -f $EXPECTED_BYTES))." Yellow
    Say 'Das muss nichts heissen - ESU kann die Datei ersetzt haben.' DarkGray
}
Say "SHA256  : $sha" White
Say ''
Say 'ESU veroeffentlicht KEINE Pruefsummen. Es gibt nichts, wogegen sich' DarkGray
Say 'dieser Hash abgleichen liesse. Halte ihn als EIGENE Baseline fest,' DarkGray
Say 'um spaetere Veraenderungen zu bemerken. Zweitmeinung:' DarkGray
Say "  https://www.virustotal.com/gui/file/$sha" White

Say ''
Say "Installer-Architektur: $(Get-Bitness $archive)" Cyan

# ========================================================== 2. Entpacker
Head '2. ENTPACKER BEREITSTELLEN'
$sevenZip = @(
    "$env:ProgramFiles\7-Zip\7z.exe",
    "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $sevenZip) {
    Say '7-Zip fehlt. Es kennt die meisten Installerformate von 2002.' Yellow
    if ($PSCmdlet.ShouldProcess('7-Zip', 'Per winget installieren')) {
        $a = Read-Host '  7-Zip jetzt per winget installieren? (j/n)'
        if ($a -match '^[jJyY]') {
            winget install --id 7zip.7zip --accept-package-agreements --accept-source-agreements --silent
            $sevenZip = @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe") |
                        Where-Object { Test-Path $_ } | Select-Object -First 1
        }
    }
}

$winrar = @(
    "$env:ProgramFiles\WinRAR\WinRAR.exe",
    "${env:ProgramFiles(x86)}\WinRAR\WinRAR.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($sevenZip) { Say "7-Zip  : $sevenZip" Green }
if ($winrar)   { Say "WinRAR : $winrar (Rueckfallebene)" Green }
if (-not $sevenZip -and -not $winrar) { Say 'Kein Entpacker verfuegbar. Abbruch.' Red; return }

# ========================================================== 3. Entpacken
Head '3. ENTPACKEN (kein Code wird ausgefuehrt)'
$extractDir = Join-Path $WorkDir 'extracted'
Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $extractDir -Force

$extracted = $false
if ($sevenZip) {
    Say 'Versuch 1: 7-Zip ...' DarkGray
    & $sevenZip x $archive "-o$extractDir" -y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -and (Get-ChildItem $extractDir -Recurse -File).Count -gt 0) {
        $extracted = $true; Say '7-Zip hat entpackt.' Green
    } else { Say "7-Zip: Exitcode $LASTEXITCODE" Yellow }
}
if (-not $extracted -and $winrar) {
    Say 'Versuch 2: WinRAR ...' DarkGray
    & $winrar x -ibck -y $archive "$extractDir\" 2>&1 | Out-Null
    if ((Get-ChildItem $extractDir -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0) {
        $extracted = $true; Say 'WinRAR hat entpackt.' Green
    }
}

if (-not $extracted) {
    Say ''
    Say 'Entpacken fehlgeschlagen.' Red
    Say 'Vermutlich ein InstallShield-Paket. Optionen, beste zuerst:' Yellow
    Say ''
    Say '  a) 7-Zip als PE-Container oeffnen und das Overlay freilegen:' White
    if ($sevenZip) { Say "     & '$sevenZip' x -tpe `"$archive`" -o`"$WorkDir\pe`" -y" White }
    Say '  b) unshield / i6comp direkt auf data1.cab ansetzen, falls eines'
    Say '     auftaucht. 7-Zip kann InstallShields "ISc("-Kabinette NICHT lesen.'
    Say '  c) Universal Extractor 2 (buendelt ein aelteres 7-Zip fuer NSIS).'
    Say '  d) In einer VM oder Windows Sandbox regulaer installieren und den'
    Say '     fertigen Programmordner herauskopieren.'
    Say ''
    Say 'NICHT empfohlen: "setup.exe /a" ist KEIN Extraktionsschalter fuer' DarkGray
    Say 'InstallShield-InstallScript von 2002 - /a gehoert zum Windows' DarkGray
    Say 'Installer. Bei so einem Setup startet es einfach den Installer.' DarkGray
    return
}

# =================================================== 4. Inhalt bewerten
Head '4. WAS IST DRIN?'
$bins = Get-ChildItem $extractDir -Recurse -File -Include *.exe, *.dll, *.ocx -ErrorAction SilentlyContinue
if (-not $bins) {
    Say 'Keine ausfuehrbaren Dateien gefunden.' Yellow
    Get-ChildItem $extractDir -Recurse -File | Select-Object -First 20 |
        ForEach-Object { Say "  $($_.FullName.Replace($extractDir,''))" }
    return
}

$report = foreach ($b in $bins) {
    [pscustomobject]@{
        Datei    = $b.FullName.Replace("$extractDir\", '')
        Groesse  = $b.Length
        Bitness  = Get-Bitness $b.FullName
    }
}
$report | Sort-Object Groesse -Descending | Format-Table -AutoSize | Out-String | Write-Host

$has16 = $report | Where-Object { $_.Bitness -like '16-Bit*' }
$has32 = $report | Where-Object { $_.Bitness -eq '32-Bit' }

if ($has32) {
    Say "32-Bit-Binaries gefunden: $($has32.Count) - die laufen auf Win10 x64." Green
}
if ($has16) {
    Say "16-Bit-Binaries gefunden: $($has16.Count) - die laufen NICHT auf x64:" Red
    $has16 | ForEach-Object { Say "   $($_.Datei)" Red }
    Say 'Ein NE-Uninstaller (_ISDEL.EXE o.ae.) ist harmlos.' DarkGray
    Say 'Ist die HAUPTanwendung dabei, hilft nur die Windows-2000-VM.' Red
}

# --------------------------------------------- Abhaengigkeiten pruefen
# Das hier entscheidet haeufiger ueber Erfolg als die Bitness.
Head '4b. ABHAENGIGKEITEN - die eigentlichen Stolpersteine'

$drivers = Get-ChildItem $extractDir -Recurse -File -Include *.vxd, *.sys -ErrorAction SilentlyContinue
if ($drivers) {
    Say 'TREIBER GEFUNDEN - das ist ein K.-o.-Kriterium:' Red
    $drivers | ForEach-Object { Say "   $($_.Name)" Red }
    Say 'Die Software greift vermutlich direkt auf I/O-Ports zu. Das geht' Red
    Say 'auf 64-Bit-Windows nicht. Nur die VM loest das.' Red
} else { Say 'Keine .vxd/.sys - kein direkter Port-Zugriff erkennbar.' Green }

$vbx = Get-ChildItem $extractDir -Recurse -File -Include *.vbx -ErrorAction SilentlyContinue
if ($vbx) {
    Say 'VBX GEFUNDEN - VBX ist per Definition 16 Bit:' Red
    $vbx | ForEach-Object { Say "   $($_.Name)" Red }
}

$ocx = Get-ChildItem $extractDir -Recurse -File -Include *.ocx -ErrorAction SilentlyContinue
if ($ocx) {
    Say 'ActiveX-Controls gefunden:' Yellow
    $ocx | ForEach-Object { Say "   $($_.Name)" Yellow }
    if ($ocx.Name -match 'MSCOMM') {
        Say ''
        Say 'ACHTUNG: MSCOMM32.OCX ist das VB6-Control fuer serielle Ports.' Red
        Say 'Es braucht regsvr32 UND einen Lizenzschluessel unter' Red
        Say 'HKCR\Licenses, den nur der ECHTE Installer schreibt.' Red
        Say 'Ohne ihn bricht die App beim Oeffnen von COM1 ab mit' Red
        Say '"Lizenzinformation fuer diese Komponente nicht gefunden".' Red
        Say ''
        Say 'In dem Fall ist reines Entpacken gescheitert - dann bleibt' Yellow
        Say 'nur, in einer VM/Sandbox regulaer zu installieren.' Yellow
    } else {
        Say 'Registrieren nicht vergessen (64-Bit-Windows, 32-Bit-OCX):' DarkGray
        Say '  C:\Windows\SysWOW64\regsvr32.exe <pfad zur .ocx>' White
    }
}

$hlp = Get-ChildItem $extractDir -Recurse -File -Include *.hlp -ErrorAction SilentlyContinue
if ($hlp) {
    Say 'Alte .hlp-Hilfedateien gefunden - winhlp32 ist auf Win10 nur noch' Yellow
    Say 'ein Stub. Die Hilfe laesst sich nicht oeffnen. Betrifft nur die' Yellow
    Say 'Hilfe, nicht die Funktion des Programms.' Yellow
}

# Kernruntimes der 2002-Aera sind auf diesem Host bereits vorhanden
# (msvbvm60.dll, mfc42.dll 6.06 SP6, msvcrt, msvcp60) - da ist nichts
# nachzuinstallieren. Fehlende OCX muessen aus der Installer-Payload
# kommen, NIEMALS von DLL-Download-Seiten.
foreach ($rt in 'msvbvm60.dll', 'mfc42.dll', 'msvcrt.dll') {
    $p = Join-Path $env:WINDIR "SysWOW64\$rt"
    Say "Runtime $rt : $(if (Test-Path $p) { 'vorhanden' } else { 'FEHLT' })" $(if (Test-Path $p) { 'Green' } else { 'Yellow' })
}

$msi = Get-ChildItem $extractDir -Recurse -File -Include *.msi -ErrorAction SilentlyContinue
if ($msi) {
    Say ''
    Say 'MSI gefunden. Payload ohne Custom Actions entpacken mit:' Cyan
    $msi | ForEach-Object {
        Say "  msiexec /a `"$($_.FullName)`" /qn TARGETDIR=`"$WorkDir\msi-payload`"" White
    }
}

# ====================================================== 5. Bereitstellen
Head '5. BEREITSTELLEN'
if (-not $has32) {
    Say 'Keine 32-Bit-Anwendung vorhanden - Bereitstellung uebersprungen.' Yellow
    Say 'Weiter mit der VM: vm\New-LegacyVM.ps1' Yellow
    return
}

if ($PSCmdlet.ShouldProcess($InstallDir, 'Entpackte Anwendung kopieren')) {
    $null = New-Item -ItemType Directory -Path $InstallDir -Force
    Copy-Item "$extractDir\*" $InstallDir -Recurse -Force
    Say "Kopiert nach $InstallDir" Green
    Say 'Bewusst NICHT unter Program Files - sonst greift die' DarkGray
    Say 'UAC-Virtualisierung bei einem Programm, das in sein eigenes' DarkGray
    Say 'Verzeichnis schreibt.' DarkGray

    # Kompatibilitaets-Layer pro EXE setzen (HKCU, wirkt ohne Adminrechte)
    $layerKey = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
    # NIEMALS New-Item -Force auf diesen Key: Bei einem EXISTIERENDEN
    # Registry-Key legt -Force ihn neu an und LOESCHT dabei alle Werte -
    # also die Kompatibilitaetseinstellungen aller anderen Programme.
    # Nur anlegen, wenn er wirklich fehlt.
    if (-not (Test-Path $layerKey)) {
        $null = New-Item -Path $layerKey -Force
        Say 'Layers-Key neu angelegt (war nicht vorhanden).' DarkGray
    }
    # Sicherheitsnetz: bestehende Werte vorher wegsichern.
    $backup = Join-Path $WorkDir 'AppCompatFlags-Layers-backup.reg'
    & reg.exe export 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' $backup /y 2>&1 | Out-Null
    if (Test-Path $backup) { Say "Registry-Sicherung: $backup" DarkGray }
    foreach ($e in Get-ChildItem $InstallDir -Recurse -Filter *.exe) {
        # WINXPSP3: Einen Windows-2000-Modus gibt es unter Win10 NICHT.
        #   XP SP3 ist der naechstliegende NT-5.x-Layer. WIN98 waere falsch -
        #   es meldet Version 4.10 und aktiviert Win9x-Shims, die eine
        #   NT-Anwendung eher stoeren.
        # DPIUNAWARE: Laesst Windows die Oberflaeche hochskalieren. Ohne das
        #   wird eine 2002-App auf einem HiDPI-Schirm winzig.
        # BEWUSST KEIN RUNASADMIN: Es schaltet die UAC-Virtualisierung ab -
        #   also genau das Sicherheitsnetz, das Schreibzugriffe auffaengt -
        #   erzeugt bei jedem Start einen UAC-Prompt und blockiert per UIPI
        #   Drag&Drop aus dem Explorer. Da wir ohnehin nach C:\LokProgrammer
        #   installieren und nicht nach Program Files, wird es nicht gebraucht.
        # Set-ItemProperty legt EINEN Wert an und laesst bestehende Eintraege
        # in Ruhe - der Key enthaelt auf diesem Host bereits andere Programme.
        Set-ItemProperty -Path $layerKey -Name $e.FullName -Value '~ WINXPSP3 DPIUNAWARE' -Force
        Say "Kompatibilitaet gesetzt: $($e.Name)  (WinXP SP3, DPI durch Windows)" Green
    }
    Say ''
    Say 'Falls die Oberflaeche unscharf ist: DPIUNAWARE aus dem Wert nehmen.' DarkGray
    Say 'Falls das Programm gar nicht startet: als letzten Versuch WIN98.' DarkGray
}

# =============================================================== 6. Weiter
Head '6. NAECHSTE SCHRITTE'
Say 'Reihenfolge einhalten - die meisten Fehlschlaege sind Bedienfehler:' Cyan
Say ''
Say '  1. Programm starten (noch OHNE Hardware).'
Say '  2. In den Einstellungen ausdruecklich COM1 waehlen.'
Say '  3. LokProgrammer mit 1:1-Kabel anschliessen - KEIN Nullmodemkabel.'
Say '  4. ERST JETZT das Netzteil einstecken. Nicht vorher.'
Say '     Nie Steckernetzteil UND Trafo gleichzeitig - Zerstoerungsgefahr.'
Say '  5. Keine Lok auf dem Programmiergleis beim Verbindungsaufbau.'
Say ''
Say 'Diagnose ueber die gruene LED am Programmer:' Cyan
Say '  dauerhaft  = Spannung liegt an'
Say '  BLINKEND   = er empfaengt Daten vom PC -> serielle Strecke ist ok'
Say '  blinkt nicht -> es kommt nichts an COM1 an. Dann liegt es an'
Say '  Kabel oder Port, NICHT an der Software.'
Say ''
Say 'Port vorher pruefen:  .\tools\Test-COM1.ps1' White
Write-Host ''
