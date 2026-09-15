<#
    Inspect-Installer.ps1
    Statische Analyse verdaechtiger Installer - laeuft INNERHALB der Windows Sandbox.
    Fuehrt den Installer NICHT aus. Rein lesend.
#>

$ErrorActionPreference = 'Continue'
$Host.UI.RawUI.WindowTitle = 'LokProgrammer - Analyse'

function Write-Head($t) {
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
}

function Write-KV($k, $v, $color = 'Gray') {
    Write-Host ('  {0,-22} ' -f ($k + ':')) -NoNewline -ForegroundColor DarkGray
    Write-Host $v -ForegroundColor $color
}

# ------------------------------------------------------------------ Dateisuche
# shared wird rekursiv durchsucht, Downloads und Desktop nur oberflaechlich.
# Kein Recurse auf dem Desktop - dort haengen die Mount-Ordner drin, das
# wuerde sich selbst scannen und dauert unnoetig lange.
$searchDirs = [ordered]@{
    "$env:USERPROFILE\Desktop\shared" = $true
    "$env:USERPROFILE\Downloads"      = $false
    "$env:USERPROFILE\Desktop"        = $false
}

$files = @()
foreach ($d in $searchDirs.Keys) {
    if (-not (Test-Path $d)) { continue }
    $files += Get-ChildItem -Path $d -File -Recurse:$searchDirs[$d] -ErrorAction SilentlyContinue |
              Where-Object { $_.Extension -match '^\.(exe|zip|msi|cab|rar|7z)$' }
}
$files = $files | Sort-Object FullName -Unique

Write-Head 'LOKPROGRAMMER INSTALLER - STATISCHE ANALYSE'
Write-Host "  Sandbox-Benutzer : $env:USERNAME"
Write-Host "  Durchsuchte Pfade: $(($searchDirs.Keys) -join '  |  ')"

if (-not $files) {
    Write-Host ''
    Write-Host '  Keine Kandidaten gefunden.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Variante A: Datei auf dem HOST in den Ordner "shared" legen,' -ForegroundColor Gray
    Write-Host '              Sandbox schliessen und neu starten.' -ForegroundColor Gray
    Write-Host '  Variante B: Hier IN der Sandbox laden (nur bei aktivem Netzwerk):' -ForegroundColor Gray
    Write-Host '              powershell -File $env:USERPROFILE\Desktop\tools\Get-LokProgrammer.ps1' -ForegroundColor White
    Write-Host ''
    Write-Host '  Danach erneut starten:' -ForegroundColor Gray
    Write-Host '              powershell -File $env:USERPROFILE\Desktop\tools\Inspect-Installer.ps1' -ForegroundColor White
    Write-Host ''
    return
}

# ------------------------------------------------------------------ PE-Analyse
function Get-BinaryFacts([string]$path) {
    $r = [ordered]@{
        Magic = 'unbekannt'; Format = 'unbekannt'; Bitness = 'unbekannt'
        Subsystem = 'unbekannt'; LinkerStamp = $null; Packer = @(); HasZip = $false
    }
    try {
        $fs = [System.IO.File]::OpenRead($path)
        $br = New-Object System.IO.BinaryReader($fs)

        # 8 Byte Magic lesen - deckt auch Container ab, die keine PE-Dateien sind
        $m = $br.ReadBytes(8)
        $fs.Position = 0
        $r.Magic = ('{0:X2} {1:X2} {2:X2} {3:X2}' -f $m[0], $m[1], $m[2], $m[3])

        $hex = ($m | ForEach-Object { '{0:X2}' -f $_ }) -join ''
        $container = switch -Regex ($hex) {
            '^D0CF11E0A1B11AE1' { 'OLE Compound File (MSI / Installer-Datenbank)'; break }
            '^4D534346'         { 'MSCF - Microsoft Cabinet (.cab)'; break }
            '^504B0304'         { 'ZIP-Archiv'; break }
            '^526172211A07'     { 'RAR-Archiv'; break }
            '^377ABCAF271C'     { '7z-Archiv'; break }
            default             { $null }
        }
        if ($container) {
            $r.Format  = $container
            $r.Bitness = 'entfaellt - kein ausfuehrbares Binary'
            if ($hex -like '504B0304*') { $r.HasZip = $true }
            $br.Close(); $fs.Close(); return $r
        }

        if ($m[0] -ne 0x4D -or $m[1] -ne 0x5A) {
            $r.Format = "Kein bekanntes Format (Magic $($r.Magic))"
            $br.Close(); $fs.Close(); return $r
        }
        $null = $br.ReadBytes(2)

        $fs.Position = 0x3C
        $peOff = $br.ReadInt32()
        if ($peOff -le 0 -or $peOff -gt ($fs.Length - 6)) {
            $r.Format = 'MZ - reine DOS-/Stub-Datei'
            $br.Close(); $fs.Close(); return $r
        }

        $fs.Position = $peOff
        $sigS = -join ($br.ReadBytes(2) | ForEach-Object { [char]$_ })

        if ($sigS -eq 'NE') {
            $r.Format = 'NE - 16-Bit Windows (Win 3.x / Win9x-Aera)'
            $r.Bitness = '16 Bit'
            $br.Close(); $fs.Close(); return $r
        }
        if ($sigS -ne 'PE') {
            $r.Format = "Unbekannte Signatur '$sigS'"
            $br.Close(); $fs.Close(); return $r
        }

        $r.Format = 'PE - Windows Executable'
        $null = $br.ReadBytes(2)
        $machine = $br.ReadUInt16()
        $null = $br.ReadUInt16()
        $stamp = $br.ReadUInt32()
        if ($stamp -gt 0 -and $stamp -lt 4000000000) {
            $r.LinkerStamp = ([datetimeoffset]::FromUnixTimeSeconds($stamp)).UtcDateTime
        }

        $r.Bitness = switch ($machine) {
            0x014c { '32 Bit (i386)' }
            0x8664 { '64 Bit (x64)' }
            0x01c0 { 'ARM' }
            0xaa64 { 'ARM64' }
            default { '{0} (0x{1:x4})' -f 'unbekannt', $machine }
        }

        # COFF-Header ab hier: PointerToSymbolTable(4), NumberOfSymbols(4),
        # SizeOfOptionalHeader(2), Characteristics(2).
        $null = $br.ReadUInt32()          # PointerToSymbolTable
        $null = $br.ReadUInt32()          # NumberOfSymbols
        $optSize = $br.ReadUInt16()       # SizeOfOptionalHeader
        $null = $br.ReadUInt16()          # Characteristics
        # Subsystem liegt bei Offset 68 im Optional Header - identisch fuer
        # PE32 und PE32+ (BaseOfData faellt weg, dafuer ImageBase 8 statt 4 Byte).
        # Fuer das Feld werden 70 Byte Optional Header gebraucht.
        if ($optSize -ge 70) {
            $optStart = $fs.Position
            $fs.Position = $optStart + 68
            $sub = $br.ReadUInt16()
            $r.Subsystem = switch ($sub) { 2 { 'GUI' } 3 { 'Konsole' } default { "Typ $sub" } }
        }
        $br.Close(); $fs.Close()
    } catch {
        # Ohne dieses Aufraeumen bleibt die Datei gesperrt und die Handles
        # lecken ueber die Schleife ab.
        if ($br) { try { $br.Close() } catch { } }
        if ($fs) { try { $fs.Close() } catch { } }
        $r.Format = "Lesefehler: $($_.Exception.Message)"
        return $r
    }

    # Packer- / SFX-Signaturen
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        $markers = [ordered]@{
            'WinZip'        = 'WinZip Self-Extractor'
            'PKSFX'         = 'PKZIP SFX'
            'Nullsoft'      = 'NSIS'
            'Inno Setup'    = 'Inno Setup'
            'InstallShield' = 'InstallShield'
            'WiseMain'      = 'Wise Installer'
            '7-Zip'         = '7-Zip SFX'
            'SFXRAR'        = 'WinRAR SFX'
        }
        foreach ($k in $markers.Keys) { if ($ascii.Contains($k)) { $r.Packer += $markers[$k] } }

        # Native String-Suche statt byteweiser Schleife. Die Schleife brauchte
        # gemessen ~3,4 s pro 1,85-MB-Datei, das wirkt wie ein Haenger.
        # Latin1 bildet jedes Byte 1:1 auf ein Zeichen ab, daher verlustfrei.
        $latin = [System.Text.Encoding]::GetEncoding(28591).GetString($bytes)
        $r.HasZip = $latin.IndexOf("PK`u{0003}`u{0004}", 2) -ge 0
    } catch { }

    return $r
}

# ------------------------------------------------------------------ Auswertung
foreach ($f in $files) {
    Write-Head $f.Name
    Write-KV 'Pfad'          $f.FullName
    Write-KV 'Groesse'       ('{0:N0} Bytes  ({1:N2} MB)' -f $f.Length, ($f.Length / 1MB))
    Write-KV 'Dateidatum'    $f.LastWriteTime

    $sha = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
    Write-KV 'SHA256' $sha White
    Write-KV 'MD5'    (Get-FileHash $f.FullName -Algorithm MD5).Hash

    $sig = Get-AuthenticodeSignature $f.FullName
    $sigColor = switch ($sig.Status) { 'Valid' { 'Green' } 'NotSigned' { 'Yellow' } default { 'Red' } }
    Write-KV 'Signatur-Status' $sig.Status $sigColor
    if ($sig.SignerCertificate) {
        Write-KV 'Herausgeber' $sig.SignerCertificate.Subject
        Write-KV 'Zert. gueltig bis' $sig.SignerCertificate.NotAfter
    } else {
        Write-KV 'Herausgeber' 'KEINER - unsigniert' Yellow
    }

    $b = Get-BinaryFacts $f.FullName
    if ($b) {
        Write-KV 'Format'      $b.Format
        Write-KV 'Architektur' $b.Bitness $(if ($b.Bitness -like '16*') { 'Red' } else { 'Gray' })
        if ($b.Subsystem -ne 'unbekannt') { Write-KV 'Subsystem' $b.Subsystem }
        if ($b.LinkerStamp) {
            # Bei Altsoftware ist das ein echtes Builddatum und damit ein guter
            # Plausibilitaetstest: die ESU-Datei MUSS hier 2001/2002 zeigen.
            # Moderne MS-Binaries tragen dort einen Build-Hash - Datum sinnlos.
            $plaus = if ($b.LinkerStamp.Year -ge 1995 -and $b.LinkerStamp.Year -le 2010) {
                'Green'
            } elseif ($b.LinkerStamp -gt (Get-Date)) {
                'DarkGray'
            } else { 'Yellow' }
            Write-KV 'Linker-Zeitstempel' $b.LinkerStamp $plaus
            if ($b.LinkerStamp -gt (Get-Date)) {
                Write-Host '                         (in der Zukunft - Reproducible Build, kein echtes Datum)' -ForegroundColor DarkGray
            }
        }
        if ($b.Packer.Count) { Write-KV 'Packer erkannt' ($b.Packer -join ', ') Yellow }
        # Nur bei einer PE-Datei ist eingebettetes ZIP ein SFX-Hinweis.
        # Ein reines .zip ist selbstverstaendlich ein Archiv, kein Selbstentpacker.
        if ($b.HasZip -and $b.Format -like 'PE*') {
            Write-KV 'Enthaelt ZIP-Daten' 'ja - selbstentpackendes Archiv (SFX)' Yellow
        }

        if ($b.Bitness -like '16*') {
            Write-Host ''
            Write-Host '  ACHTUNG: 16-Bit-Binary. Laeuft auf 64-Bit-Windows NICHT -' -ForegroundColor Red
            Write-Host '  auch nicht in dieser Sandbox. Dafuer braucht es eine'      -ForegroundColor Red
            Write-Host '  32-Bit-VM (Windows 2000 / XP).'                            -ForegroundColor Red
        }
    }

    Write-Host ''
    # Laeuft Defender nur passiv (weil ein Drittscanner die Fuehrung hat),
    # ist ein "SAUBER" von MpCmdRun wertlos. In der Sandbox ist Defender
    # aktiv - auf einem Host mit Avira/Kaspersky/etc. aber nicht.
    $passive = $false
    try { $passive = ((Get-MpComputerStatus -ErrorAction Stop).AMRunningMode -match 'Passive|SxS') } catch { }
    if ($passive) {
        Write-KV 'Defender' 'PASSIVMODUS - Scan waere aussagelos' Yellow
        Write-Host '      Ein Drittanbieter-Scanner fuehrt hier. Pruefe dessen' -ForegroundColor DarkGray
        Write-Host '      Quarantaene, nicht den Defender-Verlauf.' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  VirusTotal (Hash-Abfrage, kein Upload):' -ForegroundColor DarkGray
        Write-Host "  https://www.virustotal.com/gui/file/$sha" -ForegroundColor White
        continue
    }
    Write-Host '  Defender-Scan laeuft ...' -ForegroundColor DarkGray
    $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path $mp) {
        $out = & $mp -Scan -ScanType 3 -File $f.FullName -DisableRemediation 2>&1 | Out-String
        # Exitcode auswerten, NICHT den Text. In der Sandbox ist der Defender-
        # Dienst oft inaktiv - ein Scanfehler darf nicht als Fund erscheinen.
        # 0 = sauber, 2 = Bedrohung gefunden, alles andere = Scan misslungen.
        switch ($LASTEXITCODE) {
            0 { Write-KV 'Defender' 'SAUBER - keine Bedrohung gefunden' Green }
            2 {
                Write-KV 'Defender' 'TREFFER - Details unten' Red
                Write-Host ($out.Trim() -replace '(?m)^', '      ') -ForegroundColor Red
            }
            default {
                Write-KV 'Defender' "Scan nicht moeglich (Exitcode $LASTEXITCODE) - KEIN Fund!" Yellow
                Write-Host '      Meist ist der Defender-Dienst in der Sandbox inaktiv.' -ForegroundColor DarkGray
                Write-Host '      Das ist KEINE Aussage ueber die Datei. VirusTotal nutzen.' -ForegroundColor DarkGray
            }
        }
    } else {
        Write-KV 'Defender' 'MpCmdRun.exe nicht gefunden' Yellow
    }

    Write-Host ''
    Write-Host '  VirusTotal (Hash-Abfrage, kein Upload):' -ForegroundColor DarkGray
    Write-Host "  https://www.virustotal.com/gui/file/$sha" -ForegroundColor White
}

Write-Head 'FERTIG'
Write-Host '  Es wurde NICHTS ausgefuehrt - rein lesende Analyse.' -ForegroundColor Green
Write-Host ''
Write-Host '  Naechste Schritte:' -ForegroundColor Cyan
Write-Host '   1. SHA256 oben kopieren, bei VirusTotal pruefen.'
Write-Host '   2. Nur wenn unbedenklich: Installer HIER in der Sandbox starten.'
Write-Host '      Vorher besser Netzwerk abschalten  ->  Sandbox-Isoliert.wsb'
Write-Host '   3. Beim Schliessen der Sandbox wird alles restlos verworfen.'
Write-Host ''
