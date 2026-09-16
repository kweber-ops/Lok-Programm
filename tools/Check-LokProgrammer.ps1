<#
    Check-LokProgrammer.ps1

    Eigenstaendiges Pruefskript fuer den Fall, dass ein Virenscanner die
    ESU-LokProgrammer-Software als Schadsoftware meldet.

    Beantwortet drei Fragen auf einmal:
      1. Ist die Datei echt? (Abgleich gegen eine Referenz von 2006)
      2. Was genau hat der Scanner gemeldet?
      3. Ist das ein Fehlalarm - und was tut man dann?

    Braucht NICHTS ausser Windows PowerShell. Nichts wird installiert,
    nichts veraendert, die Datei wird nicht ausgefuehrt.

    Aufruf:
      .\Check-LokProgrammer.ps1
      .\Check-LokProgrammer.ps1 -File "C:\Pfad\zur\Datei.exe"
#>

[CmdletBinding()]
param(
    [string]$File
)

$ErrorActionPreference = 'Continue'

# Sollwerte. Der SHA1 stammt aus dem CDX-Index des Internet Archive fuer
# loksound.de/download/software/50450_LoPro_V151.exe, Captures vom
# 16.01.2006, 17.01.2006 und 24.02.2006. Also eine Referenz, die weder
# von uns noch von ESU stammt.
$REF_BYTES  = 1944064
$REF_SHA1   = '8F0745D21BC0A4296BF6B527EC39009AD0E0BEA9'
$REF_SHA256 = 'B1D74B9CFF15FCF6FE2FE0E4A68CCDCB4E0247B64A5A0011F523E1C90C62BA16'

function Head($t) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}
function Say($t, $c = 'Gray') { Write-Host "  $t" -ForegroundColor $c }

Head 'LOKPROGRAMMER V1.51 - PRUEFUNG'

# ------------------------------------------------- Datei finden
if (-not $File) {
    $candidates = @(
        'C:\LokProgrammer\LokProgrammer.exe',
        "$env:USERPROFILE\Downloads\50450_LoPro_V151.exe",
        "$env:USERPROFILE\Downloads\LokProgrammer.exe",
        "$env:USERPROFILE\Desktop\50450_LoPro_V151.exe"
    )
    $File = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $File) {
        $File = Get-ChildItem "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop" -Filter '*LoPro*' -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty FullName
    }
}

# ================================================= 1. IST SIE ECHT?
Head '1. IST DIE DATEI ECHT?'

if (-not $File -or -not (Test-Path $File)) {
    Say 'Datei nicht gefunden.' Yellow
    Say 'Das kann bedeuten, dass der Scanner sie schon in Quarantaene' Yellow
    Say 'verschoben hat. Dann weiter bei Abschnitt 2.' Yellow
    Say ''
    Say 'Sonst Pfad angeben:  .\Check-LokProgrammer.ps1 -File "C:\...\datei.exe"' White
} else {
    $fi   = Get-Item $File
    $sha1 = (Get-FileHash $File -Algorithm SHA1).Hash
    $sha  = (Get-FileHash $File -Algorithm SHA256).Hash

    $okSize = $fi.Length -eq $REF_BYTES
    $okSha1 = $sha1 -eq $REF_SHA1
    $okSha  = $sha  -eq $REF_SHA256

    Say "Datei   : $($fi.FullName)"
    Say "Groesse : $('{0:N0}' -f $fi.Length) Bytes" $(if ($okSize) { 'Green' } else { 'Red' })
    Say "SHA1    : $sha1" $(if ($okSha1) { 'Green' } else { 'Red' })
    Say "SHA256  : $sha"  $(if ($okSha)  { 'Green' } else { 'Red' })
    Write-Host ''

    if ($okSize -and $okSha1 -and $okSha) {
        Say 'ECHT. Bitgenau identisch mit ESUs Auslieferung.' Green
        Say 'Der SHA1 stimmt mit dem Internet-Archive-Digest von 2006 ueberein -' DarkGray
        Say 'einer Referenz, die unabhaengig von ESU und von uns ist.' DarkGray
        Say 'Ein Scannertreffer auf diese Datei ist damit ein FEHLALARM.' Green
    } else {
        Say 'ABWEICHUNG! Diese Datei ist NICHT die gepruefte Originaldatei.' Red
        Say 'Erwartet:' Red
        Say "  Groesse $('{0:N0}' -f $REF_BYTES) Bytes" Red
        Say "  SHA1    $REF_SHA1" Red
        Say ''
        Say 'Nicht ausfuehren. Neu laden von:' Yellow
        Say '  https://www.esu.eu/download/software/fruehere-produkte/' White
        Say 'Niemals aus Archiven, Foren oder Spiegelservern.' Yellow
    }

    # Mark of the Web
    Write-Host ''
    $zone = Get-Content $File -Stream Zone.Identifier -ErrorAction SilentlyContinue
    if ($zone) {
        Say 'Mark of the Web: vorhanden (Datei stammt aus dem Internet)' DarkGray
        Say 'Das allein loest SmartScreen aus - ohne jeden Virenverdacht.' DarkGray
    } else {
        Say 'Mark of the Web: keines' DarkGray
    }
}

# ================================================= 2. WER HAT GEMELDET?
Head '2. WELCHER SCANNER IST AKTIV, UND WAS HAT ER GEMELDET?'

$thirdParty = $null
try {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
        ForEach-Object {
            $rt = ((($_.productState -shr 12) -band 0xF) -ne 0)
            Say "$($_.displayName) - Echtzeitschutz $(if($rt){'AN'}else{'AUS'})" $(if ($rt) { 'Green' } else { 'DarkGray' })
            if ($rt -and $_.displayName -notmatch 'Defender') { $thirdParty = $_.displayName }
        }
} catch { Say "SecurityCenter2 nicht abfragbar: $($_.Exception.Message)" Yellow }

try {
    $mode = (Get-MpComputerStatus -ErrorAction Stop).AMRunningMode
    Say "Defender-Modus: $mode" $(if ($mode -match 'Passive|SxS') { 'Yellow' } else { 'Green' })
} catch { }

if ($thirdParty) {
    Write-Host ''
    Say "Aktiv ist '$thirdParty', NICHT Defender." Yellow
    Say 'Der Fund steht dann in dessen Quarantaene. Die Defender-Abfragen' Yellow
    Say 'unten bleiben leer - das ist KEIN Freispruch.' Yellow
}

Write-Host ''
Say 'Defender-Funde:' Cyan
$found = $false
try {
    # Get-MpThreatDetection liefert den Namen NICHT mit - er muss ueber die
    # ThreatID aus Get-MpThreat nachgeschlagen werden.
    $names = @{}
    Get-MpThreat -ErrorAction Stop | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName }

    $det = Get-MpThreatDetection -ErrorAction SilentlyContinue |
           Sort-Object InitialDetectionTime -Descending | Select-Object -First 10
    if ($det) {
        $found = $true
        foreach ($d in $det) {
            Say "  Zeit       : $($d.InitialDetectionTime)" Red
            Say "  Name       : $($names[[string]$d.ThreatID])" Red
            if ($d.Resources) { $d.Resources | ForEach-Object { Say "  Datei      : $_" } }
            Say "  Aktion ok  : $($d.ActionSuccess)"
            Write-Host ''
        }
    } elseif ($names.Count) {
        $found = $true
        $names.Values | ForEach-Object { Say "  Name: $_" Red }
    } else { Say '  keine Eintraege' Green }
} catch { Say "  nicht abrufbar: $($_.Exception.Message)" Yellow }

# Ereignisprotokoll. Der Kanalname ist sprachunabhaengig.
# Event 1116 traegt die entscheidenden Felder "Detection Type" und
# "Detection Source" - damit laesst sich objektiv belegen, WELCHE Art
# von Treffer es war, statt sie aus dem Namen zu erraten.
try {
    $ev = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1006, 1015, 1116, 1117
    } -MaxEvents 5 -ErrorAction Stop
    if ($ev) {
        $found = $true
        Write-Host ''
        Say 'Ereignisprotokoll (Art des Treffers):' Cyan
        $ev | ForEach-Object {
            Say "  [$($_.TimeCreated)] ID $($_.Id)" Red
            ($_.Message -split "`n" |
             Where-Object { $_ -match 'Detection Type|Erkennungstyp|Detection Source|Erkennungsquelle|Detection Origin|Name:|Pfad:|Path:|Action|Aktion' } |
             Select-Object -First 6) | ForEach-Object { Say "     $($_.Trim())" }
            Write-Host ''
        }
    }
} catch { }

# ASR-Blockade ist KEIN Virenfund. Sie erscheint als eigenes Ereignis und
# traegt gar keinen Bedrohungsnamen - das trennschaerfste Merkmal ueberhaupt.
try {
    $asr = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1121, 1122
    } -MaxEvents 5 -ErrorAction Stop
    if ($asr) {
        $found = $true
        Say 'ASR-REGEL hat blockiert - das ist KEIN Malware-Fund:' Yellow
        $asr | ForEach-Object { Say "  [$($_.TimeCreated)] ID $($_.Id)" Yellow }
        Say '  Eine Attack-Surface-Reduction-Regel bewertet Verbreitung und' DarkGray
        Say '  Alter einer Datei, nicht ihren Inhalt. Kein Bedrohungsname,' DarkGray
        Say '  keine Aussage ueber Schadcode.' DarkGray
        Write-Host ''
    }
} catch { }

# ================================================= 3. WAS TUN?
Head '3. DEUTUNG UND VORGEHEN'

if (-not $found -and -not $thirdParty) {
    Say 'Kein Fund registriert. Wenn trotzdem eine Meldung erschien, war es' Gray
    Say 'wahrscheinlich SmartScreen ("Der Computer wurde durch Windows' Gray
    Say 'geschuetzt") - das ist eine Reputationswarnung, KEIN Virenfund.' Gray
    Say 'Sie laesst sich mit "Weitere Informationen" -> "Trotzdem ausfuehren"' Gray
    Say 'wegklicken.' Gray
} else {
    Say 'VIER Trefferarten - sie bedeuten voellig Verschiedenes:' Cyan
    Say '  1. SIGNATUR    konkreter Familienname OHNE !-Suffix' Red
    Say '                 (Emotet, Zbot, Qakbot). Das waere ernst.' Red
    Say '  2. HEURISTIK   von Menschen geschriebene Regel, lokal.' Yellow
    Say '  3. ML-VERDACHT Endung !ml, !pz oder !MTB. Der Familienname' Yellow
    Say '                 davor ist dann BEDEUTUNGSLOS - ein Score lag' Yellow
    Say '                 ueber der Schwelle, mehr nicht.' Yellow
    Say '                 Typisch: Wacatac, Wacapew, Sabsik, Bearfoos,' Yellow
    Say '                 Presenoker, Zpevdo.' Yellow
    Say '  4. REPUTATION  Block at First Sight, ASR, SmartScreen.' Green
    Say '                 Sagt NICHTS ueber Schadcode aus - nur, dass die' Green
    Say '                 Datei selten und unbekannt ist.' Green
    Write-Host ''
    Say 'Welche Art es war, steht im Ereignisprotokoll oben unter' DarkGray
    Say '"Detection Type" und "Detection Source" - nicht im Namen raten.' DarkGray
    Write-Host ''
    Say 'Passt der Hash oben, ist die Datei nachweislich das Original' Green
    Say 'von 2006 - dann ist der Treffer in JEDEM der vier Faelle ein' Green
    Say 'Fehlalarm.' Green
    Write-Host ''
    Say 'REIHENFOLGE beim Beheben - unbedingt einhalten:' Cyan
    Say '  1. Quarantaene auflisten, um den genauen Namen zu bekommen:' White
    Say '     $plat = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform" -Directory |' White
    Say '             Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1' White
    Say '     $mp = Join-Path $plat.FullName MpCmdRun.exe' White
    Say '     & $mp -Restore -ListAll' White
    Say '  2. ZUERST die Ausnahme setzen (als Administrator, VOLLER Dateipfad):' White
    Say "     Add-MpPreference -ExclusionPath 'C:\LokProgrammer\LokProgrammer.exe'" White
    Say '  3. DANN wiederherstellen:' White
    Say '     & $mp -Restore -Name <Bedrohungsname aus Schritt 1>' White
    Write-Host ''
    Say '  Umgekehrt faengt der Echtzeitschutz die Datei beim Zurueckschreiben' DarkGray
    Say '  sofort wieder ab.' DarkGray
    Write-Host ''
    Say 'Fehlalarm bei Microsoft melden (dauert meist wenige Tage):' Cyan
    Say '  https://www.microsoft.com/en-us/wdsi/filesubmission' White
    Say 'Danach Signaturen aktualisieren und die Ausnahme WIEDER ENTFERNEN:' Cyan
    Say '  Update-MpSignature' White
    Say "  Remove-MpPreference -ExclusionPath 'C:\LokProgrammer\LokProgrammer.exe'" White
    Write-Host ''
    Say 'NICHT tun:' Red
    Say '  - Echtzeitschutz abschalten. Unverhaeltnismaessig fuer eine Datei.' Red
    Say '  - Ganze Ordner ausschliessen (Downloads, Temp, Desktop).' Red
    Say '    Das ist ein bekanntes Angreifermuster.' Red
    Say '  - ExclusionExtension .exe oder ExclusionProcess verwenden.' Red
    Say '    ExclusionProcess schuetzt die Datei NICHT vor Quarantaene -' Red
    Say '    es betrifft nur Dateien, die der Prozess oeffnet.' Red
    Say '  - Umbenennen oder in ein Archiv packen. Erkannt wird der Inhalt.' Red
    Say '  - Die Datei aus einer Drittquelle holen. Das ist die' Red
    Say '    gefaehrlichste Variante - so wird aus einem Fehlalarm ein' Red
    Say '    echter Befall.' Red
    Write-Host ''
    Say 'Oberflaeche direkt oeffnen (sprachunabhaengig):' DarkGray
    Say '  Start-Process windowsdefender://threat' White
}

Write-Host ''
Say 'Zweitmeinung ueber den Hash, ohne Upload:' DarkGray
if ($File -and (Test-Path $File)) {
    Say "  https://www.virustotal.com/gui/file/$((Get-FileHash $File -Algorithm SHA256).Hash)" White
}
Write-Host ''
