<#
    Get-DefenderVerdict.ps1
    Beantwortet die Frage, die am Anfang stand und nie geprueft wurde:
    WAS genau hat Windows eigentlich gemeldet?

    "Windows haelt es fuer Schadsoftware" kann fuenf voellig verschiedene
    Dinge bedeuten - mit voellig verschiedenen Konsequenzen. Dieses Skript
    liest die tatsaechlichen Protokolle aus, statt zu raten.

    Laeuft auf dem HOST. Braucht fuer den vollen Umfang Adminrechte,
    liefert aber auch ohne sie brauchbare Ergebnisse.

    Aufruf:
      .\Get-DefenderVerdict.ps1
      .\Get-DefenderVerdict.ps1 -Days 90
      .\Get-DefenderVerdict.ps1 -File "C:\Users\du\Downloads\irgendwas.exe"
#>

[CmdletBinding()]
param(
    [int]$Days = 60,
    [string]$File
)

$ErrorActionPreference = 'Continue'

function Head($t) {
    Write-Host ''
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 74) -ForegroundColor DarkCyan
}
function Say($t, $c = 'Gray') { Write-Host "  $t" -ForegroundColor $c }

$since = (Get-Date).AddDays(-$Days)
$isAdmin = (New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Head 'WAS HAT WINDOWS TATSAECHLICH GEMELDET?'
Say "Zeitraum   : letzte $Days Tage (ab $($since.ToString('dd.MM.yyyy')))"
Say "Adminrechte: $isAdmin $(if(-not $isAdmin){'- einige Quellen bleiben leer'})" $(if($isAdmin){'Green'}else{'Yellow'})

# ====================================== 0. WER scannt hier ueberhaupt?
# Das muss VOR allem anderen geklaert werden. Laeuft ein Drittscanner,
# ist Defender im Passivmodus und hat schlicht nichts gesehen - dann
# sind alle Defender-Abfragen unten erwartungsgemaess leer, und das
# heisst NICHT "keine Bedrohung".
Head '0. WELCHER SCANNER IST HIER AKTIV?'
$primary = $null
try {
    $avs = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($av in $avs) {
        $rt = ((($av.productState -shr 12) -band 0xF) -ne 0)
        $col = if ($rt) { 'Green' } else { 'DarkGray' }
        Say "$($av.displayName) - Echtzeitschutz: $(if($rt){'AN'}else{'AUS'})" $col
        if ($rt -and $av.displayName -notmatch 'Defender') { $primary = $av.displayName }
    }
} catch { Say "SecurityCenter2 nicht abfragbar: $($_.Exception.Message)" Yellow }

try {
    $mode = (Get-MpComputerStatus -ErrorAction Stop).AMRunningMode
    Say "Defender-Modus : $mode" $(if ($mode -match 'Passive|SxS') { 'Yellow' } else { 'Green' })
} catch { }

if ($primary) {
    Write-Host ''
    Say "ACHTUNG: Der aktive Scanner ist '$primary', NICHT Windows Defender." Red
    Say 'Defender laeuft nur passiv und scannt nicht in Echtzeit.' Red
    Say 'Die Meldung "Windows haelt das fuer Schadsoftware" stammt daher' Yellow
    Say "mit hoher Wahrscheinlichkeit von $primary." Yellow
    Say ''
    Say 'Konsequenzen:' Cyan
    Say "  - Der Fund steht in der $primary-Quarantaene, nicht im Defender-Verlauf."
    Say '  - Die Defender-Namenslogik unten (!ml, Wacatac) gilt hier NICHT.'
    Say "  - Einen Fehlalarm meldest du an $primary, nicht an Microsoft."
    Say '  - Die Defender-Abfragen unten sind erwartungsgemaess leer.'
    Say '    Das ist KEIN Freispruch fuer die Datei.'
}

# ================================================ 1. Defender: aktive Funde
Head '1. DEFENDER - aktuelle Bedrohungen (Get-MpThreat)'
try {
    $threats = Get-MpThreat -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -ge $since }
    if ($threats) {
        foreach ($t in $threats) {
            Say "Name       : $($t.ThreatName)" Red
            Say "Schwere    : $($t.SeverityID)   Kategorie: $($t.CategoryID)"
            Say "Erstfund   : $($t.InitialDetectionTime)"
            Say "Status     : $($t.ThreatStatusID)"
            if ($t.Resources) { $t.Resources | ForEach-Object { Say "Datei      : $_" } }
            Write-Host ''
        }
    } else { Say 'Keine Eintraege im Zeitraum.' Green }
} catch { Say "Nicht abrufbar: $($_.Exception.Message)" Yellow }

# ============================================ 2. Defender: Erkennungsverlauf
Head '2. DEFENDER - Erkennungsverlauf (Get-MpThreatDetection)'
try {
    $det = Get-MpThreatDetection -ErrorAction Stop |
           Where-Object { $_.InitialDetectionTime -ge $since } |
           Sort-Object InitialDetectionTime -Descending
    if ($det) {
        foreach ($d in $det | Select-Object -First 25) {
            Say "Zeit       : $($d.InitialDetectionTime)" White
            Say "ThreatID   : $($d.ThreatID)"
            Say "Aktion     : $($d.ActionSuccess)  Quelle: $($d.DetectionSourceTypeID)"
            if ($d.Resources) { $d.Resources | ForEach-Object { Say "Ressource  : $_" Yellow } }
            Write-Host ''
        }
    } else { Say 'Keine Eintraege im Zeitraum.' Green }
} catch { Say "Nicht abrufbar: $($_.Exception.Message)" Yellow }

# ======================================================= 3. Defender-Eventlog
Head '3. DEFENDER-EREIGNISPROTOKOLL'
# 1116 Malware erkannt | 1117 Aktion ausgefuehrt | 1006/1007 Scan-Fund
# 1015 verdaechtiges Verhalten | 5007 Konfiguration geaendert
$ids = 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119
try {
    $ev = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Windows Defender/Operational'
        Id        = $ids
        StartTime = $since
    } -ErrorAction Stop
    if ($ev) {
        foreach ($e in $ev | Select-Object -First 20) {
            $col = if ($e.Id -in 1116, 1117, 1015) { 'Red' } else { 'Gray' }
            Say "[$($e.TimeCreated)] ID $($e.Id)" $col
            $txt = ($e.Message -split "`n" | Where-Object { $_ -match 'Name:|Pfad:|Path:|Schweregrad|Severity' } |
                    Select-Object -First 4) -join ' | '
            if ($txt) { Say "   $($txt.Trim())" }
        }
    } else { Say 'Keine passenden Ereignisse.' Green }
} catch { Say "Protokoll nicht lesbar: $($_.Exception.Message)" Yellow }

# ============================================================= 4. SmartScreen
Head '4. SMARTSCREEN (App-Reputation - KEIN Virenfund!)'
$found = $false
foreach ($log in 'Microsoft-Windows-SmartScreen/Debug', 'Microsoft-Windows-AppLocker/EXE and DLL') {
    try {
        $se = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since } -ErrorAction Stop |
              Select-Object -First 10
        if ($se) {
            $found = $true
            Say "--- $log ---" DarkGray
            $se | ForEach-Object { Say "[$($_.TimeCreated)] $(($_.Message -split "`n")[0])" }
        }
    } catch { }
}
if (-not $found) {
    Say 'Keine SmartScreen-Ereignisse gefunden.' Gray
    Say 'Das ist normal - SmartScreen protokolliert Reputationsblockaden' DarkGray
    Say 'oft gar nicht im Eventlog. Entscheidend ist der Wortlaut am Bildschirm:' DarkGray
    Write-Host ''
    Say '"Der Computer wurde durch Windows geschuetzt"' White
    Say '   -> SmartScreen, reine Reputation. KEIN Virenfund.' Green
    Say '"Es wurde eine Bedrohung gefunden" / roter Defender-Balken' White
    Say '   -> Echter Defender-Fund. Bedrohungsname notieren.' Red
    Say '"Diese App kann auf dem PC nicht ausgefuehrt werden"' White
    Say '   -> 16-Bit oder falsche Architektur. Mit Sicherheit nichts zu tun.' Yellow
}

# ================================================= 5. Datei-Detailpruefung
if ($File) {
    Head "5. DATEIPRUEFUNG - $File"
    if (-not (Test-Path $File)) {
        Say 'Datei existiert nicht (evtl. bereits in Quarantaene verschoben).' Yellow
    } else {
        $fi = Get-Item $File
        Say "Groesse : $('{0:N0}' -f $fi.Length) Bytes"
        Say "SHA256  : $((Get-FileHash $File -Algorithm SHA256).Hash)" White

        # Mark of the Web
        $zone = Get-Content -Path $File -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($zone) {
            Say 'Mark of the Web: VORHANDEN' Yellow
            $zone | ForEach-Object { Say "   $_" DarkGray }
            Write-Host ''
            Say 'Das allein loest schon SmartScreen aus - ohne jeden Virenverdacht.' DarkGray
            Say 'Gezielt entfernen (nur wenn die Datei geprueft ist):' DarkGray
            Say "   Unblock-File -Path '$File'" White
        } else {
            Say 'Mark of the Web: nicht vorhanden' Green
        }

        $sig = Get-AuthenticodeSignature $File
        Say "Signatur: $($sig.Status)" $(if ($sig.Status -eq 'Valid') { 'Green' } else { 'Yellow' })
    }
}

# ====================================================== 6. Deutung der Namen
Head 'DEUTUNG EINES BEDROHUNGSNAMENS'
Say 'Endet der Name auf  !ml   -> Machine-Learning-Verdacht, kein Signaturfund.' Yellow
Say 'Enthaelt er         Wacatac, Wacapew, Sabsik, Zpevdo, Presenoker' Yellow
Say '                    -> generische Sammelnamen, klassische Fehlalarmkandidaten.' Yellow
Say 'Enthaelt er         HackTool, RiskWare, PUA  -> korrekt erkannt, aber' Yellow
Say '                    nicht zwingend boesartig (z.B. Port-Zugriffstreiber).' Yellow
Say ''
Say 'Konkreter Familienname OHNE !ml (z.B. Emotet, Zbot, Qakbot)' Red
Say '   -> Signaturtreffer. Das ist ernst zu nehmen.' Red
Write-Host ''
Say 'Fehlalarm melden: https://www.microsoft.com/en-us/wdsi/filesubmission' White
Write-Host ''
