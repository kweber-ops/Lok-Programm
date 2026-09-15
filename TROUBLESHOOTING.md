# Wenn doch noch Probleme auftreten

Nach Symptom sortiert. Jeder Eintrag nennt die **Ursache**, die **Prüfung** und den
**Fix** — und, wo es zählt, was *nicht* die Ursache ist.

---

## Das Programm startet gar nicht

### „Diese App kann auf dem PC nicht ausgeführt werden"

Das ist eine Architekturmeldung, keine Sicherheitsmeldung. Sie bedeutet 16-Bit-Code auf
64-Bit-Windows — dort gibt es kein NTVDM.

```powershell
.\tools\Inspect-Installer.ps1     # meldet "16-Bit (NE)" falls zutreffend
```

Bei der geprüften V1.51 kann das **nicht** auftreten: sie ist PE32 i386. Tritt es
trotzdem auf, ist es eine andere Datei als die dokumentierte — Größe und SHA256
gegen `CLAUDE.md` prüfen.

### Fenster erscheint kurz und verschwindet

Delphi-Anwendungen fangen Laufzeitfehler in `TApplication.HandleException` ab und zeigen
eine **Messagebox** — sie erzeugen *keinen* Eintrag im Ereignisprotokoll. Ein leeres
Eventlog beweist hier nichts.

Fix: Aus einer Konsole starten, damit nichts wegklickt, und auf die Messagebox achten.

### Der Virenscanner hat sie kassiert

Auf diesem Host ist **Avira** aktiv, nicht Defender (`AMRunningMode: SxS Passive Mode`).
Der Fund steht in der Avira-Quarantäne, nicht im Defender-Verlauf.

```powershell
.\tools\Get-DefenderVerdict.ps1 -Days 90
```

Reihenfolge beim Wiederherstellen: **erst Ausnahme setzen, dann wiederherstellen.**
Umgekehrt fängt der Echtzeitschutz die Datei beim Zurückschreiben sofort wieder ab.
Echtzeit- und On-Demand-Ausnahmen sind in Avira **getrennte Listen** — nur eine zu setzen
bedeutet, dass der nächste Vollscan die Datei Wochen später doch einkassiert.

Niemals den Downloads-Ordner, `%TEMP%` oder einen Laufwerksstamm als Ausnahme eintragen.

---

## „Es wurde kein LokProgrammer an irgend einer seriellen Schnittstelle gefunden!"

Diese eine Meldung erscheint bei **allen** Ursachen. Deshalb von unten nach oben prüfen.

### Zuerst: die grüne LED

Das ist das schärfste Diagnosewerkzeug und kostet nichts.

| LED | Bedeutung |
|---|---|
| aus | Programmer hat keinen Strom |
| dauerhaft an | Spannung liegt an, aber es kommen keine Daten |
| **blinkt** | Programmer empfängt Daten vom PC — die serielle Strecke ist in Ordnung |

Blinkt sie beim Suchlauf nicht, liegt es an Kabel, Port oder Passthrough — **nicht** an
Windows und nicht an der Software.

### Das Programm kennt nur COM1 bis COM4

Hart einprogrammiert. Liegt der Programmer auf COM5 oder höher, findet ihn die Software
nie. Das ist keine Windows-Einschränkung.

```powershell
[System.IO.Ports.SerialPort]::GetPortNames()
```

Fix: Im Geräte-Manager unter *Anschlusseinstellungen → Erweitert* die Portnummer auf
COM1–COM4 ändern.

### Port ist belegt

`CreateFileA` auf COM1 liefert dann `ERROR_ACCESS_DENIED`. Typische Besetzer auf Windows 10:
Bluetooth-Geräteverwaltung, FTDI-/Prolific-„Serial Enumerator", Hersteller-Tools,
USV-Software.

```powershell
.\tools\Test-COM1.ps1
```

Meldet das Skript „Port lässt sich öffnen", ist er frei.

### Falsches Kabel

**1:1-Kabel, kein Nullmodemkabel.** Das ist der häufigste Anfängerfehler.

### Falsche Reihenfolge beim Einschalten

Netzteil **erst einstecken, nachdem das Programm gestartet ist.**
Und niemals Steckernetzteil und Trafo-Wechselspannung gleichzeitig — Zerstörungsgefahr.

Keine Lok auf dem Programmiergleis, während die Verbindung aufgebaut wird.

### USB-Seriell-Adapter statt Onboard-Port

Erfahrungsgemäß die häufigste Fehlerquelle. Der Onboard-16550 (`ACPI\PNP0501`) ist
deutlich zuverlässiger. Wenn ein Adapter unvermeidlich ist: in einer VM den
**USB-Adapter durchreichen**, nicht den COM-Port.

---

## Kein Ton beim Vorhören

Die Software nutzt **DirectSound**. Auf diesem Host existieren sieben Audio-Endpunkte,
darunter ein Funk-Headset (zeitweise abwesend), NVIDIA Virtual Audio, DroidCam und zwei
VB-Audio Virtual Cables — eines mit Status *Error*.

DirectSound nimmt das **Standardgerät**. Ist das ein virtuelles oder abgeschaltetes
Gerät, bleibt es stumm — ohne Fehlermeldung.

Fix: Vor dem Vorhören ein reales Ausgabegerät als Standard setzen
(*Systemsteuerung → Sound → Wiedergabe*). Prüfen, ob `DSound.dll` geladen ist:

```powershell
& "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -Command "(Get-Process LokProgrammer).Modules | Where-Object ModuleName -match 'dsound'"
```

Die Meldung „Sie haben keine Soundkarte in Ihrem Rechner installiert" kommt aus dem
Programm und meint dasselbe.

---

## Einstellungen gehen verloren

Die Anwendung ist vollständig portabel — sie schreibt weder Dateien noch Registry-Werte
(die einzigen gelesenen Schlüssel sind `Software\Borland\Delphi\*`, das ist die
VCL-Lokalisierung).

Falls sie beim Speichern einer Portkonfiguration doch etwas ablegt: Die EXE hat **kein
Manifest**, also greift UAC-Virtualisierung. Unter `Program Files` landet der Schreibvorgang
still in:

```
%LOCALAPPDATA%\VirtualStore\Program Files (x86)\...
```

Fix: außerhalb von `Program Files` betreiben — `C:\LokProgrammer` ist der dokumentierte Ort.

---

## Oberfläche sieht falsch aus

### Winzig auf hochauflösendem Schirm

Der Layer `DPIUNAWARE` lässt Windows hochskalieren. Fehlt er, wird die 2002er-Oberfläche
sehr klein.

```powershell
$k = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
Set-ItemProperty -Path $k -Name 'C:\LokProgrammer\LokProgrammer.exe' -Value '~ WINXPSP3 DPIUNAWARE'
```

**Niemals** `New-Item -Force` auf diesen Key — das löscht alle Einträge anderer Programme.

### Unscharf

Dann `DPIUNAWARE` wieder entfernen — es ist ein Tausch zwischen Größe und Schärfe.

### Steuerelemente verrutscht

Die Anwendung lädt bewusst `comctl32` **5.82** (ungethemt) aus WinSxS. Das ist korrekt für
ein Programm von 2002. Kein v6-Manifest anbauen — das würde das Layout erst zerstören.

---

## Menüeinträge sind ausgegraut

### „Hilfethemen"

**Kein Fehler.** ESU hat die Hilfe in V1.51 deaktiviert ausgeliefert: Der Menüeintrag hat
`Enabled = False` und keinen Handler. Es gibt keine Hilfedatei, die man nachrüsten könnte.

### Drucken fehlt

Wurde nie implementiert — kein `winspool.drv` im Import, `comdlg32` importiert nur
`GetOpenFileNameA` und `GetSaveFileNameA`.

---

## Projektdateien lassen sich nicht öffnen

### Doppelklick auf `*.ESU` startet nichts

Die Dateiverknüpfung ist nicht registriert, weil es keine Installation gab. Über
*Datei → Öffnen* funktioniert alles. Nachrüsten, falls gewünscht:

```powershell
cmd /c assoc .ESU=LokProgrammerProject
cmd /c ftype LokProgrammerProject="C:\LokProgrammer\LokProgrammer.exe" "%%1"
```

### Datei wird nicht gefunden, obwohl sie da ist

Die Dateidialoge sind **ANSI** (`GetOpenFileNameA`). Pfade mit Umlauten oder Zeichen
außerhalb der Codepage können scheitern.

Fix: Projekte in einem kurzen ASCII-Pfad halten, z. B. `C:\LokProgrammer\Projekte`.

---

## Der Decoder reagiert nicht

### Erst lesen, dann schreiben

Zum Testen einen **entbehrlichen** Decoder nehmen. Ein Abbruch mitten im Schreibvorgang
kann ihn in einen inkonsistenten Zustand bringen.

### Der Decoder ist zu neu

Der 50450 programmiert **ausschließlich LokSound „classic"** (ca. 1999–2001). ESU dazu
wörtlich: *„The LokProgrammer part no. 50450 is not suitable for programming LokSound
decoders version 3.5."*

Kein Software- oder Windows-Problem — eine Hardwaregrenze. Für neuere Decoder:

- **Nur CVs setzen?** Jede NMRA/DCC-Zentrale plus JMRI DecoderPro. Kostet nichts.
- **Sound oder Firmware?** Geht ausschließlich mit LokProgrammer-Hardware.
  Aktuelles Modell 53451, rund 135 €, die Software 5.2.18 läuft nativ auf Windows 10.

JMRI unterstützt **keinen** LokProgrammer, kein Modell.

---

## Wenn nichts davon hilft: die VM

Nur diese Stufe löst Installer-, Registry- und Timing-Fragen in einem Schritt.

```powershell
.\vm\New-LegacyVM.ps1 -IsoPath "D:\iso\w2k.iso" -WhatIf
```

**Windows 2000**, nicht XP: Es aktiviert nicht — Microsoft hat die Telefonaktivierung am
03.12.2025 abgeschaltet. Legal brauchst du eine eigene Altlizenz oder eine gebrauchte
Vollversion **mit Originaldatenträger**.

**VirtualBox oder VMware, niemals Hyper-V.** Hyper-V bindet VM-COM-Ports ausschließlich an
Named Pipes, nie an einen physischen Port. Windows Sandbox kann es ebenfalls nicht — ihr
Konfigurationsschema kennt keine serielle Umleitung.

Nach der Installation: sofort Snapshot. Und `IO-APIC` sowie `ACPI` danach **nie mehr
ändern** — NT5 wählt die HAL beim Setup anhand dieser Werte, späteres Umstellen endet im
Bluescreen.

### Timing bricht in der VM ab

Nicht mehr CPU-Kerne zuweisen — das verschlechtert es in VirtualBox eher. Ursache ist
Latenz und Jitter der virtualisierten UART-Zugriffe. Auf diesem Host läuft ein
Hypervisor (durch WSL2/VirtualMachinePlatform), der VirtualBox in das langsamere
NEM-Backend zwingt.

Falls es wirklich am Timing scheitert: **nicht** VBS global abschalten, sondern einen
zweiten Booteintrag anlegen —

```powershell
bcdedit /copy "{current}" /d "Windows 10 ohne Hypervisor"
bcdedit /set "{<neue-GUID>}" hypervisorlaunchtype off
```

— dann bleiben WSL2 und Docker im Alltagseintrag unangetastet. Auf diesem Host laufen
ohnehin **null** VBS-Schutzdienste (`SecurityServicesRunning = {0}`, Legacy-BIOS ohne
Secure Boot), der Sicherheitsverlust wäre also gering. Die relevante Frage ist nicht
Sicherheit, sondern ob WSL2 und Docker gebraucht werden.
