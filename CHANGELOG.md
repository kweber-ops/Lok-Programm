# Changelog

Alle Änderungen an diesem Werkzeugkasten. Format lose nach
[Keep a Changelog](https://keepachangelog.com/de/1.1.0/).

Die Einträge dokumentieren auch, **wodurch** ein Fehler aufgefallen ist — fast alle
kamen erst beim Lauf gegen echte Dateien heraus, nicht bei der Syntaxprüfung.

## [1.0.0] — 2026-09-15

Erster vollständiger Stand. Die Ausgangsfrage („Warum hält Windows 10 das Programm für
Schadsoftware?") ist beantwortet: **gar nicht.** Das Programm läuft unverändert.

### Ergebnis

- ESU LokProgrammer PC-Software V1.51 läuft auf Windows 10 Pro 22H2 x64 **ohne jede
  Modifikation** — keine Installation, kein Kompatibilitätsmodus, keine Signatur,
  kein Entfernen des Mark of the Web.
- Verifiziert im Betrieb: 93 Module geladen, alle aus Windows; Handles/GDI/USER über
  25 Minuten konstant (Δ 0); keine Fehlerereignisse; COM1 korrekt belegt und freigegeben.

### Hinzugefügt

- `Deploy-LokProgrammer.ps1` — Download, Größenprüfung, SHA256-Baseline,
  Architekturklassifizierung, Entpacken statt Ausführen, Ablage außerhalb von
  `Program Files`, Setzen der Kompatibilitäts-Flags.
- `tools/Inspect-Installer.ps1` — statische Analyse: PE/NE-Erkennung, 16/32/64-Bit,
  Subsystem, Linker-Zeitstempel, Packer-Marker, Container-Magics (MSI/CAB/ZIP/RAR/7z),
  Signaturstatus, Defender-Scan.
- `tools/Get-DefenderVerdict.ps1` — beantwortet, **welcher** Scanner tatsächlich etwas
  gemeldet hat; liest Defender-Verlauf, Ereignisprotokoll, Mark of the Web.
- `tools/Test-COM1.ps1` — serielle Diagnose auf Host- und Gastseite, optionaler
  Loopback-Test.
- `tools/Get-LokProgrammer.ps1` — Download innerhalb der Sandbox.
- `Sandbox-Analyse.wsb` / `Sandbox-Isoliert.wsb` — zweistufige Windows-Sandbox.
- `vm/New-LegacyVM.ps1` — VirtualBox-VM (Windows 2000) mit physischem COM1-Passthrough.
- `README.md`, `CLAUDE.md`, dieses Changelog, `TROUBLESHOOTING.md`.

### Behoben

Alle Fehler fielen beim Test gegen echte Dateien auf, nicht bei der Syntaxprüfung.

- **PE-Parser um 2 Byte verschoben** (`Inspect-Installer.ps1`). Ein `ReadUInt16` zu viel
  ließ `Characteristics` statt `SizeOfOptionalHeader` in `$optSize` landen; das Subsystem
  wurde 2 Byte versetzt aus `DllCharacteristics` gelesen. Belegmessung: `SysWOW64\notepad.exe`
  meldete `Typ 49472` statt `GUI`. Zusätzlich `-gt 68` auf `-ge 70` korrigiert.
- **Defender-Scanfehler als Malware-Treffer gemeldet.** Es wurde der Ausgabetext statt
  `$LASTEXITCODE` geprüft. In einer Sandbox ist der Defender-Dienst oft inaktiv — der
  Fehlalarm wäre dort die Regel gewesen, ausgerechnet beim Abbruchkriterium.
- **Defender-Passivmodus nicht berücksichtigt.** `Inspect-Installer.ps1` meldete
  „SAUBER", obwohl Defender gar nicht scannt. Gibt jetzt `PASSIVMODUS — Scan wäre
  aussagelos` aus.
- **`New-Item -Force` auf den Registry-Key `AppCompatFlags\Layers`.** Bei einem
  *existierenden* Key legt `-Force` ihn neu an und löscht alle Werte. Hat beim Testlauf
  sechs bestehende Kompatibilitätseinträge fremder Programme gelöscht. Aus den
  Agent-Protokollen rekonstruiert und wiederhergestellt, mit `reg.exe` verifiziert.
  Jetzt: Anlegen nur bei `-not (Test-Path)`,
  plus `.reg`-Sicherung vor jeder Änderung.
- **`RUNASADMIN` als Kompatibilitäts-Flag entfernt.** Es schaltet die UAC-Virtualisierung
  ab — genau das Sicherheitsnetz, das erhalten bleiben sollte —, erzeugt bei jedem Start
  einen UAC-Prompt und blockiert per UIPI Drag & Drop. Ersetzt durch `WINXPSP3 DPIUNAWARE`.
- **Falscher Ratschlag `setup.exe /a`** im Fehlschlag-Zweig. `/a` ist ein
  Windows-Installer-Schalter, kein Extraktionsschalter für InstallShield-InstallScript
  von 2002. Ersetzt durch den PE-Container-Weg (`7z x -tpe`) und `unshield`/`i6comp`.
- **Rekursive Desktop-Suche** verursachte Laufzeiten über zwei Minuten und scannte
  fremde Ordner. Jetzt: `shared` rekursiv, `Downloads` und `Desktop` nur oberflächlich.
- **MSI/CAB/RAR/7z wurden als „Format unbekannt" gemeldet.** Container-Magics ergänzt
  (`D0CF11E0`, `MSCF`, `Rar!`, `7z`).
- **Ein normales ZIP wurde als „selbstentpackend" etikettiert.** Der SFX-Hinweis
  erscheint jetzt nur noch bei PE-Dateien mit eingebettetem ZIP.
- **Handle-Leck** im `catch`-Zweig des PE-Parsers — `$fs`/`$br` wurden nicht geschlossen,
  die Datei blieb gesperrt.
- **Byteweise ZIP-Suche** brauchte gemessen 3,4 s pro 1,85-MB-Datei. Durch native
  String-Suche ersetzt: **107 ms**, Faktor 32.
- **`ProtectedClient` und `ClipboardRedirection` widersprachen sich** in
  `Sandbox-Analyse.wsb`. In Stufe 1 wird nichts ausgeführt, der Schutz brachte dort fast
  nichts, blockierte aber das Herauskopieren des SHA256. Jetzt `Disable` in Stufe 1,
  `Enable` in Stufe 2.
- **Abhängigkeitsprüfung ergänzt** (`.vxd`/`.sys` als K.-o.-Kriterium, `.vbx`, `.ocx` mit
  gezielter MSCOMM32-Lizenzwarnung, `.hlp`, Runtime-Verfügbarkeit, MSI-Hinweis).

### Korrigierte Fehlannahmen

Diese Aussagen standen in früheren Ständen und waren falsch:

- „Unsigniert ist verdächtig." — Auch die **aktuelle** ESU-Software 5.2.18 (2026) ist
  unsigniert (Certificate Table 0/0). Unsigniert ist ESU-Normalzustand.
- „Hash gegen ESU prüfen." — ESU veröffentlicht für keinen Download eine Prüfsumme,
  weder auf der Seite noch in HTTP-Headern. Eine Integritätsprüfung gegen eine
  Herstellerreferenz ist strukturell unmöglich.
- „Windows blockiert unsignierte Programme." — Tut es nicht. Smart App Control, der
  einzige Mechanismus, der unsigniert hart blockiert, existiert **nur auf Windows 11**.
- „Windows Sandbox könnte den LokProgrammer testen." — Das `.wsb`-Schema kennt keine
  serielle Umleitung. Hyper-V ebenfalls nicht (nur Named Pipes).
- „Der 16-Bit-Installer ist das Hauptrisiko." — Die Datei ist gar kein Installer.
- „MSCOMM32.OCX-Lizenzproblem droht." — Es ist Delphi, nicht VB6. Kein OCX beteiligt.
- „Fehlende Hilfe und fehlendes Drucken sind Windows-10-Schäden." — Beides ist
  Originalzustand von V1.51.

### Nachträglich belegt

Recherche gegen das Internet Archive und ESUs eigene Release Notes, nach dem ersten Stand:

- **Die Datei ist bitidentisch mit ESUs Originalnutzlast.** SHA1
  `8F0745D21BC0A4296BF6B527EC39009AD0E0BEA9` stimmt mit dem Wayback-CDX-Digest der
  Captures vom 16.01.2006, 17.01.2006 und 24.02.2006 überein. Damit existiert doch eine
  unabhängige Vergleichsmöglichkeit — die frühere Aussage „es gibt nichts, wogegen man
  prüfen könnte" war zu pessimistisch.
- **Die Originalauslieferung war ein WinZip-Selbstentpacker** (693.760 Bytes), dessen
  ZIP-Verzeichnis **genau einen** Eintrag enthält: `Lokprogrammer_V151.exe`, entpackt
  1.944.064 Bytes. ESU hat den Entpacker zwischen Januar 2004 und Januar 2006 durch die
  blanke Anwendung ersetzt, bei gleichem Dateinamen und gleicher Version. Es fehlt nichts.
- **`C:\LokProgrammer` ist ESUs eigenes Vorgabeverzeichnis.** Die Installationsanweisung
  lautete wörtlich: entpacken, Voreinstellung `c:\lokprogrammer`. Die Wahl war also nicht
  nur technisch richtig, sondern entspricht der Herstellervorgabe.
- **Systemvoraussetzungen V1.51** laut Release Notes: Pentium 90, 32 MB RAM, ein freier
  COM-Port, Windows 98/98SE/ME/2000/**XP**, **DirectX 6.1+**, Soundkarte. Die
  esu.eu-Downloadseite nennt nur „95/98/2000" und untertreibt damit.
- **Sound- und Dokumentationsmaterial waren immer separate Downloads.** Die Werkssounds
  für LokSound „classic" stehen weiterhin unter Geräuschdateien → Generation 1 bereit.
- **„1 MegaBit" ist kein Defekt**, sondern die Sound-Flashgröße des Decoders
  (1–4 MBit = 12/24/36/48 Sekunden), Vorgabewert 1 MBit.

### Bekannte Grenzen

- Die Kette 50450 → COM1 → LokSound classic ist **ohne angeschlossene Hardware nicht
  verifizierbar**.
- 5 von 12 Delphi-Formularen waren zum Messzeitpunkt noch nicht instanziiert (die VCL
  erzeugt sie erst bei Bedarf) — damit nicht positiv nachgewiesen.
- Die serielle Suche des Programms deckt nur **COM1–COM4** ab.
- Der Programmbinärcode ist aus Lizenzgründen **nicht** Teil dieses Repositories.
