# LokProgrammer — Sandbox und Legacy-VM

> ## ⛔ ZUERST LESEN — drei Fragen, bevor hier irgendetwas gebaut wird
>
> Die Recherche hat ergeben, dass dieses ganze Projekt für die meisten
> Ausgangslagen **überflüssig** ist.
>
> **Der LokProgrammer 50450 kann ausschließlich LokSound „classic"
> programmieren** (ca. 1999–2001). ESU sagt das in beide Richtungen:
>
> - ESU-FAQ: *„Zum Programmieren und Updaten von LokSound 'classic'
>   Decodern kann nur der LokProgrammer 50450 verwendet werden."*
> - LokSound-V3.5-Handbuch: *„The LokProgrammer part no. 50450 is not
>   suitable for programming LokSound decoders version 3.5."*
>
> Daraus folgt:
>
> | Deine Lage | Richtiger Weg | Aufwand |
> |---|---|---|
> | Du willst nur **CVs einstellen** | Jede NMRA/DCC-Zentrale + JMRI DecoderPro | 0 € |
> | Deine Decoder sind **neuer als LokSound classic** | LokProgrammer 53451, aktuelle Software 5.2.18 läuft nativ auf Win10 | ~135 € |
> | **LokSound classic** + 50450-Hardware vorhanden + **Sound** tauschen | Erst dann der Legacy-Pfad hier | VM + Win2000-Lizenz |
>
> **Die harte Grenze:** CVs gehen mit jeder DCC-Zentrale.
> **Sounddateien und Firmware** gehen *ausschließlich* über
> LokProgrammer-Hardware — dafür gibt es keinen Ersatz.
>
> **JMRI unterstützt keinen LokProgrammer** (kein Modell). Der
> Hardware-Index kennt ESU nur als ECoS-Zentrale.


Werkzeuge, um die ESU-Altsoftware (LokProgrammer PC-Software v1.51,
01.01.2002, für den nicht mehr hergestellten LokProgrammer 50450)
erst auf Unbedenklichkeit zu prüfen und dann tatsächlich zu betreiben.

**Das sind zwei verschiedene Probleme mit zwei verschiedenen Werkzeugen.**

---

## Die wichtigste Erkenntnis zuerst

**Windows Sandbox kann COM1 nicht durchreichen.** Das `.wsb`-Schema
kennt keine serielle Umleitung und keinen Geräte-Passthrough — die
dokumentierte Optionsliste ist abschließend. Außerdem läuft in der
Sandbox zwingend der aktuelle Host-Build, nie Windows 98/2000.

Die Sandbox beantwortet also nur: *„Ist die Datei sauber?"*
Sie kann den LokProgrammer 50450 **niemals** ansteuern.

Für den Betrieb braucht es die VM in `vm\`.

---

## Stufe 0 — zuerst das Billigste probieren

Bevor irgendeine VM gebaut wird: Architektur der EXE messen.

Die Herstellerangabe „Windows 95/98/2000" sagt nichts über die Bitness.
Wenn nur der Installer-Stub 16-Bit ist, die eigentliche Anwendung aber
ein 32-Bit-Win32-Programm, läuft sie mit hoher Wahrscheinlichkeit direkt
auf Windows 10 x64 — mit dem echten COM1, ohne VM, ohne Lizenzfrage und
mit der geringsten seriellen Latenz.

`Inspect-Installer.ps1` gibt die Architektur aus. Meldet es ein 32-Bit-PE,
den Container mit 7-Zip entpacken und die Anwendung direkt starten.

---

## Sandbox — Sicherheitsbewertung

Windows Sandbox ist ein hypervisor-isolierter Wegwerf-Container mit
**eigenem Kernel** (Feature `Containers-DisposableClientVM`). Der Kernel
wird *nicht* mit dem Host geteilt — das unterscheidet sie klar von
Windows Server Containers, die MSRC ausdrücklich *nicht* als Boundary führt.

Die Einordnung ehrlich:

- Die MSRC-„Virtual machine boundary" deckt Hyper-V Isolated Containers
  ausdrücklich ab und wird serviciert.
- **Aber:** Der String „Windows Sandbox" kommt in den Servicing Criteria
  nicht vor. Das Hyper-V-Bounty-Programm (bis 250.000 USD für einen
  L1-Guest-Escape) schließt die Sandbox explizit aus und verweist sie
  auf das Insider-Programm mit maximal 30.000 USD.
- Fazit: Die Grenze ist technisch real und wird gepatcht, aber Microsoft
  gibt für Windows Sandbox als Produkt **kein Boundary-Versprechen** ab.
  Wer eine zugesicherte Isolation braucht, nimmt eine echte VM.

### Der Preis der Installation

Die drei aktiv ausgenutzten CVEs vom Januar 2025 (CVE-2025-21333,
-21334, -21335, alle im Treiber `vkrnlintvsp.sys`, seit 14.01.2025 im
CISA-KEV-Katalog) sind **keine** Sandbox-Ausbrüche, sondern lokale
Rechteausweitungen **auf dem Host**.

Entscheidend ist der Mechanismus: Der verwundbare Treiber kommt erst
**mit der Sandbox-Installation** auf den Host — und ist dort aktiv,
auch wenn die Sandbox nie gestartet wird. Der PoC sagt das wörtlich:
das Sandbox-Feature muss eingeschaltet sein, damit die verwundbaren
Syscalls überhaupt beim Treiber landen.

Bei aktuellem Patchstand ist das vertretbar. Ungepatcht ist die
Installation ein Netto-Verlust an Sicherheit.

### Rangfolge der schwächenden `.wsb`-Optionen

1. `MappedFolder ReadOnly=false` — braucht keinen Exploit, wirkt per
   Design auf den Host, überlebt das Schließen. **Default ist `false`.**
2. `Networking=Enable` — LAN-Exposition plus `vmswitch.sys` als
   historisch belegte Angriffsfläche.
3. `VGpu=Enable` — die einzige Option, vor der Microsoft selbst warnt.
4. `ClipboardRedirection` — Exfiltrationskanal, keine Codeausführung.
5. `AudioInput`/`VideoInput` — Privacy, nicht Boundary.

Beide Konfigurationen hier setzen 1–3 auf die sichere Seite.

### Ehrliche Einschränkung

`ReadOnly=true` verhindert **Schreiben, nicht Lesen**. Der Inhalt von
`shared\` und `tools\` ist aus der Sandbox heraus vollständig lesbar —
bei aktivem Netzwerk in Stufe 1 also grundsätzlich exfiltrierbar. Lege
dort nichts ab, was nicht hineingehört.

Und: Ein negativer Befund beweist wenig. Malware erkennt
`WDAGUtilityAccount` und die Sandbox-Artefakte trivial und hält still.

---

## Ablauf

### Voraussetzung (einmalig, Adminrechte + Neustart)

    Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All

Prüfen: `Test-Path C:\Windows\System32\WindowsSandbox.exe`

> **Vorher anpassen:** Beide `.wsb`-Dateien binden feste Host-Pfade ein
> (`C:\LokProgrammer-Sandbox\shared` und `…\tools`). Trag dort den Pfad ein,
> unter dem dieses Repository bei dir liegt — sonst startet die Sandbox mit
> leeren Ordnern.

### Stufe 1 — `Sandbox-Analyse.wsb`

Netzwerk **an**, Zwischenablage **an**, alle Mounts read-only.
Die Datei wird *in* der Sandbox geladen, damit der Host sie nicht anfasst.

    powershell -File $env:USERPROFILE\Desktop\tools\Get-LokProgrammer.ps1
    powershell -File $env:USERPROFILE\Desktop\tools\Inspect-Installer.ps1

SHA256 per Zwischenablage herausholen, bei VirusTotal prüfen.

> Die in Stufe 1 geladene Datei bleibt **in der Sandbox** und ist beim
> Schließen weg. Das ist Absicht. Für Stufe 2 lädst du die Datei auf dem
> Host nach `shared\` — sie dort liegen zu haben ist unkritisch, solange
> sie nicht ausgeführt wird.

### Stufe 2 — `Sandbox-Isoliert.wsb`

Netzwerk **aus**, Zwischenablage **aus**, `ProtectedClient` **an**.
Hier darf ausgeführt werden. Ein Ausbruch erforderte einen
Hypervisor-/VSP-0-Day.

---

## Die VM — `vm\New-LegacyVM.ps1`

### Warum nicht Hyper-V

Hyper-V bindet VM-COM-Ports **ausschließlich an Named Pipes**, nicht an
physische Host-Ports (Gen 1 wie Gen 2, so dokumentiert bei
`Set-VMComPort`). Für den 50450 braucht es einen echten UART.

Physischen Passthrough beherrschen **VirtualBox** (`--uartmode1 \\.\COM1`)
und **VMware Workstation** (`serial0.fileType = "device"`).
QEMU öffnet den Port zwar, propagiert aber Baudrate und Parität nicht —
für ein proprietäres Protokoll disqualifiziert.

### Gast-OS: Windows 2000 Professional

- Vom Hersteller für diese Software ausdrücklich genannt.
- **Aktiviert nicht** — entscheidend, seit Microsoft die Telefon-
  aktivierung am 03.12.2025 abgeschaltet hat. XP wäre nur noch über
  ein Onlineportal mit Microsoft-Konto aktivierbar.
- NT-Treibermodell mit funktionierenden VirtualBox-Treibern; Win98 SE
  hat gar keine offiziellen Guest Additions.

### Aufruf

    .\vm\New-LegacyVM.ps1 -IsoPath "D:\iso\win2000pro.iso" -WhatIf   # Vorschau
    .\vm\New-LegacyVM.ps1 -IsoPath "D:\iso\win2000pro.iso"

Das Skript lädt **nichts** herunter und installiert kein OS.

### Lizenz

Windows 2000/XP sind nicht mehr neu erhältlich. Legal bleiben nur die
eigene Altlizenz oder eine gebrauchte Vollversion **mit Original-
datenträger** (EuGH C-128/11 UsedSoft, eingeschränkt durch C-166/15
Ranks — ein Key ohne Medium, ein COA-Aufkleber allein oder ein
Archiv-ISO ist keine Lizenz). Gibt es beides nicht, existiert kein
legaler Weg. Das ist eine Einordnung, keine Rechtsberatung.

Lizenzfrei zum Ausprobieren: **ReactOS 0.4.16** (weiterhin Alpha) oder
eine Linux-VM mit Wine und COM1 auf `/dev/ttyS0`.

---

## Den eigenen Host einordnen

Diese Werte vor dem VM-Bau selbst erheben — sie entscheiden über die Wahl:

| Befund | Womit prüfen | Warum es zählt |
|---|---|---|
| Serieller Port | `Get-PnpDevice -Class Ports` | `ACPI\PNP0501` ist ein echter Onboard-16550 und die beste Ausgangslage. USB-Adapter sind die häufigste Fehlerquelle. |
| Hypervisor | `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent` | Ist einer aktiv, laufen VirtualBox und VMware im langsameren NEM/WHP-Backend. |
| Herkunft | `Test-Path C:\Windows\System32\vmms.exe` | Fehlt die Datei, kommt der Hypervisor nicht von Hyper-V, sondern meist von WSL2 oder der VirtualMachinePlatform. |
| VBS | `Get-CimInstance Win32_DeviceGuard` | `SecurityServicesRunning` zeigt, ob HVCI und Credential Guard wirklich laufen — oder ob nur der Hypervisor-Preis bezahlt wird. |
| CPU | `Get-CimInstance Win32_Processor` | Ein NT5-Gast braucht wenig. Mehr Kerne verschlechtern serielles Timing eher. |

**Konsequenz bei aktivem Hypervisor:** VirtualBox fällt auf das langsamere NEM/WHP-Backend
zurück. Für einen Win2000-Gast ist das mit hoher Wahrscheinlichkeit
trotzdem völlig ausreichend — erst testen, bevor am System geschraubt wird.

Falls das Timing doch scheitert: **nicht** VBS global abschalten, sondern
einen zweiten Booteintrag anlegen (`bcdedit /copy` + `hypervisorlaunchtype off`).
Dann bleiben WSL2 und Docker im Alltagseintrag unangetastet. Der eigentliche
Kollateralschaden liegt dort, nicht bei der Sicherheit — auf diesem Host
laufen null VBS-Schutzdienste.

---

## Dateien

    Sandbox-Analyse.wsb          Stufe 1 — Netzwerk an, nur analysieren
    Sandbox-Isoliert.wsb         Stufe 2 — Netzwerk aus, ausführen erlaubt
    shared\                      Host-Ordner, read-only eingebunden
    tools\Inspect-Installer.ps1  Statische Analyse (PE, Hash, Signatur, Defender)
    tools\Get-LokProgrammer.ps1  Download in der Sandbox (fragt nach)
    tools\Test-COM1.ps1          Serielle Diagnose, Host und Gast
    vm\New-LegacyVM.ps1          VirtualBox-VM mit COM1-Passthrough

---

## Reihenfolge beim Decoder

**Erst auslesen, dann schreiben.** Zum Testen einen entbehrlichen
Decoder nehmen. Ein Abbruch mitten im Schreibvorgang kann ihn in einen
inkonsistenten Zustand bringen — und das serielle Durchreichen ist der
wackeligste Teil der Kette, nicht das Gast-OS.
