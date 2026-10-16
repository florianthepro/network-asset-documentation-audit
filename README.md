<!-- todo: import von externen analyze systemen dh dymps und datenformate sowie audit regel auto -->
> [!CAUTION]
> Disclaimer: This README.md was created using AI. AI was used for Vison finding.

# Network Asset Documentation Audit

```text
Projektname: Network Asset Documentation Audit
Repository: network-asset-documentation-audit
Kurzname: NADA
Version: 1.0.0
Einstiegspunkt: index.php
```

## Zielbild

NADA ist eine dateibasierte Webanwendung zur strukturierten Aufnahme und Auswertung physischer und logischer Netzwerkfakten in getrennten Kundenumgebungen.

Die Anwendung folgt einem Finding-zentrierten Modell: Beobachtungen werden einmal erfasst und anschließend zu Asset-Übersicht, Netzwerkkarte und Reports verdichtet.

```text
Finding erfassen
├── sachliche Einzelbeobachtung
├── optionaler Netzwerk- oder Hardwarekontext
├── automatisch erzeugte Kurzbezeichnung
└── Anhänge

Kontext ableiten
├── Assets
├── Netzwerke und VLANs
├── Verbindungen und Dienste
├── Standorte
└── Audit- und Risikoinformationen

Ausgabe erzeugen
├── Übersicht
├── Netzwerkkarte
└── Reports
```

## Grundprinzip

Ein Finding beschreibt genau einen beobachteten Sachverhalt.

Die automatisch erzeugte Finding-Bezeichnung dient ausschließlich der Findings-Übersicht. Asset-Namen und Bezeichnungen in der Netzwerkkarte entstehen unabhängig davon aus tatsächlichen Feldern wie Hostname, Hersteller, Modell, Gerätetyp, VLAN, CIDR, Gebäude, Raum oder Rack.

```text
Finding-Text:  TCO-PC0055 erfasst
Asset-Name:    TCO-PC0055
Netzwerkkarte: TCO-PC0055
```

Damit gelangen keine Formulierungen wie „Gerät erfasst“ in Asset-Liste oder Netzwerkkarte.

## Tenant-Modell

Jeder Kunde wird als eigener Tenant geführt.

Tenants können beliebig tief verschachtelte Sub-Tenants besitzen, zum Beispiel für Tochtergesellschaften, Standorte, Abteilungen oder getrennte technische Bereiche.

```text
Tenant
├── Sub-Tenant
│   ├── Sub-Tenant
│   │   └── Sub-Tenant
│   └── Sub-Tenant
└── Sub-Tenant
```

Die Tenant-Navigation ist separat scrollbar und unterstützt das Ein- und Ausklappen verschachtelter Zweige. Der Pfad des aktiven Tenants wird automatisch geöffnet.

Ansichten können wahlweise nur den aktuellen Tenant oder zusätzlich alle lesbaren Sub-Tenants berücksichtigen.

## Navigation

```text
Übersicht
├── Assets
├── Netzwerkkarte
└── Reports

Findings
Einstellungen
Benutzer
```

`Benutzer` und `Einstellungen` erscheinen nur, wenn der angemeldete Benutzer dort tatsächlich eine nutzbare Funktion besitzt.

## Finding-Arten

```text
Gerät
Netzwerk / VLAN
Verbindung / Dienst
Standort / Rack
Audit / Risiko
Allgemeine Beobachtung
```

Das Finding-Overlay zeigt zunächst nur wenige Felder. Weitere Felder erscheinen abhängig von Finding-Art, Gerätetyp und Benutzerinteraktion.

Die Reihenfolge bleibt stabil:

```text
Finding-Art
Sachbezogene Hauptfelder
Optionale Kontextfelder
Audit-Bewertung, falls relevant
Notizen
```

Notizen stehen immer am Ende des Overlays.

## Geräte

Geräte-Findings können folgende Informationen enthalten:

```text
Gerätetyp
Hersteller
Modell
Seriennummer
Hostname
IPv4
IPv6
MAC-Adresse
DHCP-Kennzeichnung
Betriebssystem
OS-Version
```

Hostname und IP-Daten befinden sich im optionalen Bereich `Netzwerkdaten hinzufügen`.

Bei `Laptop / Notebook` werden Betriebssystem und OS-Version direkt angezeigt.

### IP-Validierung

IPv4-Eingaben akzeptieren ausschließlich Ziffern und Punkte, sind auf 15 Zeichen begrenzt und werden zusätzlich serverseitig als gültige IPv4-Adresse geprüft.

IPv6-Eingaben akzeptieren ausschließlich Hexadezimalzeichen und Doppelpunkte, sind auf 39 Zeichen begrenzt und werden zusätzlich serverseitig als gültige IPv6-Adresse geprüft.

```text
IPv4: 192.168.10.25
IPv6: 2001:db8::25
```

Ist DHCP aktiviert, wird die eingetragene IP als aktuell beobachtete dynamische Adresse behandelt. Ohne DHCP-Kennzeichnung wird keine dynamische Vergabe angenommen.

## Verbindung und Dienst

Dienste werden nicht als allgemeine Eigenschaft eines Laptops erfasst, sondern als eigener Sachverhalt unter `Verbindung / Dienst`.

```text
Bekanntes Quell-Asset
IP-Adresse des Dienstes
Dienst oder Zweck
Protokoll
Port
Bekannte Gegenstelle
Verbindungsart
```

Die Dienst-IP kann mit bereits bekannten Asset-IP-Adressen korreliert werden. DHCP bleibt dabei als eigener Kontextfaktor erhalten, sodass eine dynamische Übereinstimmung von einer stabilen Zuordnung unterschieden werden kann.

## Audit und Risiko

Nur die Finding-Art `Audit / Risiko` verwendet Bewertungsfelder:

```text
Erfassungsstand
Relevanz
Status
Empfehlung / nächste Aktion
```

Für alle anderen Finding-Arten gelten feste Werte:

```text
Erfassungsstand: Beobachtet
Relevanz: Dokumentation
Status: Erfasst
Empfehlung: leer
```

## Automatische Bezeichnungen

Finding-Bezeichnungen werden beim Speichern automatisch erzeugt und nicht manuell eingegeben.

Beispiele:

```text
TCO-PC0055 erfasst
Netzwerk 20
HTTPS auf 192.168.10.25
Standort Gebäude A Raum 12
Audit / Risiko
```

Technische Finding-IDs bleiben intern erhalten, werden aber nicht in der Findings-Übersicht angezeigt.

## Assets und Netzwerkkarte

Assets und Netzwerkkarte verwenden keine automatisch erzeugten Finding-Texte als Objektnamen.

Die Bezeichnung eines Geräts wird in dieser Reihenfolge abgeleitet:

```text
1. Hostname
2. Hersteller und Modell
3. Gerätetyp
```

Ist Asset-Name und Hostname identisch, wird der Hostname in der Asset-Übersicht nicht doppelt dargestellt.

Netzwerkobjekte verwenden VLAN oder CIDR. Standorte verwenden Gebäude, Raum und Rack.

## Reports

NADA stellt drei Reportdateien bereit:

```text
Auditbericht:       audit-report.html
Gesamtdaten:        network-audit.json
Asset-Inventar:     exports/assets.csv
```

Vor jedem Download wird gefragt, ob ausschließlich der aktuelle Tenant oder zusätzlich alle lesbaren Sub-Tenants enthalten sein sollen.

```text
Nur dieser Tenant
Mit Sub-Tenants
```

Die Auswahl für den Download ist unabhängig vom aktuell eingestellten Seitenumfang. Der Report wird unmittelbar vor dem Download mit dem gewählten Umfang aktualisiert, sofern das Recht `Reports erzeugen` vorhanden ist.

## Anhänge und Tenant-Icons

Uploads sind ausschließlich zulässig als:

```text
Tenant-Icon
Anhang an einem Finding
```

Tenant-Icons:

```text
PNG oder JPG
maximal 2 MB
```

Finding-Anhänge:

```text
JPG
PNG
PDF
TXT
CSV
maximal 20 MB
```

Dateitypen werden anhand ihres Inhalts geprüft. Die Anwendung benötigt dafür keine optionale PHP-Erweiterung wie `fileinfo`.

## Rechte

Rechte werden pro Benutzer einzeln vergeben.

```text
Lesebereich
├── Alle Tenants
└── Bestimmte Tenants

Schreibbereich
├── Alle Tenants
└── Bestimmte Tenants

Zugriff
├── Findings
├── Reports erzeugen
├── Benutzerverwaltung
└── Tenantverwaltung
```

### Findings

Erlaubt das Anlegen, Bearbeiten und Löschen von Findings sowie das Anhängen von Bildern und Dokumenten in den freigegebenen Schreib-Tenants.

### Reports erzeugen

Erlaubt die Aktualisierung und den Download der Reports für die freigegebenen Schreib-Tenants.

### Benutzerverwaltung

Erlaubt das Anlegen, Bearbeiten und Löschen von Benutzern sowie die Vergabe ihrer Lese-, Schreib- und Verwaltungsrechte.

### Tenantverwaltung

Erlaubt:

```text
Tenants anlegen
Tenants bearbeiten
Tenant-Icons ändern
Tenants löschen
Tenant-Hierarchie verwalten
```

Ein Tenant mit vorhandenen Sub-Tenants muss von unten nach oben gelöscht werden.

## Lockout-Schutz

Existiert nur ein gültiger Benutzer ohne verwertbare Verwaltungsmarkierung, erhält dieser automatisch Benutzer- und Tenantverwaltung.

Falls mehrere alte Benutzer vorhanden sind und keine Benutzerverwaltung erreichbar ist, kann manuell folgende Datei angelegt werden:

```text
storage/global-admin.txt
```

Der Inhalt besteht ausschließlich aus dem exakten Benutzernamen:

```text
florian
```

Alte Benutzerformate und frühere Einzelrechte werden beim Lesen auf das aktuelle Rechtemodell abgebildet.

## Datenhaltung

```text
tenant/
└── <tenant-id>/
    ├── tenant.json
    ├── input/
    │   ├── assets.json
    │   ├── networks.json
    │   ├── connections.json
    │   ├── locations.json
    │   ├── findings.json
    │   ├── notes.json
    │   ├── tenant-icon/
    │   └── attachments/
    └── output/
        ├── network-audit.json
        ├── audit-report.html
        └── exports/
            └── assets.csv

storage/
├── users.json
├── audit.jsonl
├── revisions/
└── global-admin.txt
```

`input/` enthält die führenden Eingabedaten.

`output/` enthält reproduzierbare Ausgaben und kann aus dem aktuellen Kontext neu erstellt werden.

Vor Änderungen werden Revisionen angelegt. Schreibvorgänge erfolgen atomar und werden mit Dateisperren abgesichert.

## Start

Voraussetzungen:

```text
PHP 7.4 oder neuer
Standardfunktionen für JSON und Sessions
Schreibzugriff im Projektverzeichnis
Keine zusätzlich zu installierende PHP-Erweiterung
```

Repository bereitstellen:

```bash
git clone https://github.com/florianthepro/network-asset-documentation-audit.git
cd network-asset-documentation-audit
php -S 0.0.0.0:8080
```

Danach öffnen:

```text
http://localhost:8080
```

Beim ersten Aufruf wird der erste Administrator angelegt. Das Passwort muss mindestens zwölf Zeichen lang sein.

## Projekt-Index

Weitere bereitgestellte Projektinstanzen befinden sich im zentralen Projekt-Index:

```text
https://github.com/florianthepro/pages/tree/main/content/instances
```

[Projektinstanzen öffnen](https://github.com/florianthepro/pages/tree/main/content/instances)

## Schreibrechte des Webservers

Das Projektverzeichnis muss für den verwendeten Webserver-Benutzer beschreibbar sein, damit NADA Tenants, Eingabedaten, Revisionen, Icons, Anhänge und Reports anlegen beziehungsweise aktualisieren kann.

Vor der Ausführung muss `WEBROOT` auf das tatsächliche NADA-Verzeichnis gesetzt werden. Die folgenden Beispiele verwenden `/var/www/html`.

### Debian und Ubuntu

Webserver-Benutzer: `www-data`

```bash
sudo bash -c 'WEBROOT=/var/www/html; USER=www-data; chown -R "$USER:$USER" "$WEBROOT" && chmod -R u+rwX,g+rwX,o-rwx "$WEBROOT"'
```

### RHEL und CentOS

Webserver-Benutzer: `apache`

```bash
sudo bash -c 'WEBROOT=/var/www/html; USER=apache; chown -R "$USER:$USER" "$WEBROOT" && chmod -R u+rwX,g+rwX,o-rwx "$WEBROOT"'
```

Die Befehle entziehen allen anderen Benutzern den Zugriff auf das Verzeichnis. Der gewählte Pfad darf deshalb nur auf das gewünschte Webprojekt zeigen.

## Temporärer Apache-Test unter Windows

Die folgenden Befehle laden ein temporäres Apache-Testskript aus dem zentralen `pages`-Repository und führen es lokal aus.

### PowerShell

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/florianthepro/pages/main/content/loader/start_apache_temp.bat')"
```

### Eingabeaufforderung

```bat
curl -sS -o "%TEMP%\tmp_start.bat" "https://raw.githubusercontent.com/florianthepro/pages/main/content/loader/tmp-apache.bat" && cmd /c "%TEMP%\tmp_start.bat"
```

Die Testskripte werden direkt aus dem angegebenen Repository geladen und ausgeführt. Vor dem Einsatz sollte der Inhalt der jeweiligen BAT-Datei geprüft werden.

## Repository

```text
network-asset-documentation-audit/
└── index.php
```

Die zur Laufzeit benötigten Verzeichnisse und Dateien werden von `index.php` selbstständig erstellt.

## Sicherheit

```text
Tenant-IDs werden validiert
Pfadwechsel außerhalb der Tenant-Struktur werden blockiert
Formulare verwenden CSRF-Schutz
Passwörter werden gehasht gespeichert
Sitzungen verwenden HttpOnly- und SameSite-Cookies
Lese- und Schreibrechte werden serverseitig geprüft
Uploads werden nach Größe und Dateisignatur geprüft
Änderungen werden protokolliert
Revisionen werden vor dem Überschreiben angelegt
Report-Downloads prüfen den Tenant-Zugriff
```

Für den produktiven Betrieb muss NADA hinter HTTPS betrieben werden. `tenant/` und `storage/` dürfen nicht direkt über den Webserver erreichbar sein.

## Abgrenzung

NADA führt keine selbstständigen Netzwerk-, Port- oder Schwachstellenscans aus.

Die Anwendung dokumentiert ausschließlich autorisiert und bewusst eingetragene Beobachtungen. Kontext wird aus diesen Angaben abgeleitet, nicht erfunden.

## Leitlinie

```text
Ein Skript.
Getrennte Kundendaten.
Ein Finding pro Sachverhalt.
Korrigierbarer Input.
Reproduzierbarer Output.
Kontext statt doppelter Datenpflege.
Keine unnötigen Abhängigkeiten.
Keine erfundenen Audit-Ergebnisse.
```
