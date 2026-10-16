next ist 64 dwl index file

# Network Asset Documentation & Audit

```text
Projektname: Network Asset Documentation & Audit
Repository: network-asset-documentation-audit
Kurzname: NADA
Einstiegspunkt: index.php
```

## Zielbild

NADA ist ein einzelnes PHP-Skript zur strukturierten Aufnahme, Korrektur und Auswertung physischer und digitaler Netzwerkbestandteile bei mehreren Kunden.

Während der Bestandsaufnahme entsteht aus denselben Eingabedaten automatisch eine saubere Netzwerkdokumentation mit Asset-Inventar, Tenant-Struktur, Netzwerkkarte und Auditbericht.

```text
Kunde
├── eigene Eingabedaten
├── eigene Ausgaben
└── Sub-Tenants
    ├── eigene Eingabedaten
    ├── eigene Ausgaben
    └── weitere Sub-Tenants
```

## Grundprinzip

Alles, was im Netzwerk physisch vorhanden oder digital erreichbar ist, wird als Asset oder zugehörige Netzwerkstruktur erfasst.

Dazu gehören unter anderem:

```text
Clients
Server
Switches
Router
Firewalls
Access Points
Drucker
NAS-Systeme
Kameras
Virtuelle Maschinen
Container
IP-Adressen
Webinterfaces
SSH-Dienste
Netzwerke und VLANs
Standorte, Räume und Racks
Patchfelder und Ports
Physische und logische Verbindungen
```

Die aufgenommenen Daten bleiben jederzeit änderbar. Automatisch erzeugte Ausgaben sind von den Eingabedaten getrennt und können vollständig neu erstellt werden.

## Tenant-Modell

Jeder Kunde ist ein eigener Tenant.

Ein Tenant kann beliebig viele Sub-Tenants besitzen, zum Beispiel für Tochtergesellschaften, Niederlassungen, Abteilungen, Geschäftsbereiche oder getrennte Kundenumgebungen.

Übergeordnete Tenants können wahlweise nur ihre eigenen Daten oder eine konsolidierte Sicht einschließlich aller Sub-Tenants anzeigen.

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
    │   └── attachments/
    └── output/
        ├── network-audit.json
        ├── audit-report.html
        └── exports/
            └── assets.csv
```

`input/` ist die führende und manuell korrigierbare Datenquelle.

`output/` enthält ausschließlich automatisch erzeugte Ergebnisse.

Vor dem Überschreiben einer Eingabedatei wird eine Revision unter `storage/revisions/` angelegt. Schreibvorgänge erfolgen atomar und werden über Dateisperren abgesichert.

## Funktionen

```text
Mehrere Kunden und verschachtelte Sub-Tenants
Asset-Inventar
IPv4, IPv6, MAC, VLAN, Gateway und DNS
Dienste und erreichbare Oberflächen
Standorte, Räume, Racks und Patchports
Netzwerke und Verbindungen
Audit-Findings mit Schweregrad und Empfehlung
Automatisch erzeugte SVG-Netzwerkkarte
Konsolidierter Auditbericht
JSON-, CSV- und HTML-Ausgaben
Dateianhänge
Änderungsrevisionen
Audit-Protokoll
Lokale Benutzeranmeldung
Dark-IT-Oberfläche
```

## Start

Voraussetzungen:

```text
PHP 8.1 oder neuer
PHP-Erweiterungen: JSON, Session, Fileinfo, mbstring
Schreibzugriff im Projektverzeichnis
```

Repository bereitstellen und starten:

```bash
git clone https://github.com/florianthepro/network-asset-documentation-audit.git
cd network-asset-documentation-audit
php -S 0.0.0.0:8080
```

Danach öffnen:

```text
http://localhost:8080
```

Beim ersten Aufruf wird der Administrator angelegt. Das Passwort muss mindestens zwölf Zeichen lang sein.

## Repository

```text
network-asset-documentation-audit/
└── index.php
```

Alle zur Laufzeit benötigten Verzeichnisse und Dateien werden von `index.php` selbstständig erstellt.

## Sicherheit

```text
Tenant-IDs werden strikt validiert
Pfadwechsel außerhalb des Tenant-Verzeichnisses werden blockiert
Formulare sind mit CSRF-Schutz versehen
Passwörter werden ausschließlich gehasht gespeichert
Sitzungen verwenden HttpOnly- und SameSite-Cookies
Uploads werden nach Größe und MIME-Typ geprüft
PHP-Ausführung in Datenverzeichnissen wird blockiert
Änderungen werden revisionssicher protokolliert
Ausgaben werden aus den Eingabedaten neu erzeugt
```

Für den produktiven Betrieb muss NADA hinter HTTPS betrieben werden. Das Webserver-Dokumentenverzeichnis darf nur `index.php` öffentlich ausliefern; `tenant/` und `storage/` dürfen nicht direkt erreichbar sein.

## Abgrenzung

NADA führt keine selbstständigen Netzwerk-Scans, Port-Scans oder automatischen Zugriffe auf Kundensysteme aus.

Das Werkzeug dokumentiert ausschließlich Daten, die autorisiert und bewusst eingegeben, importiert oder als Anhang hinterlegt wurden.

## Leitlinie

```text
Ein Skript.
Getrennte Kundendaten.
Korrigierbarer Input.
Reproduzierbarer Output.
Keine unnötigen Abhängigkeiten.
Keine dekorative Oberfläche.
Keine erfundenen Audit-Ergebnisse.
```
