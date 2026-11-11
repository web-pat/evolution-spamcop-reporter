# Evolution SpamCop Reporter

Lokale Spam-Erfassung, kontrollierte SpamCop-Einreichung und Auswertung für Linux
und GNOME Evolution. Python ab 3.12, Apache-2.0, keine Laufzeitabhängigkeiten.
[Ausführliche englische Dokumentation](README.md).

## Installation

Unter aktuellem Debian/Ubuntu:

```sh
sudo apt install python3 python3-venv pipx evolution
pipx ensurepath
```

Repository herunterladen/klonen, im Projektverzeichnis ausführen:

```sh
pipx install .
spamreporter init
```

Gegebenenfalls Terminal neu öffnen. Die private Konfiguration liegt unter
`~/.config/spamreporter/config.toml`, Daten unter `~/.local/share/spamreporter`.
XDG_CONFIG_HOME/XDG_DATA_HOME werden berücksichtigt. Konfiguration mit einem
Texteditor bearbeiten: persönliche `submit.*@spamcop.net`-Adresse, Versandidentitäten
und lokale Quellen eintragen. Rechte `0600` beibehalten. `config.example.toml`
enthält ausschließlich synthetische Beispiele. Dann `spamreporter doctor` aufrufen.

## Kontrollierter Ablauf

```sh
spamreporter ingest --file examples/synthetic.eml --source evolution
spamreporter analyze
spamreporter queue
spamreporter review HASH
```

`HASH` durch den vollständigen ausgegebenen SHA-256 ersetzen. Das Original liegt
nach `review` unter `~/.local/share/spamreporter/review/HASH.eml`. Zuerst prüfen:
Handelt es sich tatsächlich um unangeforderte Massenwerbung? Ein Spamordner allein
ist kein ausreichender Nachweis. Das synthetische Beispiel niemals real melden!

```sh
spamreporter queue HASH --source evolution --confirm-spam
spamreporter prepare --dry-run
spamreporter prepare
spamreporter send HASH --backend eml
spamreporter status --id HASH
spamreporter report --format html --output beobachtungen.html
spamreporter report --format csv --output beobachtungen.csv
```

Die fertige MIME-Einreichung liegt in `~/.local/share/spamreporter/outbox/HASH.eml`.
Sie enthält die Originalnachricht unverändert als `message/rfc822`-Anhang und gilt
weiterhin nur als vorbereitet. Pro Einreichung wird eine Nachricht verwendet;
50.000 Byte inklusive MIME-Hülle werden geprüft. Es wird nichts abgeschnitten.

Für echte, geprüfte Nachrichten wahlweise:

* `send HASH --backend evolution --confirm`: Composer öffnen. Identität, Anhang,
  MIME-Typ und endgültige Größe prüfen, danach selbst senden. Evolution kann die
  MIME-Struktur neu serialisieren und Signaturen ergänzen.
* `send HASH --backend sendmail --confirm`: nur nach `allow_send=true`; separat
  eingerichteten lokalen Mailtransport verwenden. Kein eigener SMTP-Client.

Eine Transportübergabe ist weder Zustellnachweis noch abgeschlossener Abuse-Report.
SpamCop sendet beim regulären Workflow Links zur manuellen Prüfung/Bestätigung.
Antwort und Abschluss können mit lokalen Belegen manuell dokumentiert werden;
siehe [SpamCop setup](docs/spamcop-setup.md). Unklare Versandfehler werden nicht
automatisch wiederholt. Ein geöffneter Entwurf sperrt weitere Versandversuche.

## Evolution und mehrere Quellen

In einem passenden Evolution-Filter **An Programm weiterleiten / Pipe to Program**
mit dem absoluten Programmpfad konfigurieren:

```text
/home/DEIN-BENUTZER/.local/bin/spamreporter ingest --stdin --source evolution
```

Den tatsächlichen Pfad zeigt `command -v spamreporter`. Der Aufruf speichert nur
lokal; Analyse und Versand blockieren Evolution nicht.

**Automatische IMAP-Filter betreffen neue Nachrichten im Posteingang.** Serverseitig
befüllte Spamordner benötigen manuelles Anwenden mit Strg+Y oder einen lokalen
Export. Evolution-IMAP-Caches sind kein Maildir. Ein direkter Camel-Adapter wird
mangels verifizierter sitzungsübergreifender Integration nicht angeboten.

Beliebig viele EML-, echte Maildir- und statische mbox-Quellen sind konfigurierbar.
`spamreporter scan` liest sie ausschließlich; Originale werden niemals geändert
oder gelöscht. `analyze` ergänzt lokale Statistiken. Weiterleitungen können über
exakte vertrauenswürdige Servernamen und IP-Netze beschrieben werden. Unklare
Received-Ketten bleiben unbekannt; SPF/DKIM/DMARC sind ungeprüfte Headerangaben.
ASN-Daten können aus einer lokalen CSV geladen werden, ohne Netzwerkabfragen.

## Automatisierung und Datenschutz

Die Dateien unter `systemd/` nach `~/.config/systemd/user/` kopieren, dann:

```sh
systemctl --user daemon-reload
systemctl --user enable --now spamreporter-scan.timer
```

Voraussetzung: `init` wurde ausgeführt, Standard-Datenpfad und pipx-Installation.
Der Timer erfasst, analysiert und bereinigt alle 30 Minuten; er meldet nichts.
Ein automatischer Transport bereits geprüfter Nachrichten braucht zusätzlich
globale und quellenspezifische Freigabe. Alte Nachrichten werden nie automatisch
als Spam freigegeben.

`cleanup --dry-run` zeigt abgelaufene Daten, `cleanup` entfernt sie und behält
Fingerprints gegen Doppelmeldungen. `cleanup --purge-all --confirm` löscht auch
diese Historie. Aktive Entwürfe/Übergaben vorher klären. Externe Exporte und Backups
separat löschen. Berichte enthalten keine persönlichen Mailadressen, aber IPs und
lokale Beobachtungen; sie sind keine weltweite Spamstatistik.

Keine Telemetrie, keine externe Analytik, keine Ausführung von Anhängen.
Weitere Hinweise: [Architektur](docs/architecture.md),
[Evolution-Einrichtung](docs/evolution-setup.md), [Datenschutz](docs/privacy.md),
[Fehlersuche](docs/troubleshooting.md).
