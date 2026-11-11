# Evolution SpamCop Reporter

Local-first spam review, SpamCop email submissions and mailbox-level analytics
for Linux and GNOME Evolution. Python 3.12+, Apache-2.0, no runtime dependencies.

[Deutsche Anleitung](README.de.md) · [Architecture and research](docs/architecture.md)

## What works

* Binary stdin from Evolution **Pipe to Program**, EML files/directories, genuine
  Maildir folders, and static mbox exports. Originals are read-only.
* SQLite content fingerprints, separate delivery records, transactional preparation,
  audited states and crash-aware transport claims.
* Exact original bytes embedded as `message/rfc822`; conservative 50,000-byte limit
  including MIME overhead. One original per submission, no truncation.
* Offline EML export, interactive Evolution drafts, or explicitly enabled local
  sendmail-compatible transport. No Python IMAP, POP3 or SMTP client.
* Conservative Received-chain analysis, optional offline ASN CSV, HTML/CSV/terminal
  observations, private storage and retention with deduplication tombstones.

Scanning **never sends or approves spam**. A junk-folder location is not proof of
unsolicited bulk email. Every candidate needs explicit review before queueing.
Submission to SpamCop's parser is distinct from completing an abuse report.

## Install

On a current Debian/Ubuntu system with Python 3.12 or newer:

```sh
sudo apt install python3 python3-venv pipx evolution
pipx ensurepath
```

Download/clone this repository, open a terminal in its directory, then:

```sh
pipx install .
spamreporter init
```

Restart your terminal if `spamreporter` is not yet on PATH. Fedora users can install
`python3`, `pipx` and `evolution` using `dnf`. No privileged installation of this
application is needed. For an update from a newer checkout: `pipx install --force .`.

Edit `~/.config/spamreporter/config.toml` with a text editor. Keep its permissions
at `0600`. Set your sender identity and confidential SpamCop `submit.*` address;
enable only the sources you intend to inspect. `config.example.toml` explains the
settings. XDG_CONFIG_HOME and XDG_DATA_HOME are honored; `--config PATH` overrides
the config location. A custom `data_dir` should be a dedicated private directory.

```sh
spamreporter doctor
spamreporter --help
```

`doctor` reports missing submission settings until you configure them; offline
capture and analysis work even without a SpamCop account.

## First offline walkthrough

Use the synthetic sample only offline. Never actually submit it to SpamCop.

```sh
spamreporter ingest --file examples/synthetic.eml --source evolution
spamreporter analyze
spamreporter queue
```

The import prints a full SHA-256 fingerprint. Below, replace `HASH` with that value.
`review` exports the unchanged original under
`~/.local/share/spamreporter/review/HASH.eml`. Inspect it as plain text or using
Evolution with remote content disabled. Do not execute attachments.

```sh
spamreporter review HASH
# For the offline sample this simulates the review decision; use genuine review for real mail.
spamreporter queue HASH --source evolution --confirm-spam
spamreporter prepare --dry-run
spamreporter prepare
spamreporter send HASH --backend eml --dry-run
spamreporter send HASH --backend eml
spamreporter status --id HASH
spamreporter report
spamreporter report --format html --output observations.html
spamreporter report --format csv --output observations.csv
```

The submission is now `~/.local/share/spamreporter/outbox/HASH.eml`, still in
`prepared` state, **not sent**. Output files are private and never overwritten.
Synthetic documentation IPs intentionally produce unknown origin attribution.

For real spam after reviewing originals:

```sh
# Opens a composer; manually verify identity, attachments, MIME type and final size.
spamreporter send HASH --backend evolution --confirm
# Alternative: after explicitly setting allow_send=true and configuring the local MTA:
spamreporter send HASH --backend sendmail --confirm
```

Choose one delivery method per submission. Once a composer has opened or a
transport has accepted work, the same submission cannot be sent again by the CLI.
See [SpamCop setup](docs/spamcop-setup.md) for evidence recording and failure recovery.

## Evolution and local sources

Set an Evolution filter's **Pipe to Program** action to the installed executable:

```text
/home/YOUR-USER/.local/bin/spamreporter ingest --stdin --source evolution
```

Use your own absolute path (`command -v spamreporter`). The command only captures
bytes locally and returns; analysis and transport happen later.

**Automatic IMAP filters apply to new Inbox messages, not arbitrary server-filled
junk folders.** For these folders select messages and apply filters manually with
Ctrl+Y, or export messages to a configured local source. Do not point a Maildir
adapter at Evolution's IMAP cache. Offline synchronization does not change that.
Detailed instructions: [Evolution setup](docs/evolution-setup.md).

```sh
spamreporter scan
spamreporter analyze
```

Any number of sources may be configured. A delivery belongs to its source; identical
bytes share one fingerprint and one submission, even across mailboxes. Different
delivery headers produce different fingerprints. Sender Message-ID is not an identity.

## Automation and retention

The supplied systemd user timer scans, analyzes and expires data every 30 minutes.
It does not queue or send anything. Run `init` first, then:

```sh
mkdir -p ~/.config/systemd/user
cp systemd/spamreporter-scan.* ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now spamreporter-scan.timer
systemctl --user list-timers
```

The service assumes pipx's `~/.local/bin/spamreporter` and the default data path.
For custom XDG/data paths, edit `ExecStart`, `Environment` and `ReadWritePaths`
using `systemctl --user edit spamreporter-scan.service`. A graphical session is
unnecessary for scan/analysis. For trusted unattended transport of **already
reviewed** items, set `allow_send=true`, `allow_automatic=true`, and the relevant
source's `auto_submit=true`, then run `prepare` and `send --backend sendmail
--automatic` from your own job. There is no automatic spam-classification shortcut.

```sh
spamreporter cleanup --dry-run
spamreporter cleanup
```

Expired originals, metadata, evidence and managed exports are removed; fingerprints,
delivery identifiers and state history remain to prevent repeat submissions.
When copies belong to multiple sources the longest retention applies. Active drafts
and uncertain in-progress handoffs are retained until resolved. Reports you exported
elsewhere and backups need separate deletion. `cleanup --purge-all --confirm`
erases all database records and managed exports, **including deduplication history**.

## Limits and trust

* No direct Camel/EDS cache adapter or native extension in v1; see feasibility research.
* Evolution generates its own final MIME and may add signatures. Its draft backend
  needs local GUI verification; exact size and serialization guarantees apply to
  the stored EML/sendmail payload, not a subsequently edited composer message.
* Local MTA success means handoff, not delivery or SpamCop completion. Ambiguous
  timeouts/crashes/nonzero exits are never automatically retried.
* Received IPs are trust-boundary candidates. Missing or unverifiable chains are
  unknown; authentication headers are unverified claims. ASN mappings are local,
  administrator-supplied observations, not authoritative attribution.
* Standard reports omit personal addresses, subjects, full headers and tokens and
  pseudonymize domains. They still contain potentially sensitive IPs and counts.
* No Quick Reporting, undocumented browser automation or automatic final confirmations.

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Tests use synthetic messages and mocked outbound transports. CI covers Python
3.12–3.14. See [CONTRIBUTING](CONTRIBUTING.md), [privacy](docs/privacy.md),
[troubleshooting](docs/troubleshooting.md), and [SECURITY](SECURITY.md).
This project is independent of GNOME, Cisco and SpamCop.
