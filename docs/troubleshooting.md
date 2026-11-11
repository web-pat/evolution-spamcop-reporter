# Troubleshooting

Start with `spamreporter doctor`, `status`, and `status --id HASH`. Never paste your
SpamCop token, full config, personal headers or originals into a public issue.

| Symptom | Action |
| --- | --- |
| Command not found | Restart terminal after `pipx ensurepath`; use `command -v spamreporter`. |
| `ensurepip` unavailable | Install your distribution's matching `python3-venv` package. |
| Missing config | Run `init`; global `--config` belongs before the subcommand. |
| Permission failure | Dedicated config file/database need 0600; storage directory needs 0700. |
| Doctor says no submit identity | Set a regular submit token and the source's `[identities]` mapping. Capture still works offline. |
| Server-side Spam folder not imported | Apply filters manually (Ctrl+Y) or export; automatic IMAP filtering is Inbox-only. |
| Filter doesn't execute | Check absolute path, source name, permissions and Flatpak restrictions. Use Pipe to Program, not Run Program. |
| Maildir scan sees nothing | Confirm real cur/new/tmp layout. Never point it at an IMAP cache. |
| Scan reports skipped inputs | Unreadable, empty, changing or oversized files are skipped individually. Other files/sources continue; exit 2 means partial failure. The user service accepts 2 and continues analysis/cleanup. |
| Repeated scan reaches limit | The limit counts newly observed deliveries; known files are read/hashed but do not consume the limit. |
| Changed source trust configuration | v1 analyzes captured messages; existing observations are historical. Use a separate test data directory to validate new trust rules before production. |
| Unknown IP/ASN | Expected unless a topmost receiver is explicitly trusted, the chain is parseable, and a public peer exists. ASN requires a local CSV mapping. |
| `manual_review` after analysis | Malformed MIME/header structure was detected; inspect original. v1 does not automatically waive defects or alter the original. |
| No entry after prepare | Check `status --id HASH`: size/format/settings problems become manual_review. Dry-run prints only valid candidates and changes nothing. |
| Prepared but not sent | Correct for EML output. Use one explicitly selected delivery backend. |
| Evolution attachment missing | Verify path permissions/sandbox access and the composer warning. The GUI must be reviewed locally. |
| `error` after send | Executable failed to start; fix it, then explicitly retry. |
| `manual_review` or `handing_off` after send | Outcome uncertain. Check MTA logs and replies. Never blindly resend. |
| SQLite busy | Wait for the other writer; check local filesystem locking. CLI waits up to 15 seconds. |
| Report output exists | Choose a new filename or remove the prior export yourself; no implicit overwrite. |
| Cleanup retains a draft | Resolve the draft/transport outcome first. For a verified discarded unsent draft, record `cancelled` with evidence and `--attest`; this does not enable resending. |
| Timer cannot write custom data path | Update the service's Environment/ReadWritePaths, then daemon-reload. |
| stdin no longer prints a fingerprint | Intentional: Camel consumes stdout as replacement email. Use `queue` or `status` to drain intake and inspect IDs; file imports still print IDs. |
| Pending intake files | A normal command or the timer imports `.json` records. Unreadable records and interrupted `.tmp` writes are retained; inspect privately with the filter stopped. |
| Missing data after changing directories/upgrading | TOML paths now resolve beside the config. If previously relative, point data_dir to the existing absolute database directory before upgrading. |
| ASN table rejected | Use exactly `network,asn,operator` columns and complete rows with CIDR networks and AS-number values. Errors report a line number without echoing private contents. |
| Historical statistics disappeared | Default retention removes them. Enable `retain_statistics=true` before expiry for report-safe snapshots; already deleted observations cannot be restored. |

`journalctl --user -u spamreporter-scan.service` shows timer results. It does not
contain raw message content. `systemctl --user disable --now spamreporter-scan.timer`
stops periodic scans. No persistent daemon needs to be killed.

## Local integration checks before real use

With synthetic messages and offline/isolated transport, verify stdin import preserves
full headers, Maildir flag changes do not duplicate deliveries, generated attachment
bytes match the imported file, Evolution opens the intended recipient and attachment,
and your MTA honors explicit envelope recipients. Do not send test messages to SpamCop.
The automated suite mocks outbound processes; it does not claim that a GUI or real
mail transport was exercised on every distribution.
