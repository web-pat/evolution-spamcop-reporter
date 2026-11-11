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
| Scan stops on an oversized input | Review the source; export the problematic message separately. A source error aborts that source for this run; other sources continue. |
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
| Cleanup retains a draft | Resolve the draft/transport outcome first; active external work is excluded. |
| Timer cannot write custom data path | Update the service's Environment/ReadWritePaths, then daemon-reload. |

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
