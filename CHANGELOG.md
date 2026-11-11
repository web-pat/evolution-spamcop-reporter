# Changelog

## Unreleased — Evolution stability fixes

* Corrected the Camel pipe contract: stdin capture is silent and durably spooled,
  independent of SQLite write locks; normal commands import pending records idempotently.
* Evolution launches no longer share sendmail's kill-on-timeout behavior. Tests now
  explicitly prevent accidental real Evolution launches.
* Replaced backtracking Received parsing with bounded tokenization, strict receiver
  matching and multicast rejection; structured header defects are now included.
* Moved analysis and MIME construction outside write locks, indexed delivery lookup,
  and bounded cleanup transactions. Schema 1 upgrades in place to schema 2.
* Isolated bad scan inputs; systemd continues after partial scan failure (exit 2).
* Excluded expired submissions from automatic sending; added explicit EML handoff
  evidence and terminal cancellation for verified discarded drafts.
* Accounted for CRLF expansion in submission size limits, including at handoff.
* Made configured relative paths config-relative and ASN CSV errors actionable.
* Added opt-in report-safe historical observations without changing default retention.

## 0.1.0 — 2026-11-11

* Documented Evolution/Camel feasibility and verified SpamCop email-submission limits.
* Added read-only stdin, EML, recursive Maildir and static mbox capture.
* Added SQLite fingerprints, delivery records, audit history and atomic transport claims.
* Added reviewed queue, byte-preserving MIME preparation, EML, Evolution draft and
  opt-in local sendmail backends, dry-run, rate limits and explicit evidence recording.
* Added conservative Received trust-chain analysis and offline ASN mappings.
* Added private HTML/CSV/terminal observations, XDG configuration, doctor and retention.
* Added scan-only systemd user automation, synthetic pytest tests and Ruff/CI checks.
* Known boundaries: no standalone Camel adapter, unattended Evolution send, Quick
  Reporting, automatic final confirmations or machine-authenticated completion evidence.
