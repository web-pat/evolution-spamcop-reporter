# Privacy and data lifecycle

No telemetry, remote images, attachment execution, DNS resolution, external ASN
services, tracking pixels or web requests occur in application code. The only
outbound route is a deliberately invoked Evolution composer or configured local
mail transport. Full originals are sent only to the configured regular SpamCop
submission address. SpamCop's own subsequent processing/reporting is a separate
disclosure which you must review in its interface.
When using Evolution, check and remove any account-default CC/BCC recipients before
manually sending; composer defaults are controlled by Evolution, not this application.

The XDG data directory contains private SQLite BLOBs (complete original mail and
prepared envelopes), delivery records, metadata, state events and optional evidence.
The database therefore contains addresses, message IDs, Received headers and body
data even though standard reports omit them. Config holds the confidential SpamCop
token and source/identity mappings. Protect both with device encryption and private
backups. The application enforces 0700 storage directories, 0600 database/config and
new output files; CLI umask is 0077. Symlink inputs/exports are rejected. Do not put
the database on a shared or network filesystem: SQLite WAL needs reliable local
locking. The same Unix user remains trusted; this is not a hostile-user sandbox.

Standard logs show fingerprints, source labels and states, not original content or
tokens. Source labels must be non-personal identifiers. Reports omit full addresses,
subjects, IDs and raw header chains; domains are deterministic SHA-256 pseudonyms.
Those pseudonyms are not anonymization against dictionary guessing. IPs, timestamps,
operators and counts can remain sensitive. Reports describe captured mailboxes only.
HTML escapes text and has no active/external content. CSV protects against formula
injection; terminal output removes control sequences.

`cleanup` applies per-source retention (longest retention for shared originals).
It removes original/prepared/evidence BLOBs, metadata and managed exports but keeps
fingerprints, hashed delivery keys, source labels, timestamps and state audit events
to prevent duplicates. Reimporting an expired fingerprint does not restore its
contents or make it eligible for submission. Active editor/transport states are
retained so cleanup cannot remove data being used by an external process.

`cleanup --purge-all --confirm` removes all records and managed EML exports, and
compacts/checkpoints the database. It refuses active drafts/transport claims.
Deduplication history is then gone: future scans can capture old source mail again,
but still cannot approve or send it automatically. The private configuration is
not deleted by this command. To fully uninstall local data, stop the timer and all
application/editor processes, remove the dedicated config/data directories, and
remove external reports and backups yourself. Original Evolution/source mail is
always outside this application's deletion scope.

SQLite secure_delete and WAL checkpointing reduce ordinary recoverable remnants;
they do not promise physical erasure on SSDs, snapshots or backups. Use encryption
and your storage system's deletion procedures where necessary. Exported files outside
the managed directories are never automatically deleted.
