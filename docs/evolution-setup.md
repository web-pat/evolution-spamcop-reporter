# Evolution integration

## Pipe to Program

1. Install with pipx and run `spamreporter init`. Configure a `kind="stdin"` source.
2. Find the absolute executable path with `command -v spamreporter`.
3. Evolution → Edit → Message Filters → Add. Select a narrow test condition first.
4. Choose **Pipe to Program**, not **Run Program**, as the action. Enter the absolute
   executable followed by `ingest --stdin --source evolution`.
5. Apply the filter to one synthetic message. Check `spamreporter status` and `queue`.
   Use `review HASH` to compare the original bytes/headers with your export.
6. Expand to your intended selection only after confirming the path and source.

For custom config paths, the global option comes first:
`spamreporter --config /absolute/private/config.toml ingest --stdin --source evolution`.
The executable reads binary stdin and durably spools it without accessing SQLite.
No parser, ASN lookup, composer or MTA is run on this path. **stdout remains empty**:
Camel uses non-empty stdout as a replacement message. Do not add `echo`, progress
output or a wrapper that prints to stdout. `ingest --file` continues to print an ID
for interactive use. `status`, `queue`, `scan`, `analyze` and other normal commands
drain the spool before working; the user timer also does this. Dry-run commands
do not drain it. Evolution's action discards stderr and does not reliably retry
failures, so verify capture counts and permissions after configuring it.

## IMAP junk folders and existing mail

The receiving-account option **Apply filters to new messages in Inbox on this
server** does not monitor arbitrary IMAP Junk/Spam folders. A server-side filter
may prevent those messages ever appearing in Inbox. For 3–4 junk folders, select
the desired messages and use Message → Apply Filters (Ctrl+Y). Applying the filter
repeatedly is safe for identical message bytes.

Alternatively, save selected messages as a static mbox export and configure an
mbox source, or use complete RFC 5322 EML files exported by another local tool.
Evolution's default drag-and-drop export is mbox. Do not merely rename an mbox
file to `.eml`; each file must contain exactly one RFC 5322 message for EML import.
An mbox export can normalize line endings and escaping; inspect your distribution's
export behavior before real submissions. Work from a completed, unchanging export.

For genuine Maildir directories, the scanner reads `cur` and `new`, including
nested folder Maildirs, skips `tmp` and symbolic links, and does not modify flags.
This is different from Evolution's private IMAP cache. Do not configure the cache
path, `folders.db`, or a Camel cache directory as a Maildir source.

## Composer backend

`spamreporter send HASH --backend evolution --confirm` uses Evolution's documented
MAILTO composer entry point and its maintainer-documented `attach=` extension.
It percent-encodes the exact private original EML path. The outer prebuilt submission
is not attached as a second-level wrapper. The original attachment remains on disk
until the outcome is recorded and its retention period expires.

The state becomes `draft_opened` when launch is requested without an immediate
error, never `handed_off`. This is not proof the editor or attachment loaded. When
Evolution is initially closed, its process may stay alive for the whole desktop
session; the launcher returns without killing it. There is no unattended send here.
Select the configured identity manually; automatic account selection is not claimed.
Verify the recipient, remove any automatically configured CC/BCC copies, and check
original Received headers, attachment MIME type
(`message/rfc822`), final encoded size ≤50 KB and absence of extra signatures.
If Evolution rejects the attachment or changes its representation, use the EML/local
sendmail fallback **before launching a draft**, or resolve the existing draft first.
An opened draft is intentionally not automatically reopened or re-sent.
After verifying a draft was closed/discarded without sending, record a local note:
`spamreporter status --id HASH --record cancelled --evidence note.txt --attest`.
The terminal `cancelled` state permits retention cleanup, but never an automatic retry.

## Distribution and sandbox differences

GI typelibs and Camel development packages vary; neither is needed by this project.
Flatpak Evolution may lack access to the pipx executable, host configuration or
private attachment path. Host filter execution is not assumed to work through a
sandbox. Test your actual installation; distro-packaged Evolution is the simplest
supported setup. This project does not change sandbox permissions automatically.
Headless systems can use EML or local sendmail. A future native module could export
cached folder messages using Evolution's existing session; see architecture.md.
