# Architecture and feasibility investigation

Research date: 2026-11-11. Online documentation was consulted before implementation.
The published Camel reference currently identifies itself as 3.63.1 (development);
distribution packages can be older. This project requires Python 3.12+, not GI.

## Evidence and decisions

* [Evolution filter actions](https://gnome.pages.gitlab.gnome.org/evolution/help/mail-filters-actions.html)
  documents **Pipe to Program** as sending the message to an external application.
  `ingest --stdin` reads bytes, hashes and commits them locally; no MIME analysis,
  network activity or transport occurs on the filter path. Return status is not a
  reliable Evolution retry mechanism: check imports during setup.
* [Using filters](https://gnome.pages.gitlab.gnome.org/evolution/help/mail-filters.html)
  explicitly restricts the IMAP automatic option to new Inbox messages. Server-side
  junk folders need manual Select All / Apply Filters (Ctrl+Y), or an export.
  Enabling offline synchronization alone does not trigger this application's scan.
* Genuine Maildir `cur`/`new` are read recursively; `tmp` and symlinks are excluded.
  The IMAP cache is **not** a Maildir. No cache databases are inspected or edited.
  EML is a portable byte-preserving interchange. Static mbox exports are supported
  as a convenience; mbox separators and mboxrd escaping are container conventions,
  so export fidelity must be checked. Do not scan a concurrently written mbox.
  [Evolution export help](https://gnome.pages.gitlab.gnome.org/evolution/help/mail-save-as-pdf.html)
  documents mbox as the default drag-and-drop format (not EML).
* [Camel API](https://gnome.pages.gitlab.gnome.org/evolution-data-server/camel/)
  provides MIME, session, store and folder objects, exposed in GI-capable builds.
  PyGObject/typelib availability varies by distribution. This is a library, not an
  IPC service granting access to the running Evolution mail session. EDS address
  book/calendar services must not be mistaken for a mail-access service.
  [get_message_cached](https://gnome.pages.gitlab.gnome.org/evolution-data-server/camel/method.Folder.get_message_cached.html)
  (since 3.24) explicitly avoids network I/O and returns NULL for absent bodies;
  `get_message_sync` is not a cache-only guarantee. Creating an independent store
  against Evolution's cache introduces locking/version/ownership concerns.
  No reliable standalone read-only GI integration was established; none is claimed.
  A future native Evolution module could obtain the existing session/folder,
  enumerate UIDs, call get_message_cached, and pipe bytes to this application.
  It needs integration tests against supported Evolution releases and must skip
  uncached messages rather than fetching them. No native module is needed for v1.
* The [Evolution manual](https://manpages.debian.org/testing/evolution/evolution.1.en.html)
  documents `evolution MAILTO` for opening a composer, not unattended sending.
  The [GNOME maintainer explanation](https://mail.gnome.org/archives/evolution-list/2012-May/msg00187.html)
  confirms the Evolution-specific `attach=` extension and attachment checks;
  [2018 usage](https://mail.gnome.org/archives/evolution-list/2018-October/msg00091.html)
  confirms it. Paths and fields are URL encoded. It is not an RFC-standard mailto
  attachment API. Desktop sandbox/path access and attachment acceptance must be
  tested locally. The application attaches original EMLs, not the submission as
  a nested wrapper. Identity, attachment MIME type and final size require review
  in the composer; Evolution may add signatures or reserialize the message.
  EML output and local sendmail provide exact pre-built MIME alternatives.
  Current upstream [e-msg-composer.c](https://github.com/GNOME/evolution/blob/master/src/composer/e-msg-composer.c)
  was also inspected: its MAILTO parser still accepts `attach`/`attachment`, URL-decodes
  paths, checks file existence, loads attachments asynchronously and warns about
  blacklisted paths. Its blacklist exempts XDG data/cache/config base directories.
  This confirms the extension remains implemented, not just historically described.
* [SpamCop email submission](https://www.spamcop.net/fom-serve/cache/166.html)
  specifies at most 20 messages and 50 KB overall. We conservatively use 50,000
  bytes, including MIME headers/boundaries. The workflow prepares one original
  per submission, deliberately trading batching for simpler recovery and review.
  The reusable builder supports 1–20. Nothing is truncated.
  [Reporting rules](https://www.spamcop.net/fom-serve/cache/125.html) prohibit
  material modifications and require unsolicited bulk email, not just a junk flag.
  Email submission yields parsing links; it is not proof of abuse-report completion.
* Quick reporting has historical [staff documentation](https://forum.spamcop.net/topic/163-faq-entry-what-is-quick-reporting)
  requiring Mailhosts and individual approval. [2023 discussion](https://forum.spamcop.net/topic/72529-any-way-to-automate-spam-reporting-from-email-client)
  shows account-dependent availability. Current universal entitlement cannot be
  verified. v1 accepts only `submit.*@spamcop.net`, never Quick or web automation.
  No universal daily quota was established; account restrictions still apply.

## Components and persistence

`inputs` → `store` (fast ingest) → `analysis` → explicit review/queue →
`submission` → `transports`; `reporting` reads metadata. `config` and `cli`
coordinate them. Standard library only at runtime. SQLite holds original BLOBs,
metadata, separate deliveries, immutable prepared payloads, attempts and events.
SHA-256 is the global content identity, not Message-ID. Different bytes, including
different Received headers, remain different messages; no speculative fuzzy dedup.
Delivery keys distinguish source/path/UID and content; repeated stdin with no UID
uses the fingerprint, since identical delivery events cannot otherwise be inferred.
Maildir flags and new→cur renames do not create new deliveries.

SQLite WAL, busy timeout and BEGIN IMMEDIATE serialize state transitions. A unique
submission per fingerprint prevents concurrent preparation. Original and submission
bytes are stored in the transaction, avoiding database/filesystem split commits.
Private export files are materialized only on request.

States: captured → analyzed → queued → prepared → handing_off → handed_off →
response_received → completed. `draft_opened`, `error`, `manual_review` are separate.
Every transition is audited. Completion/response records require a local evidence
file and explicit human attestation; the application does not authenticate SpamCop
replies or claim machine verification. Evidence hashes and bytes are retained.

Exactly-once delivery across a process and an external MTA is impossible without
an idempotent transport protocol. The claim is committed **before** invoking the
transport. An interrupted claim stays handing_off; timeout/nonzero exit becomes
manual_review, never automatically retried. Only failure to start the executable
is safely retryable (`send --retry`). Resolve ambiguous outcomes by checking local
MTA logs and recording evidence, not by blindly resending. Editor launch also
claims the submission permanently until the user records what happened.

Queueing always requires explicit message IDs and confirmation of spam review.
Automatic transport means delivery of already reviewed queued items only, with
global and per-source opt-ins and a rolling daily attempt limit. Scanning never
queues old or new messages automatically. Each prepare/send invocation is bounded.

## Trust model

Received analysis starts at the topmost hop, requiring an exact configured `by`
host. Forwarder continuation additionally requires the observed peer IP to match
the configured IP networks for that exact next host. Stop at the first untrusted
public peer; that is a *boundary candidate*, not a proven originating computer.
Missing, private, ambiguous or broken chains produce unknown. A configured trust
anchor assumes the source really came through that receiving server; headers alone
cannot prove this. Never follow an arbitrary lower header because its `by` looks
familiar. SPF/DKIM/DMARC are stored as unverified header claims, not recomputed.
ASN lookup is optional local CSV longest-prefix matching with provenance. No DNS,
HTTP, ASN service, telemetry or other networking is performed by the application.
