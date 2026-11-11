# SpamCop and transport setup

1. Register directly with SpamCop and obtain your personal **submit** address.
2. Configure all your receiving/forwarding paths using SpamCop Mailhosts, including
   every original address forwarded into a shared mailbox. Carefully inspect initial
   parser results so your own providers are not mistaken for the spam origin.
3. Put the address in the private TOML `recipient`; set `[identities]` for each source.
4. Start with offline EML output. Review actual unsolicited bulk mail individually
   with `review HASH`, then explicitly queue the fingerprint and source.

Official sources, checked 2026-11-11:

* https://www.spamcop.net/fom-serve/cache/166.html — email submissions, 20 messages,
  50 KB total, replies with already-authorized parser links.
* https://www.spamcop.net/fom-serve/cache/125.html — what qualifies, full headers,
  no material changes, and consequences of misreporting.
* https://www.spamcop.net/fom-serve/cache/397.html — Mailhosts and forwarding.

The application conservatively caps each fully serialized submission at 50,000
bytes, budgeting for LF-to-CRLF transport expansion while preserving original bytes.
v1 produces one original per envelope, never truncates a message, and stops
oversized or binary/non-line-oriented messages for manual review. The original
attachment bytes are not parsed and reserialized during construction. Base64 is
not used for the `message/rfc822` container because RFC 2046 disallows it; existing
encodings *inside* the original are untouched. Local MTA processing can normalize
line endings or add outer transport headers; test your transport's behavior.
The 50,000-byte check covers the generated message after potential line-ending
normalization, not headers later added by MTAs.
Keep reasonable headroom if a transport adds substantial headers.

Account-specific rate/age restrictions can also apply. Do not submit old backlog
blindly; check current SpamCop policy and parser feedback. The local default is a
rolling limit of 20 transport/editor attempts per 24 hours, including failed attempts.
It is a local guardrail, not an assertion of your SpamCop account's quota.

## Local sendmail

Install and configure a trusted sendmail-compatible local MTA separately. It may be
a system MTA or a wrapper such as msmtp; credentials belong to that transport, not
this repository. Configure an argument array, for example:

```toml
backend = "sendmail"
allow_send = true
sendmail = ["/usr/sbin/sendmail", "-i"]
```

The application appends `--` and the single configured envelope recipient. Do not
configure `-t`, additional recipients, a shell pipeline or credentials in this array.
The generated From header uses the source's identity. Configure the MTA's envelope
sender/account separately if required (a reviewed wrapper can select by From).
Verify support for `--`, `-i`, 8-bit MIME and your envelope policy locally.

```sh
spamreporter send HASH --backend sendmail --confirm --dry-run
spamreporter send HASH --backend sendmail --confirm
```

Dry-run validates permissions and readiness but invokes no executable or export.
Exit status zero means only **handed to local transport**. Delivery bounces and
SpamCop replies arrive through your regular Evolution account. No mailbox polling
or own SMTP client is used.

## Response and completion evidence

Regular submit processing sends a parser link. Open it yourself, verify the proposed
targets, and decide whether to send abuse reports. No web forms are automated.
Keep the response EML and, after actual completion, a local record of the confirmed
report IDs/result. Record these only after checking authenticity and correspondence:

```sh
spamreporter status --id HASH --record response_received --evidence reply.eml --attest
spamreporter status --id HASH --record completed --evidence completion.txt --attest
```

The database stores the evidence bytes and SHA-256 plus a human-attested audit
event. The CLI does not authenticate SpamCop responses or infer completion from a
subject line. `completed` means you have explicitly supplied and verified proof.
For a manually sent Evolution draft, first record `handed_off` with sent-folder/MTA
evidence, then the reply and completion. A prepared EML or opened editor is not proof.
The same `handed_off` evidence command works for an EML exported by the application
and subsequently sent using an external tool. It then blocks additional transport
handoffs. For exports made by the original release, re-run the offline EML export
command to register that export before recording evidence; it does not send mail.

## Recovery

* Failure to start the transport produces `error`; after correcting the executable,
  `send HASH --backend sendmail --confirm --retry` is permitted.
* Timeout or nonzero exit produces `manual_review`: the transport may already have
  accepted mail. A crash leaves `handing_off`. These are never retried automatically.
* Inspect MTA logs and SpamCop replies. If handoff is established, record it with
  evidence. Do not reset SQLite state manually to force a resend.
* A canceled/closed Evolution draft stays reserved until you explicitly record
  `cancelled` with a local note and `--attest`, having verified it was closed without
  sending. That terminal state allows retention cleanup but no resubmission.
  Never record cancellation while an editor or transport might still be using it.
* Expired unsent submissions become `expired`; older purged `prepared` records are
  also excluded from automatic selection. One unavailable automatic item does not
  prevent later eligible items being considered; failures remain visible in stderr
  and the exit status.

Quick Reporting is deliberately absent: historical staff guidance requires
Mailhosts and account-specific approval; current general eligibility could not be
verified. The config accepts only regular `submit.*@spamcop.net` addresses.
