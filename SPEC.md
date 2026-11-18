# CL03 — wire format v1 (normative)

<!-- edition:begin -->

| | |
|---|---|
| **Specification** | v1.3 |
| **Wire format** | v1 |
| **Date** | 18 November 2026 |
| **As printed** | [PDF, A4](pdf/cl03-spec%20-%20v1.3%20-%20A4.pdf) · [PDF, Letter](pdf/cl03-spec%20-%20v1.3%20-%20Letter.pdf) |
| **Licence** | [CC BY 4.0](LICENSE) |

> This is the specification as printed. It is written in the repository of
> the CL03 implementation and published here unchanged, so "this repository"
> and "here" in it mean that repository. The files, tests and design
> documents it names (`ovcrypto/`, `vectors/`, `ios/`, `accounts/`, `DESIGN`,
> `docs/MANAGED-PKI.md`) and the findings of the 2026-11 audit it cites by
> number are that implementation's, and are not in this repository.

<!-- edition:end -->

This document specifies **CL03**, the Verifier's QR code and the validation
of it: §1-§11 are the credential's wire format, version 1. The offline
verification system that implements it, this repository with verify's offline
credential, pairing and key sync, is the CL03 implementation.

`ovcrypto/wire.py` is the reference implementation for §1-§11. Where this
document and that module disagree, the module is correct and this document
is a bug. `vectors/vectors.json` pins both against `ios/OfflineVerifierTests`.

**§12 and §13 are different, and knowingly weaker.** The ticket QR does not
pass through `wire.py`: it is built by `accounts/pairing.py` here and
`accounts/devices.py` in the `verify` deployment, and read by
`ios/OfflineVerifier/Net`. It has no vectors -- see §13.3 -- so for now this
document is the only thing holding the implementations together, which is the
reverse of the arrangement above. Treat a disagreement there as a question,
not as a settled answer. §19, the key file, has a reference,
`ovcrypto/keyfile.py`, with vectors, which OVX's reader (`ios/OVX/KeyFiles`)
agrees with. §14, the revocation feed, has a reference since the
2026-11 audit: `ovcrypto/feed.py`, with vectors (§14.3). §17, attachments and
their part symbols, has had one from the start: `ovcrypto/attachments.py`,
with vectors (§17.6).

All integers are **big-endian, unsigned** unless stated. All offsets are in bytes.

---

## 1. QR string

```
CL03:<base45>
```

`base45` is RFC 9285 over the payload of §2. Both the prefix and the Base45
alphabet lie inside the QR **alphanumeric** charset, so encoders must select
alphanumeric mode — byte mode would waste ~45% of the capacity budget.

An issuer writes `CL03:`, and it is the only marker a reader accepts.

`CL03:` is a marker, not necessarily the first thing in the string: a reader
trims ASCII whitespace (space, tab, CR, LF, VT, FF) from both ends, decodes
what follows the **first** occurrence of the marker, and ignores what
precedes it. verify prints `<transaction UUID>:CL03:<base45>`, so a plain
camera reads the UUID; a UUID cannot contain the marker, and Base45 can spell
it, which is why the first occurrence is the one. Nothing before it is signed, so a verifier that shows
it compares it with the credential's own claims (2026-11 audit, found with
F054: the reference required the marker first and refused what every phone
read).

Recommended: error-correction level **Q**, smallest version that fits, stamp
sized so that **module size ≥ 0.4 mm**. See `ovcrypto/qrsize.py`.

## 2. Payload

```
offset  size  field
------  ----  -------------------------------------------------------------
     0     4  magic         "CL03" (0x43 0x4C 0x30 0x33)
     4     1  version       0x01
     5     1  suite         0x01 = X25519 / HKDF-SHA256 / AES-256-GCM
     6     1  flags         see §2.1
     7     4  epoch         audience key epoch
    11    32  ephPub        X25519 ephemeral public key
------------  header ends at 43; the whole header is AEAD associated data
    43     2  pubLen
    45     N  pubCT         AES-256-GCM ciphertext of §3
        16    pubTag
              --- the following present iff flags bit 1 ---
           2  resLen
           N  resCT         AES-256-GCM ciphertext of §4
          16  resTag
```

No trailing bytes are permitted. A parser MUST reject a payload with any.

### 2.1 flags

| bit | mask | meaning |
|---|---|---|
| 0 | 0x01 | public-section claims are raw-DEFLATE compressed |
| 1 | 0x02 | restricted section present |
| 2 | 0x04 | restricted-section claims are raw-DEFLATE compressed |

Bits 3–7 are reserved and MUST be zero, and bit 2 MUST NOT be set without
bit 1; a parser refuses a payload with either. Compression is applied per
section and
kept **only when it reduces size** — much of this payload is hashes and UUIDs,
which expand under DEFLATE. "Raw" means `wbits = -15`: no zlib header, no
adler32 (Apple's `COMPRESSION_ZLIB` is the same format).

A compressed section MUST be one complete raw-DEFLATE stream with nothing
after it, and MUST inflate to at least 1 byte and at most 1 MiB (1,048,576
bytes). Anything else is `malformed`, a stream RFC 1951 forbids included.
The cap guards against a section that inflates to tens of megabytes; a section
past it is refused, never cut to it, since a cut at a claim boundary once read
as a smaller claim set that still verified (2026-11 audit, F089, F097).
DEFLATE's output is not canonical (two compressors write two streams for one
input), so whether a section is compressed, and how, is the issuer's choice; a
verifier holds the claims it inflates to, not the stream, to §5.

## 3. Public section plaintext

```
size  field
----  ----------------------------------------------------------------
   2  claimsLen
   N  claims       TLV, §5. Compressed iff flags bit 0.
  32  resHash      SHA-256 of the restricted section plaintext,
                   or 32 zero bytes when flags bit 1 is clear
   1  sigAlg       0x01 = ECDSA-P256-SHA256; 0x02 = Ed25519
   4  keyId        issuer key identifier
  64  sig          signature over §6
```

`resHash` covers the restricted section **as it appears on the wire before
encryption** — i.e. after any compression. With no restricted section it MUST
be 32 zero bytes, and a verifier refuses any other as `malformed`. It is what allows a device holding
only the public-tier key to verify the whole credential.

## 4. Restricted section plaintext

```
size  field
----  ----------------------------------------------------------------
   N  claims       TLV, §5. Compressed iff flags bit 2.
                   Length is implied by the ciphertext length.
```

## 5. Claims (TLV)

Standard form, for values shorter than 255 bytes (its length is never
0xFF):

```
   1  tag
   1  length
   N  value
```

Extended form, for values of 255..65535 bytes:

```
   1  0xFF
   1  tag
   2  length
   N  value
```

Claims MUST be serialised in **ascending tag order**, and a tag MUST NOT appear
twice. Both are required for the signature to be reproducible by a verifier.
The extended form is for values of 255 bytes or more and for nothing shorter,
the standard form for nothing longer, and 0xFF is never a tag. One claim set
has one encoding, and a parser refuses every other: claims out of order, a
repeated tag, a value in the other form, or 0xFF as a tag is `malformed`
(2026-11 audit, F081).

### 5.1 Public tier (0x01–0x3F)

| tag | name | encoding |
|---|---|---|
| 0x01 | credential_id | 16 bytes, UUID |
| 0x02 | doc_type | uint8 |
| 0x03 | doc_number | UTF-8 |
| 0x04 | document_hash | 32 bytes, SHA-256 of the document contents |
| 0x05 | issuer_id | UTF-8 |
| 0x06 | issued_at | uint32, unix seconds |
| 0x07 | expires_at | uint32, unix seconds |
| 0x08 | issuer_location | UTF-8 |
| 0x09 | transaction_type | UTF-8 |
| 0x0A | operator | UTF-8 |
| 0x0B | public_attachments | attachment list, §17.1 |

0x00 is no claim, in either tier. `credential_id` is REQUIRED: without it
nothing can revoke the credential.
`issued_at` and `expires_at`, when present, are exactly 4 bytes. A verifier
refuses a credential that breaks either as `malformed` (2026-11 audit, F054,
F097).

**`doc_type` is opaque.** It is a `uint8` and this specification does not
define what any value means. There is no registry, and a verifier MUST NOT
render one as a document name. An earlier build of the iOS app carried a
private table — `1` birth certificate, `2` marriage certificate, and so on —
that existed nowhere else; when a second deployment issued credentials with
`doc_type = 2` meaning a verification record, the app told the holder they
were looking at a marriage certificate. Treat the value as an issuer-local
discriminator and display it, if at all, as the number it is.

**`transaction_type` is what a person reads.** It carries what the credential
attests, in the issuer's own words, and a verifier displays it verbatim. Text
rather than a code precisely because the categories are per-issuer and change
without anybody telling a phone — which is the property that makes a shared
numeric registry unworkable. It is OPTIONAL: a credential without it is
well-formed, and a verifier shows the other claims as before.

### 5.2 Restricted tier (0x40–0x7F)

| tag | name | encoding |
|---|---|---|
| 0x40 | surname | UTF-8 |
| 0x41 | given_names | UTF-8 |
| 0x42 | middle_name | UTF-8 |
| 0x43 | suffix | UTF-8 |
| 0x44 | date_of_birth | **int32**, days since 1970-01-01 (signed: pre-1970 is valid) |
| 0x45 | sex | uint8, ISO 5218 (0 unknown, 1 male, 2 female, 9 n/a) |
| 0x46 | pcn | 8 bytes, packed BCD of the 16-digit card number |
| 0x47 | digital_id | UTF-8 |
| 0x48 | portrait_hash | 32 bytes, SHA-256 of the portrait symbol's bytes, §12.1 |
| 0x49 | place_of_birth | UTF-8 |
| 0x4A | fields | ordered (label, value) list, see §5.3 |
| 0x4B | attachments | attachment list, §17.1 |

A public-tier tag MUST NOT appear in the restricted section, and vice versa.
Issuers MUST reject such input rather than re-tier it, and verifiers MUST
refuse such a credential as `malformed`: the public section on every device,
the restricted section wherever it is opened. A restricted claim is never
shown as a public one, whoever signed it (2026-11 audit, F056).

0x80–0xFE are available for application extensions, in the restricted
section. 0xFF is reserved as the extended-length marker.

### 5.3 The displayed field list (0x4A)

```
repeat:  u8 labelLen | label utf-8 | u16 valueLen | value utf-8
```

Every field the issuing organization chose to **display**, in the order the
document prints them. A list rather than a tag per field because the labels
are chosen per organization and the set is not fixed: no registry of tags can
cover "whatever this deployment decided to print".

- Order MUST be preserved. It is the document's order, and the point is that a
  verifier can render the same rows in the same sequence as the paper beside
  it.
- Labels MUST NOT be sorted, deduplicated or translated. Two rows may
  legitimately share a label, and rewriting one is the verifier
  second-guessing the issuer about its own document.
- A verifier that also finds typed tags 0x40–0x49 SHOULD render the list and
  suppress them, not both: the same fact under two labels reads as a
  discrepancy.

`verify` stopped emitting the typed person tags when it began emitting this
list. They remain defined so credentials issued before 2026-08-30 decode.

## 6. Signed bytes

```
"OfflineVerifier/v1/sig" 0x00
| version 1 | suite 1 | flags 1 | epoch 4
| claimsLen 2 | claims N | resHash 32 | sigAlg 1 | keyId 4
```

`claims` is the **public** section's claims, exactly as they appear on the wire
(compressed if flags bit 0 is set).

The signature covers `epoch`, `suite` and `flags` but **not** `ephPub`:

- covering `epoch` prevents relabelling a credential into another key window and
  defeats the surreptitious-forwarding weakness of naive sign-then-encrypt;
- excluding `ephPub` keeps signing separable from encryption, so an offline
  printer HSM can sign without performing the encryption. `ephPub` remains
  integrity-protected as AEAD associated data.

### 6.1 Signature encoding

`sigAlg = 0x01`: ECDSA over P-256 with SHA-256, encoded as raw `r ‖ s`, 32 bytes
each. `s` MUST be in the lower half of the group order. Verifiers MUST reject
`s > n/2`, `s = 0`, `r = 0`, and `r ≥ n`. The key MUST be on P-256: one on
any other curve verifies nothing, whatever its size (2026-11 audit, F055).

## 7. Key schedule

Per tier, with `tierLabel` being `"public"` or `"restricted"`:

```
salt  = header(43 bytes) ‖ AUD_pub[tier, epoch]        (32 bytes)
ikm   = X25519(ephPriv, AUD_pub[tier, epoch])
key   = HKDF-SHA256(ikm, salt, "CL03 key "   ‖ tierLabel, 32)
nonce = HKDF-SHA256(ikm, salt, "CL03 nonce " ‖ tierLabel, 12)
```

Note the trailing space in both info strings.

`HKDF-SHA256(ikm, salt, info, L)` is RFC 5869 extract-then-expand.

AEAD associated data is `header ‖ 0x00` for the public section and
`header ‖ 0x01` for the restricted section.

**The nonce is derived, not transmitted** — 12 bytes saved. This is safe only
because every message carries a fresh ephemeral key, which makes each
(key, nonce) pair unique. An implementation that reuses an ephemeral key across
two payloads breaks AES-GCM catastrophically.

## 8. Verification order

Normative. A verifier MUST:

1. Decode Base45; parse the payload; reject trailing bytes.
2. Look up the epoch key. **If absent, the result is `device_stale`** — a
   statement about the device, not the document. It MUST NOT be reported as
   expiry, tampering, or invalidity.
3. Derive the public-tier key; open the public section. Failure ⇒ `tampered`.
4. Look up `keyId` in the trust list; verify the signature over §6.
   Failure or unknown key ⇒ `forged`. The trust list is the bundle's entries
   the trust rule vouched for (§9.2), never the bundle's list as sent.
   **Nothing decrypted may be trusted before this step.** Successful AEAD
   decryption only proves the sender held an epoch key, and every verifier device
   holds one.
5. Read the public claims, inflated as §2.1 says, and hold them to §5: one
   encoding, public-tier tags only, a 16-byte `credential_id`, 4-byte times,
   and an attachment list, when there is one, to §17.1.
   Otherwise ⇒ `malformed`.
6. If the signing key's certificate names an organization (§9.2), `issuer_id`
   (`0x05`) MUST equal that name exactly. Otherwise ⇒ `forged`: an
   organization's key vouches for that organization only.
7. If the restricted section is present *and* the device holds that key: open it,
   then verify `SHA-256(plaintext) == resHash`. Mismatch ⇒ `tampered`. Its
   claims are held to §5 as well, restricted-tier tags only, and its
   attachment list to §17.1, with no id the public list also uses ⇒ else
   `malformed`.
8. Check `expires_at` and `issued_at` against the trusted clock, with tolerance
   (default 300 s). ⇒ `expired` / `not_yet_valid`.
9. Check `issued_at` against the signing key's window, from its trust entry,
   with the same tolerance. Outside it, or absent ⇒ `forged`. After step 8 on
   purpose: an old credential reads expired, not forged.
10. Check `credential_id` against the revocation filter. A hit sets an advisory
   "confirm online" flag and MUST NOT change the verdict.

Both implementations run the steps in this order (the issuer's name, 6, once
came last here and right after the signature in the code; 2026-11 audit,
F081). A server judging a credential applies every one of them: a trust list
that leaves out the key windows or the certified organizations skips 6 and 9,
and `ovcrypto.verifier.TrustList` takes one only as `TrustList.bare`, for
checking a bundle's signature (F090).

## 9. Key bundle

```
"CL03KB" 6 | version 1 | reserved 1
| issuedAt 4 | notBefore 4 | notAfter 4
| deviceIdLen 1 | deviceId N
| epochCount 1 | { epoch 4 | tier 1 | notBefore 4 | notAfter 4
                 | wrappedLen 2 | wrapped N } *
| trustCount 1 | { keyId 4 | notBefore 4 | notAfter 4
                 | spkiLen 2 | spki N } *
| revLen 4 | revocation N
| sigKeyId 4
| sig 64
```

Signed bytes are `"OfflineVerifier/v1/bundle" 0x00` followed by everything from
`"CL03KB"` up to and including `sigKeyId`.

A bundle MUST be refused when a `keyId` appears twice in its trust list, when
`notAfter` − `issuedAt` is over 31 days or not above zero (a lease over on
arrival; 2026-11 audit, F060), when `revocation`, if not empty, is not a
filter as §10 describes (F057), or when `reserved` is not 0 (F095: the
reference checks the signature over bytes it rebuilds, with a 0 there, and a
device over the bytes it got). A trust entry with `notBefore` ≥
`notAfter` and `spkiLen` 0 or 32 is a **tombstone**: the key is withdrawn, and
a device MUST refuse it everywhere from then on (§9.2). With `spkiLen` 32 the
field is the SHA-256 of the withdrawn key's DER SPKI, its **fingerprint**, and
the device MUST refuse that key under any `keyId`.

The trust entry with `keyId` 0xFFFFFFFF is no key, and never a tombstone: its
`spki` is the 32-byte digest of the `issuer_chains` sent beside the bundle
(§9.1), and its window opens (the signer writes 0 and 1). A bundle that
carries one MUST be refused unless the chains that arrived, as the device
decoded them, hash to it:

```
SHA-256( "OfflineVerifier/v1/chains" 0x00
         ‖ for each keyId, ascending:
             keyId 4 ‖ count 1 ‖ { derLen 4 ‖ DER } per certificate, the leaf first )
```

Whoever relays a bundle could otherwise drop one organization's chain and
keep the rest, and every phone that synced would read that organization's
documents as not genuine (2026-11 audit, F035). The signer writes one in
every bundle, so `keyId` 0xFFFFFFFF is no key's; a bundle without one, from
before it or made without a signer, binds nothing. A device that predates it
reads an entry with a key it cannot load. The digest is checked against what
arrives at a sync; a device judging again a bundle it stored, with the chains
it kept, does not check it, since it keeps only the chains that vouched an
entry.

**What no rule judges** (2026-11 audit, F095). The bundle's `notBefore`, and
each epoch key's `notBefore` and `notAfter`, are signed but informational: no
device reads them, and a device MAY ignore them. Which epochs a device can
open is decided by the server, which wraps only the epochs it means it to
read, and is bounded by the lease. A bundle whose `notAfter` has passed when
it arrives is accepted like any other; the lease is judged by the device's
trusted clock each time it is about to verify, and a device past `notAfter`
verifies nothing until it syncs. A bundle with no epoch keys is accepted too,
and opens nothing.

Binary rather than JSON specifically because it is signed: reproducing canonical
JSON byte-for-byte across implementations is a well-known source of silent
mismatches. JSON appears only as a transport envelope around a base64 blob.

`tier`: 0 public, 1 restricted. `wrapped` is the 32-byte raw X25519 private key,
encrypted with Apple's `eciesEncryptionCofactorVariableIVX963SHA256AESGCM` to the
device's Secure Enclave P-256 public key:

```
ephemeralPublicKey (65 bytes, X9.62 uncompressed) ‖ ciphertext ‖ tag (16)
derived = X963-KDF-SHA256(ECDH_secret, sharedInfo = ephemeralPublicKey, 32)
AES-128-GCM, key = derived[0..16], iv = derived[16..32], no AAD
```

X9.63 KDF: `SHA-256(Z ‖ counter_be32 ‖ sharedInfo)` concatenated, counter from 1.

### 9.1 Transport

`/keys/` answers `{"bundle": "<base64 CL03KB>", "issuer_chains": {"<keyId>":
["<base64 DER certificate>", ...]}, ...}`. `issuer_chains` is OPTIONAL and
carries, for a key certified by an issuing CA, its own certificate and, when
the deployment's Organization CA certified it, that CA's certificate after it:
one or two certificates. The pinned CA is never sent. A device that checks certificates says so by
sending `"capabilities": ["issuer-chain"]` with its request. Anything
malformed in `issuer_chains` is ignored; a certificate only ever raises trust
in its own key. When the bundle binds its chains (§9), whatever changes what
decodes refuses the bundle instead.

The request's `signature` is ECDSA P-256 with SHA-256 by the device's Enclave
key, DER. A device that sends `"keys-context"` among its capabilities signs

```
"OfflineVerifier/v1/keys\0" ‖ challenge
```

and one that does not signs the bare challenge (2026-11 audit, F003). The
context means no "challenge" a server hands out can make the Enclave key sign
any other message; a server MAY refuse the bare form once no device uses it.

**The phone and the app** (§13.3), both OPTIONAL and both in the pairing
request and in every `/keys/` request:
- `phone`: base64 of the 16-byte phone id for the site the device paired with.
  At pairing, that is the code's host.
- `app`: `{"id": "<bundle id>", "name": "...", "version": "...", "build":
  "..."}`, what the app says it is.

A server keeps them for display and for §13.3's grouping. It learns them only
from a pairing or from a sync whose signature and App Attest passed, ignores
malformed values rather than refusing the request, and never lets them grant
anything.

**A sync code** sent as `code` is closed out only by a device of the phone and
account it was made for. One that does not apply is not spent, and does not
fail the sync, which the signature authorised and not the code: the answer
says `"code": "applied"` or `"code": "not_applied"`.

With App Attest (2026-11 audit, F004), the request also carries `assertion`,
the App Attest assertion over the decoded challenge, by the key attested at
pairing. A server checks it against that key, never the Enclave key, and its
counter must exceed the last one seen, which it stores only if it still does
(one conditional update). At pairing the app sends `attestation`,
`attest_key_id` (base64 of the 32-byte key id), the `challenge` it attested
with, which must be one the server issued and nobody used, and
`"capabilities": ["attest-device-key"]`. The client data it attested is

```
"OfflineVerifier/v1/attest\0" ‖ challenge ‖ SHA-256(device_public_key)
```

the key being the bytes `device_public_key` decodes to, so the attestation
vouches for that key and no other. One of the bare challenge, from an older
app, does not count as an attestation: whoever relays the phone's requests
could post it beside a key of their own. `ovcrypto/appattest.py` is the
reference for both checks. The assertion needs no binding of its own: the key
it is checked against was attested for this device's Enclave key, and only
that key signs the request.

The request also carries `time_nonce`, base64 of 16 random bytes the device
makes for this sync, and a server MAY answer with `time` beside the bundle:
`{"format": "CL03ST", "version": 1, "issued_at": <u32>, "sig_key_id": <u32>,
"sig": "<base64>"}`, a signature by a key the bundle trusts for statements
over

```
"OfflineVerifier/v1/sync-time\0" ‖ "CL03ST" ‖ 0x01 ‖ device_id (16)
  ‖ time_nonce (16) ‖ uint32 issued_at ‖ uint32 sig_key_id
```

(`ovcrypto/devicelog.py::time_signed_bytes`). It is the only time a device
brings its clock's high-water mark back to (DESIGN, the clock), and only from
a reply that came back within two minutes of the nonce being made, by the
device's continuous uptime: a reply can be held open for days. Over the
device's own nonce, not the server's challenge, which whoever answers for the
host could replay to the device with an answer kept back for it. verify signs
one; the backend in this repository does not, so its devices never bring the
mark back without a Reset. A malformed `time_nonce` is refused like any other
malformed field; a server that cannot sign just now leaves `time` out.

### 9.2 Who may sign

Normative; `ovcrypto/trust.py` is the reference and `vectors/chains.json`
holds a case for each outcome. docs/MANAGED-PKI.md, "The phone contract" and
"The trust rule", gives the reasons and the refusal codes.

Each build pins raw keys and issuing CAs. A key is **vouched for** when its id
is pinned with that SPKI, or when its certificate validates at the trusted
time to a pinned CA: ECDSA P-256 with SHA-256 or SHA-384, key usage
`digitalSignature`, not a CA, at least one of the two EKUs below, a key equal
to the entry's SPKI, no unknown critical extension; and its id is not a pinned
raw id. A key with the credential EKU only may be certified through one
Organization CA directly under a pinned CA whose path length allows it; that
CA MUST have basicConstraints critical with path length 0, `keyCertSign`, a
P-256 key, and the credential EKU without the infrastructure EKU, and its own
fingerprint on the deny-list withdraws every key under it. A key is never vouched for when its fingerprint (SHA-256 of its
canonical DER SPKI), or for a certified key its id, is on the device's
deny-list: a certificate does not name a key id, so withdrawal by id alone
could be undone by offering the key under another one.

| EKU | allows |
|---|---|
| infrastructure, `2.25.121329492992163728507773796270407157063` | signing bundles, revocation feeds (§14) and log-key statements (§15.1), and credentials |
| credential, `2.25.257295685451493198219629212801851907755` | signing credentials only. The certificate's `O` and `organizationIdentifier` name the organization |

A device MUST accept a bundle only when its signer is vouched for and carries
the infrastructure EKU (a raw key counts), the device id is its own,
`issuedAt` is no later than now + 300 s and, whenever it holds a bundle, not
earlier than that bundle's by more than 300 s; and, while the bundle it holds
was signed by a certified key and its lease runs, the new signer was a live
entry of that bundle. A bundle signed by a certified key MUST list that key as
a vouched entry whose window has not ended at `issuedAt`: the next bundle it
signs would otherwise fail that very check for the whole lease (2026-11 audit,
F059). Trust entries that are not vouched for are dropped; a
bundle left with none is refused. A tombstone adds its key's id and
fingerprint to a deny-list that a re-key or a reset does not clear. A device
that cannot read its deny-list MUST NOT accept a bundle.

A build may pin a CA and its renewal under one name and key. Every pinned CA
whose name is the certificate's issuer and whose signature verifies is tried;
of those that are CAs valid at the trusted time, with a path length that
allows an Organization CA when one was sent, the one that ends last vouches.
Only when none is fit does the first one's fault decide the reason, so the
order they are pinned in decides nothing (2026-11 audit, F027). An entry's
window must lie inside the validity of the certificates sent beside it, the
leaf and any Organization CA: the pinned CA's own is checked at the trusted
time instead, so a renewal issued after a key was certified still vouches
for that key from its start.

In `issuer_chains`, a key id is canonical decimal (`0`, or digits with no
leading zero, at most 4294967295); any other name is ignored. Organization
names and identifiers are read only from UTF8String or PrintableString values,
and `issuer_id` is compared with the certificate's `O` byte for byte.

A credential's key MUST be a vouched entry with the credential EKU (or a raw
key), and the trusted now MUST be before its certificate's `notAfter`.

## 10. Revocation filter

```
"CL03RF" 6 | version 1 | log2Buckets 1 | reserved 2 | count 4
| fingerprints: uint16 × (buckets × 4)
```

Cuckoo filter, 4 slots per bucket, 16-bit fingerprints. Fingerprint `0` marks an
empty slot.

```
fingerprint(x) = be16(SHA-256("cl03-cuckoo-fp\0"  ‖ x)[0..2])  or 1 if zero
index(x)       = be32(SHA-256("cl03-cuckoo-idx\0" ‖ x)[0..4]) mod buckets
altIndex(i, f) = (i XOR be32(SHA-256("cl03-cuckoo-alt\0" ‖ be16(f))[0..4])) mod buckets
```

`buckets` is a power of two, which makes the modulo a mask and `altIndex` an
involution — that is what lets a lookup succeed from either bucket.

## 11. Verdicts

| verdict | meaning | fault of |
|---|---|---|
| `valid` | signature verifies, within validity window | — |
| `expired` | signature verifies, past `expires_at` | document |
| `not_yet_valid` | signature verifies, before `issued_at` | document |
| `forged` | signature does not verify; unknown issuer key; issued outside the key's window; issuer not the one its key's certificate names | document |
| `tampered` | AEAD or `resHash` check failed | document |
| `device_stale` | **no epoch key on this device** | **device** |
| `malformed` | not parseable | — |

`device_stale` MUST be presented as a device problem. Rendering it as a document
problem causes a verifier to reject a valid document, which is the most likely
real-world failure of this design.

A verifier meets codes sealed to keys it does not hold: another site's, or a
key file's (§19), and their epoch numbers coincide with its own. It MAY
therefore present `device_stale` (§8, step 2) and `tampered` from step 3
alike, as no key it holds opening the code (`no_matching_key`, §18.2). It
cannot tell such a code from one altered after sealing. It MUST then say
nothing against the document, and MUST offer a sync, when it has a site to
sync with, for a code newer than its keys. The verdict is unchanged.

A code read with a key file (§19) is presented as §19.5 says. Its verdict is
unchanged too.

## 12. Portrait symbol

```
CL03F1:<credential uuid>:<base45 webp>
CL03F2:<credential uuid>:<base45 compact avif>
```

A second symbol beside the credential, carrying the subject's photograph.

**It exists because the photograph does not fit in the credential**, and that
is measured rather than assumed. At 200×200 grayscale a JPEG above quality 20
exceeds the QR ceiling at *any* version, and quality 10 — a smudge — fills a
60 mm symbol on its own with no room for a single claim.

| | |
|---|---|
| image | grayscale, longest side 160 px. Cropped to the head -- a square 1.5 face-widths on a side around the largest face, lifted 0.06 of a face-width -- when the issuer finds one; aspect fit of the whole picture otherwise |
| codec | **WebP** (`CL03F1`). At quality 50 it is 1,390 bytes where JPEG is 2,667 and does not fit at all. WebP has no grayscale mode, so the encoder stores gray content in a three-channel container — this is expected, not an error. Or **AVIF** (`CL03F2`, §12.2): about 0.05 of face SSIM sharper at the same bytes |
| symbol | error-correction level Q, printed at ≥ 0.4 mm per module — about 66 mm |

Quality is chosen by fitting the printed size: an issuer tries qualities
downward until one fits. **Quality gives way, never the 0.4 mm floor** — a
sharper face on a symbol that will not scan is worth nothing.

### 12.1 Binding

The credential's `portrait_hash` (0x48) is `SHA-256` of the exact bytes carried
here. A verifier that shows the portrait MUST check it.

Without that check the two symbols are independent, and a document could be
presented with somebody else's face beside it — both scanning perfectly. The
credential uuid in the clear is a convenience only: it lets a phone that scans
this symbol first say which document it belongs to instead of failing
silently, and it proves nothing, since it is not covered by any signature.

The hash lives in the **restricted** section, so a public-tier device cannot
check it and therefore MUST NOT present the portrait as verified.

For `CL03F2` the hash covers the **compact** bytes of §12.2 -- what is printed --
never the container a verifier rebuilds around them.

### 12.2 Compact AVIF (`CL03F2`)

An AVIF file is 269 bytes of ISO-BMFF container around the AV1 picture. At the
portrait symbol's budget (about 700 bytes) that is more than a third of the
face, so the symbol carries only what varies:

```
u16 width | u16 height | av1C (4 bytes, first byte 0x81) | AV1 image data
```

A verifier rebuilds this exact container around it and hands the result to
the platform decoder (ImageIO has read AVIF since iOS 16). Every box has a
fixed size, so the image data always starts at byte 269:

| box | content |
|---|---|
| `ftyp` | major `avif`, minor 0, compatible `avif` `mif1` `miaf` |
| `meta` | `hdlr` `pict`; `pitm` item 1; `iloc` v0, 4-byte offsets and lengths, item 1 at offset 269 with the data's length; `iinf` with one `infe` v2, item 1, type `av01`, name `Color` |
| `iprp` | `ipco`: `ispe` width x height, `pixi` one 8-bit channel, `av1C` the 4 bytes, `colr` `nclx` 1/13/6 full range; `ipma` item 1 -> 1, 2, 3 (essential), 4 |
| `mdat` | the AV1 image data |

It is libavif's own layout for a monochrome 8-bit still. Only that is
described: an `CL03F2` symbol is always one monochrome 8-bit item. The issuer
(verify, `accounts/portrait_avif.py`) builds the same bytes and proves they
decode before it prints them; the two are pinned to one vector -- a
160 x 160 face, av1C `81 00 1c 00`, data `00 01 02` -- in
`AVIFPortraitTests` here and `AvifPortraitTest` there.

## 13. Ticket QR

The QR an operator generates on the web to hand **one management operation** to
a phone. Not the credential QR of §1, and it shares nothing with it: this one
carries no keys, no claims and no signature, only an address and a one-time
code.

```json
{"v":2,"url":"https://verify.example.ph","code":"5UL6YU48","op":"sync","dev":"gzGJED32RY+0BHwMpGzfTw==","for":"Ada Lovelace"}
```

UTF-8 JSON, compact separators, no whitespace.

| field | | |
|---|---|---|
| `v` | int, REQUIRED | `1` or `2`. A higher value MUST be refused, not parsed |
| `url` | string, REQUIRED | origin of the server. `https` REQUIRED — see below |
| `code` | string, REQUIRED | the one-time code. 8 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` — no `I`, `O`, `0` or `1`, because it may be read aloud or typed |
| `op` | string, REQUIRED at v2 | `enrol`, `sync` or `rekey` |
| `dev` | string, OPTIONAL | base64 of the **16 raw bytes** of the device id — the same bytes §9 puts in a bundle. Present for `sync` and `rekey` |
| `for` | string, OPTIONAL | whose account this concerns. Display only, ≤ 60 characters |

**v1 is `v:1` with no `op`, and means `enrol`.** It predates the field. A client
MUST go on accepting it: refusing would make an older server unusable by a newer
build, which is a poor way to ship a client change.

**Unlike §1 this is byte mode, and that is fine.** JSON carries lowercase and
braces, which lie outside the QR alphanumeric charset, so the ~45% capacity
penalty of §1 applies here. It does not matter: the payload is around 102
characters for `enrol` and 135 when it names a device — version 6 and version 8
at error-correction level **M**, which is what implementations emit. The
`≥ 0.4 mm` module rule of §1 does not govern either; a ticket QR is read from a
screen, not from a laser print photographed under field lighting.

That smallness is the design, not an accident. A key bundle (§9) is 1,899
characters for four epochs — version 35 — and does not fit at all once a few
hundred credentials are revoked. So the symbol carries a **connection** and the
operation happens over HTTPS afterwards.

### 13.1 Client rules

1. `https` is REQUIRED. A cleartext `url` MUST be refused, and refused
   distinguishably from a malformed one: the two need different answers — put
   the server behind TLS, versus fix the string.
2. An `op` the client does not implement MUST be refused. Performing the wrong
   operation is worse than performing none, and this field exists precisely so
   a `sync` code cannot be mistaken for an invitation to enrol.
3. `dev` and `for` are **untrusted display values**. A `dev` that is not 16
   bytes MUST be ignored rather than treated as an error, and neither field may
   decide anything. Where the server offers a connect step, its answer is
   authoritative for both.
4. A payload that is not this JSON — a credential QR being the likely
   confusion — MUST be reported as "not a pairing code" rather than as a
   malformed one.
5. **A `sync` or `rekey` code concerns a phone** (§13.3). Any of an
   implementation's apps on that phone acts on it for its own registration
   with the code's site, in this order:
   1. A code naming the app's own record acts on it.
   2. From a site the app is paired with, the connect step's `same_phone`
      decides.
      - `true`: the app acts for its own registration. A `rekey` crosses
        apps through the `rekey` route of §13.2.
      - `false`: refused as another phone's.
      - Absent: a code naming another record is refused, saying it may be
        another app's on this phone that has not yet told the site its phone.
   3. From a site the app is not paired with, a `sync` code is refused. A
      `rekey` code brings that site back through the `enrol` route of §9.1,
      which gives the record named the new key:
      - on an app paired nowhere, as its home site: a restored phone;
      - on an app paired with other sites, as one more beside them, unless
        the connect step's `app_id` names another app.
      A re-key never moves a pairing from one site to another.

### 13.2 The connect step

Optional, and served by verify but not by this repository's backend.

```
POST <url>/api/v1/device/connect/    {"code": "...", "phone": "<base64, 16 bytes>"}
```

`phone`, the asking phone's id for this site (§13.3), is OPTIONAL. It is sent
only with a `sync` or `rekey` QR, whose `op` the client has read; a pairing
code's host learns nothing it need not.

Answers the operation, the device and label it concerns, what the owner may
read, and an `endpoints` map naming where `enrol`, `rekey`, `challenge`, `keys`
and the feed of §13 live. Where it is published, that map is authoritative — it
exists so a path can move without re-flashing a fleet. Where the route is absent
(404), the payload is taken at face value, which is what a ticket QR meant
before the step existed.

For a code that names a device the answer adds:
- `app` and `app_id`: that record's app, by name and bundle id;
- `same_phone`, a boolean, **only** when the request carried `phone` and the
  record has a phone id of its own. It is left out, never false, when either
  is unknown, so a record that has not yet told its phone is not called
  another phone's. The record's phone id itself is never returned.

**The `rekey` route** takes the body of a pairing (§9.1) with a `rekey` code,
plus `device_id`: the scanning app's own registration with the site. The record
the code re-keys must be that one, and the answer names it.
- It exists so that a server from before phones answers 404 rather than
  re-key the record the code names, another app's.
- A client uses it only for a re-key that crosses apps, and takes the answer
  only if it names its own `device_id`.

**Connecting spends nothing.** The code is consumed by the endpoint that
performs the operation, so a client MAY connect on scan purely to show a
confirmation screen before committing to anything.

**Every refusal is the same string,** whether the code expired, was spent,
never existed, names the wrong operation or points at a revoked device.
Implementations MUST NOT distinguish them: telling them apart tells somebody
feeding in guesses which ones were real.

### 13.3 The phone

One handset can run more than one app of an implementation: a development
build beside a store build, or two apps of one publisher. Each holds its own
keys and its own device record at each site, so without more a site sees one
phone as two, and a code made for one app's record reads as another phone's in
the other. The **phone id** lets a site see one phone.

**The secret.** 32 random bytes, made by whichever of the implementation's apps
first needs it and kept on the handset where all of them can read it and
nothing else can (on iOS, a Keychain access group of the publisher's team).
It never leaves the handset, is never backed up to another one, and is never
changed once made: an app that cannot read it sends no phone id rather than
make a second. It survives an app's reset, since the other apps share it.

**The id a site is told** is derived for that site alone:

```
phone_id = HMAC-SHA256(secret, "CL03 phone " ‖ host)[0:16]
```

`host` is the site's host as the device recorded it at pairing, lowercased,
in UTF-8. Two sites therefore hold unrelated ids for one handset and cannot
tell from them that they share it. It travels as `"phone"`, base64 of the 16
bytes. Vectors, secret = the bytes 0x00 to 0x1f:

| host | phone_id |
|---|---|
| `verify.example.ph` | `ec70779f987ad69c4f0d77d89a051810` |
| `clik-dev.example.ph` | `56dc6d1d996bcc163e69c595ee2ca9ff` |

**What a site may do with it**, within one owner's records only: show the
records that share it as one phone; let any of them close out a `sync` code
made for another; send a `rekey` code's new key to the scanning app's own
record on that phone; and retire an app's earlier record on the phone once a
newer pairing of the same app there has synced.

**What it never does.** It authorises nothing, unlocks no key and decides no
verdict or trust: the device's Enclave signature, App Attest and the ticket do
all of that, as before. A record without one, from a device that sends none,
is a phone of its own.

## 14. Revocation feed

The filter of §10 also travels outside a key bundle, signed apart from it.
The app fetches it at each sync, right after the bundle, and keeps it in
memory until the app quits, so it is never fresher than that sync and a
relaunch leaves only the bundle's filter; a device MAY fetch it more often
(2026-11 audit, F078: this said "between syncs", which no build did).

```
GET <endpoints.revocations>          →  200 application/json
```

```json
{"format":"CL03RL","version":1,"issued_at":1788062995,"not_after":1788149395,
 "key_id":1,"filter":"<base64 of §10>","sig":"<base64 of §6.1>"}
```

Unauthenticated. There is nothing in it to protect — it is a list of opaque
16-bit fingerprints — and an API key would only change a stripped feed from
reading "nothing revoked" to reading "cannot connect", both of which are what
an attacker wants.

### 14.1 Signed bytes

The signature covers a **fixed binary layout, not the JSON**. JSON is the
transport envelope around base64; reproducing canonical JSON byte for byte
across implementations is a known source of silent mismatches, and §9 says the
same about the key bundle.

```
offset  size  field
------  ----  -------------------------------------------------------------
     0    30  context      "OfflineVerifier/v1/revocation\0"
    30     6  magic        "CL03RL"
    36     1  version      0x01
    37     4  issued_at    uint32 BE
    41     4  not_after    uint32 BE
    45     4  key_id       uint32 BE
    49     4  filterLen    uint32 BE
    53     n  filter       §10, filterLen bytes
```

`sig` is over those bytes, in the §6.1 encoding, by an issuer key of §9's trust
list. Each of the four covered scalars earns its place:

| | without it |
|---|---|
| `filter` | the feed can be swapped for an empty one |
| `not_after` | yesterday's feed is replayed to hide today's revocation |
| `key_id` | a feed signed by any trusted key passes as any other |
| context | a revocation feed could verify as a credential (§6) or a bundle (§9) |

### 14.2 Client rules

1. The signature MUST be verified before the filter is used, against a key
   the current bundle lists and the trust rule vouched for with the
   infrastructure EKU (§9.2), or against a **pinned** raw key while the device
   holds no bundle judged by that rule. An unsigned or unchecked feed is
   strippable by anyone on the path, which turns every revoked credential back
   into a valid one.
2. `now > not_after` MUST be refused. This is what bounds replay.
3. An unknown `key_id` MUST be refused.
4. A verification failure MUST NOT be treated as "no revocations". Silently
   degrading to an empty filter is exactly the stripping attack the signature
   exists to stop. The same holds for the filter inside a bundle (§9): one the
   device cannot read refuses the bundle (2026-11 audit, F057).
5. `404` MAY be treated as "this server has no feed" rather than an error: a
   device whose bundle already carries a filter (§9) is not broken without one,
   only less fresh.
6. A hit remains **advisory**, exactly as in §10 and §11. False positives are
   inherent; a hit means "confirm online", never "reject".

### 14.3 Vectors

`ovcrypto/feed.py` is §14's reference: `feed_signed_bytes`, which verify's
signer and its key-file path both sign, and `verify_feed`, rules 1-4 above.
`vectors/vectors.json`'s `feeds` holds a feed per rule -- current, on its last
second, replayed after it ended, its filter stripped, signed as a credential,
by a key it does not name, version 2, a filter that does not parse, a key id
past four bytes -- and `RevocationFeed.swift` must give each the same reason;
`vectors/signer_e2e.json` holds the signer's own (2026-11 audit, F080). §12 and
§13 have no vectors yet, and are kept in step by reading.

## 15. Activity log

A paired device records what it did and uploads it to the server that paired
it. The record is sealed on the device to a key only the server holds, so the
device can append to its log and cannot read it back (DESIGN §11i). The
reference implementation is `ovcrypto/devicelog.py`; the verify deployment
carries it verbatim, and `tests/test_devicelog.py` pins a record byte for byte
against the app's `LogSeal.swift`.

### 15.1 Log key statement

```
GET <endpoints.log-key>           →  200 application/json
                                     404 when the server keeps no log
```

```json
{"format":"CL03LK","version":1,"key_id":3,"public_key":"<base64, 32 bytes>",
 "issued_at":1791331200,"not_after":1799107200,"sig_key_id":1,
 "sig":"<base64 of §6.1>"}
```

`public_key` is a raw X25519 key. `sig` is by an issuer key of §9's trust list
over a fixed layout, never the JSON:

```
offset  size  field
------  ----  -------------------------------------------------------------
     0    27  context      "OfflineVerifier/v1/log-key\0"
    27     6  magic        "CL03LK"
    33     1  version      0x01
    34     4  key_id       uint32 BE, the log key's id
    38    32  public_key   X25519
    70     4  issued_at    uint32 BE
    74     4  not_after    uint32 BE
    78     4  sig_key_id   uint32 BE, the issuer key that signed
```

Client rules:

1. The signature MUST verify before the key is used, against the same keys
   as a revocation feed (§14.2). A device that sealed to any key it was handed
   would seal its log to whoever answered.
2. A statement MUST NOT be adopted when `now > not_after`, so a retired key
   cannot be replayed onto a device. An adopted statement stays usable past
   its `not_after`: a device offline that long keeps sealing to the key it has,
   and the server keeps every log key it has issued.
3. An adopted statement MUST be re-verified when it is loaded from storage.

### 15.2 Record

One record per event, sealed when the event happens:

```
offset  size  field
------  ----  -------------------------------------------------------------
     0     6  magic        "CL03LG"
     6     1  version      0x01
     7     4  key_id       uint32 BE, the log key it is sealed to
    11     8  seq          uint64 BE, this device's record number, from 1
    19    32  ephemeral    X25519 public key, fresh per record
    51     n  ciphertext   AES-256-GCM of the plaintext
  51+n    16  tag
```

The first 19 bytes are the **header**. With `E` the ephemeral key and `L` the
log key:

```
shared = X25519(e, L)
salt   = header ‖ E ‖ L
key    = HKDF-SHA256(shared, salt, info = "CL03LG key",   32 bytes)
nonce  = HKDF-SHA256(shared, salt, info = "CL03LG nonce", 12 bytes)
AAD    = header ‖ E
```

The nonce is derived rather than sent, which is safe for the reason §7 gives:
no two records share an ephemeral key. The header is associated data, so a
record cannot be renumbered or moved to another key without failing to open.

The plaintext is a UTF-8 JSON object:

| key | type | |
|---|---|---|
| `v` | int | 1 |
| `seq` | int | equal to the header's `seq` |
| `prev` | string | lowercase hex of SHA-256 of the **sealed** record before this one; 64 zeros for the first |
| `at` | int | milliseconds since the Unix epoch, by the device's clock |
| `event` | string | `[a-z_]{1,40}`: `pair`, `sync`, `revocations`, `unlock`, `lock`, `scan`, `portrait`, `attachment`, `clock`, `settings`, `log_send`, `org_select`, `trust`, `site`, `history` |
| `outcome` | string | `success`, `failure` or `notice` |
| `build` | string | the app's version and build |
| `detail` | object | at most 32 keys; values are short strings, integers, booleans or null |
| `org` | int | OPTIONAL: the organization the session worked for (§16.3); absent when none |

A device that verifies for several sites (DESIGN §11k) keeps **one log per
site**: each sealed to that site's log key, numbered for that site's device
record, and sent to that site alone. A record's `org` is then always one of
that site's organizations. A `scan` on such a device says in `detail.site`
which site's keys opened the code; `site` events record a site added or
removed.

`detail` MUST NOT carry personal data. A document is named by its credential
id (claim `0x01`), which the issuing server can resolve, and a National ID by
which of its codes was read (`philid_card`, `ephilid`,
`digital_national_id`, `digital_id_number`, `card_number`), never by its
number. A server MUST accept event names it does not know.

A `history` event is about the device's scan history (§18), a list the
device can read and export, which this log is not. `detail.action` is `on`,
`off`, `opened`, `exported` or `cleared`, and `detail.scans` is how many
scans it concerned. It records that a copy of such a list was opened or left
the device, never what was in it.

`prev` is over the sealed bytes, so the server checks the chain without
trusting anything it decrypted. The chain runs across uploads: the device
keeps the last `seq` and hash after a send removes the records, in the
Keychain as well as beside the records, so a reinstall does not restart it. A
reset erases it, and the device's next pairing is a new identity whose chain
starts at 1. A **re-key** keeps the identity, and with it every number the
server holds; a device that re-keys with no head MUST NOT count from 1 again,
since the server keeps the first record under each number. It starts at the
current time in milliseconds, with the zero `prev`, and the server reads the
jump as one break.

### 15.3 Upload

```
POST <endpoints.logs>
{"device_id":"<base64, 16 bytes>","challenge":"<base64>",
 "signature":"<base64 DER>","records":["<base64 of 15.2>", ...]}
```

`challenge` is from `/challenge/`, as for `/keys/`: 16 to 32 random bytes,
which a device MUST check before signing anything over it (verify issues 24, the
reference backend 32). A longer value could be another message's signed bytes:
this section's are at least 78. `signature` is ECDSA P-256 with SHA-256 by the
device's Enclave key, DER, over:

```
"OfflineVerifier/v1/log-upload\0" ‖ challenge ‖ SHA-256( ‖ᵢ uint32 BE len(rᵢ) ‖ rᵢ )
```

not the bare challenge. It binds the signature to exactly these records, and
the context keeps an upload signature from passing at `/keys/`, which signs the
challenge behind its own context (or bare, for an older device), and the other
way round.

At most 1000 records per request, each at most 8 KiB. The answer:

```json
{"ok":true,"through_seq":512,"stored":510,"duplicates":2,"conflicts":0,
 "unreadable":0,"breaks":0,"refused":0,"deferred":0}
```

With it, when `through_seq` is not 0, `ack` (2026-11 audit, F036): the
server's signed word that it holds this upload up to `through_seq`, by a key
the device's bundle lists for statements, as for 15.1:

```json
"ack": {"format":"CL03LA","version":1,"issued_at":1780000000,
        "sig_key_id":1,"sig":"<base64 64 bytes>"}
```

over

```
"OfflineVerifier/v1/log-ack\0" ‖ "CL03LA" ‖ 0x01 ‖ device_id (16)
  ‖ uint64 BE through_seq ‖ SHA-256 of the records as above ‖ uint32 BE issued_at
  ‖ uint32 BE sig_key_id
```

`refused` and `deferred` are verify's limits on one phone (2026-11 audit, F048);
a server without them omits both. A record numbered further ahead than a phone
numbers -- more than 100,000 past the newest held and past the current time in
milliseconds, which is where a re-key with no chain head jumps to -- is
`refused` and not stored. Past a daily cap of records per phone, the newest in
the batch are `deferred`: not stored, and above `through_seq`.

Server rules:

1. A record that does not open, or whose plaintext is not as 15.2 says, MUST
   still be acknowledged and kept as an unreadable placeholder. Refusing the
   batch would leave a device that can never clear its log.
2. A record whose `seq` is already stored is a duplicate when its hash matches,
   and is acknowledged; otherwise it is a conflict, and the stored one is kept.
3. A record is in chain when it is the device's first, with `seq` 1 and the
   zero `prev`, or follows the last stored record by one with that record's
   hash as `prev`. Anything else is stored and marked as a break.
4. The device's claimed time and the server's receipt time are both kept. A
   gap between them is a finding.

Client rules:

1. Only records with `seq ≤ through_seq` from the batch just sent MAY be
   removed, and only when `ack` verifies against a key the device trusts for
   statements, over exactly this upload. Without one -- a server that does not
   sign, or something answering for one -- nothing is removed, and the records
   are sent again later. Records written during the upload stay, and so do
   deferred ones.
2. A `404` MAY be treated as "this server keeps no log", and nothing removed.
3. A `429` means the phone has reached the server's daily cap: nothing was
   stored, nothing is removed, and the upload is tried again later.

## 16. Organizations

A deployment whose accounts belong to organizations, as verify's do, says
which of them a device works for. It is one device record, one key and one
bundle however many there are; nothing here changes §9's bundle. A server
with no organizations sends none of this, and a device then behaves as if
this section did not exist.

### 16.1 What the server sends

`POST /keys/` (§13.2's `keys` endpoint) adds, beside `bundle`:

```json
"organizations": [
  {"id": 3, "name": "Philippine Statistics Authority", "subtitle": "",
   "role": "admin", "initials": "PSA", "mark_color": "#00386a",
   "logo": "data:image/png;base64,iVBORw0KGgo..."}
]
```

| key | type | |
|---|---|---|
| `id` | int | the organization's id on that server, ≥ 1 |
| `name` | string | non-empty |
| `subtitle` | string | `""` when none |
| `role` | string | the owner's role there: `admin` or `operator`; anything else reads as `operator` |
| `initials` | string | up to 3 characters, for the mark drawn when there is no logo |
| `mark_color` | string | `#rrggbb`; anything else reads as `#00386a` |
| `logo` | string | a `data:image/{png,jpeg,gif,webp};base64,` URI of at most 64 KiB decoded, or `""` |

The list is the organizations the device is linked to **and** its owner may
enter at that moment, in the order to show them. It is outside the bundle's
signature: it decides what the device shows and how it files log records,
never a verdict. `organizations` absent means the server keeps none; `[]`
means none is linked. A device MUST skip an entry without a usable `id` or
`name` rather than fail the sync, and keep the first of two with one `id`.

`POST /connect/` (§13.2) adds `"organizations": [{"id": 3, "name": "..."}]`:
for a `sync` or `rekey` ticket the device's list; for an `enrol` ticket the
organizations the new device will be linked to. Display only.

### 16.2 Client rules

1. The list is stored with the bundle it arrived with, and replaced by every
   sync.
2. The organization a device works for belongs to the **session**. Locking,
   logging out, the inactivity timeout and a sync all end it.
3. On unlock: with two or more, the operator chooses before anything is
   scanned, starting on the one chosen last if it is still listed; with
   exactly one, it is chosen without asking; with none, there is no
   organization.
4. The organization is not a filter. The device reads every credential its
   keys open, whoever issued it.
5. A device MUST NOT offer to add or remove organizations. The links are set
   on the server.

### 16.3 In the activity log

While an organization is chosen, every record's plaintext (§15.2) carries
`"org": <id>`; otherwise the key is absent. Choosing one is itself a record:
event `org_select`, outcome `success`, detail `{"org": <id>}`, written after
the choice so it carries the same `org`.

Server rules:

1. A present `org` that is not an integer from 1 to 2³¹−1 makes the record
   unreadable (§15.3 rule 1).
2. The server keeps the `org` as sent, and files the record under that
   organization only if the device has ever been linked to it. A link removed
   later still counts: the record was made while it held. Otherwise the record
   is kept, under no organization.
3. A record is never refused for its `org`.

## 17. Attachments

Content of any media type -- a JSON document, an image, a page of text --
signed with a credential and carried either **inline**, inside the credential,
or split across **part symbols** printed beside it when it is too large for
one QR code. `ovcrypto/attachments.py` is the reference; `vectors.json` pins it
against the app (§17.6).

An attachment is described by an entry in a claim (§17.1), so the credential's
signature covers it: inline content directly, split content through a SHA-256
of what the parts carry. Nothing about an attachment changes the credential's
verdict (§11). What it adds is reported per attachment (§17.5).

### 17.1 The attachment list (0x0B, 0x4B)

The value of `public_attachments` (`0x0B`, public section) and of
`attachments` (`0x4B`, restricted section) is a list of one or more entries:

```
repeat:
     1  id           1..255
     1  carriage     0x01 inline, 0x02 parts
     1  typeLen      1..127
     N  mediaType    ASCII
     1  labelLen     0..255
     N  label        UTF-8
     -- carriage 0x01, inline --
     2  size         1..65535
     N  content
     -- carriage 0x02, parts --
     1  encoding     0x00 none, 0x01 raw DEFLATE
     4  size         1..1,048,576: the content's length
     1  count        1..255: how many part symbols
    32  digest       SHA-256 of the sealed bytes, §17.2
    32  key          AES-256-GCM key, §17.2
```

A list that breaks any of these is `malformed`, at §8 step 5 or 7:

- Ids are strictly ascending within a list, and no id is in both lists. Only
  a device that reads both lists can check the second rule; the issuer MUST
  keep it regardless.
- `mediaType` is `type/subtype` with no parameters: lowercase letters, digits
  and `!#$&^_.+-`, exactly one `/`, neither side empty.
- `label` is valid UTF-8. It is the issuer's name for the attachment, shown
  verbatim, and may be empty.
- An unknown `carriage` or `encoding`, a size or count out of range, and any
  byte after the last entry.

**The list an attachment is in decides who can read it**, as for every other
claim. The public list is read on every device holding the epoch key; the
restricted list only where the restricted section opens. Both the key and the
digest are in the list, so a part symbol is ciphertext to anyone who cannot
read the list that describes it: a stray scanner learns only how many bytes
it carries.

Inline content costs the credential's own stamp (§1): an issuer carries
inline only what keeps the credential at its printed size, and splits the
rest.

### 17.2 Sealing split content

```
plain  = content, or its raw DEFLATE (wbits -15) when encoding is 0x01
sealed = AES-256-GCM(key, nonce = 12 zero bytes, plain,
                     aad = "CL03AT" || credential_id (16) || id (1))
         -- ciphertext || 16-byte tag
digest = SHA-256(sealed)
```

`key` is drawn at random for each attachment and seals nothing else, which is
what makes the fixed nonce safe: the reasoning of §7's derived nonce, one key,
one message. An issuer compresses only when it shortens the content, as §2.1.
Inflating follows §2.1's rules, capped at 1 MiB, and MUST give exactly `size`
bytes.

**The digest binds the parts, not the GCM tag.** Every device that reads the
list holds `key`, and any of them could seal other content under it with a
valid tag. Only the signed digest says which sealed bytes the issuer meant.

### 17.3 Part symbol

```
CL03P1:<base45>

    16  credential_id    the credential's claim 0x01; routing only, not signed
     1  id               the entry it belongs to
     1  index            1..count
     1  count            the entry's count
     N  chunk            at least 1 byte
```

The sealed bytes are cut into `count` chunks in order, and chunk `index` is
the index-th of them. An issuer cuts them evenly; a reader takes the parts in
any order and concatenates by index. Nothing may follow the chunk -- it runs to
the end of the payload.

The marker starts the string, after ASCII whitespace is trimmed from both
ends, as `CL03F1:` does (§12). A reader checks for it before §1's marker,
because a Base45 body can spell `CL03:`.

Alphanumeric mode, level Q, at least 0.4 mm per module, as §1. A 40 mm stamp
holds version 20, 702 characters: 463 bytes after the marker, so 444 bytes
of chunk per symbol (`attachments.part_capacity`). 1 MiB of incompressible
content would take more than the 255 symbols an entry may have; the limit is
the paper, and an issuer refuses what does not fit rather than printing it.

### 17.4 Reading

A verifier MUST:

1. Read attachments only from a credential that verified: §8 ended `valid`.
   A refused or expired credential shows none.
2. Show an inline attachment as the list carries it. It is signed with the
   claims and needs nothing more.
3. Route a part symbol by `credential_id` and `id` to an entry in a list this
   device read. A part naming another credential, or an id this device did not
   read, is not used. A part whose `count` differs from its entry's, or whose
   `index` is outside 1..count, is unreadable. A second part for an index
   already held is ignored.
4. With all `count` chunks held, concatenate them in index order and check
   `SHA-256 == digest`. A mismatch means the parts presented are not the
   ones the issuer signed: the attachment is **contradicted**. The chunks held
   are dropped, so the parts can be scanned again.
5. Then open the GCM, inflate when `encoding` is `0x01`, and check the length
   against `size`. Failure after a matching digest is the issuer's fault: the
   attachment is `malformed`.
6. Never run content, or hand it to another application. Show `text/*` and
   `application/json` as UTF-8 text, `image/*` through the platform's own
   decoder, and anything else -- text that is not UTF-8, an image the
   platform cannot decode -- by its type and size only. An issuer refuses to
   attach text that is not UTF-8.

### 17.5 Results

Each attachment ends in one of: `opened`; `incomplete`, with how many of its
parts are held; `contradicted`; or `malformed`. A contradicted attachment is a
finding about the document in hand -- something printed beside it is not what
was signed -- and is shown as one, in the colour of a refusal. The credential
keeps its own verdict: its signature still verified.

The activity log (§15.2) records event `attachment` with the credential id,
the attachment's id and its result, never its content or its label.

### 17.6 Vectors

`vectors.json` key `attachments`: one credential with an inline entry and a
split one in each list, its part symbols, the opened contents, and the
refusals of §17.1, §17.3 and §17.4 -- a list that breaks each rule, signed by
the vector key, and part symbols that are damaged, from another credential,
or altered so the digest fails.

### 17.7 A cap on QR codes

A deployment MAY cap how many QR codes one document prints: the credential,
its portrait (§12) and every part symbol, together. The issuer enforces the
cap when it issues and refuses a document that needs more. It never prints
some of the parts: a phone cannot tell a cap from a code that was left off,
and would report the attachment unread for good. Inline attachments print
nothing and are not counted.

A cap of 2 leaves a credential and its portrait, with attachments inline only.
`attachments.part_budget` turns a cap into the part symbols it leaves.

## 18. Scan history file

A device MAY keep a **scan history**: a list of its own scans that it can
open and export, beside the activity log (§15) and never in its place
(DESIGN §11m). This section is the exported file, `CL03SH` version 1.
`ios/OfflineVerifier/ScanHistoryFile.swift` is the reference.

The file is **not evidence**. It is unsigned, anybody who holds it can edit
it, and it says so. The record of what a device did is the activity log on
its site's server.

### 18.1 The document

One UTF-8 JSON object, its keys sorted at every level.

| key | type | |
|---|---|---|
| `format` | string | `CL03SH` |
| `version` | int | `1`. A reader MUST refuse a version it does not know |
| `signed` | bool | always `false` |
| `build` | string | the app's version and build |
| `exported_at` | string | when the file was written (§18.3) |
| `time_zone` | string | the device's time zone, an IANA name |
| `utc_offset_minutes` | int | its offset from UTC when the file was written |
| `scope` | object | what the file covers (§18.4) |
| `retention` | object | `days` and `max_records`: how far back the device keeps a scan, and how many for a site. So a short file is not read as a quiet month |
| `sites` | array | each site in the file, the home site first: `host`, `home` (bool) and `records` (int) |
| `key_files` | array | each key file the file's records were read with: `id` (§19.2) and `records` (int). Empty when there is none |
| `count` | int | the number of records, for a reader to check |
| `records` | array | the records (§18.2), oldest first |
| `demo` | bool | `true` in a file of Demo samples; absent otherwise |

### 18.2 A record

Every key is present on every record, with `null` where it has nothing to
say.

| key | type | |
|---|---|---|
| `at` | string | when the code was read, by the device's clock (§18.3) |
| `site` | string or null | the host of the site the scan is recorded under: the one whose keys opened the code, or the session's site when none did. `null` in a file of samples, and when a key file's keys opened the code |
| `key_file` | string or null | the id of the key file whose keys opened the code (§19.2), as 64 lower-case hex digits. `null` otherwise |
| `org` | object or null | `id` and `name` of the organization the session was for, when it is that site's own (§16.3) |
| `document` | string | `credential` or `national_id` |
| `national_id` | string or null | which National ID code was read, by its name in §15.2 |
| `credential_id` | string or null | claim `0x01` as a UUID in lowercase. Present only when the credential's signature verified |
| `verdict` | string | the verdict of §11, or `unverified` for a National ID code whose signature could not be checked |
| `result` | string | what the screen said (below) |
| `result_title` | string | the title the screen showed, in English, without a date |
| `photo` | string or null | `matched`, `not_checked` or `does_not_match`; `null` when the document carries no photo this device could check |

A record MUST NOT carry personal data: no name, birth date, age band, ID
number or hash of one, photo, validity date, device name, or free text. A
National ID is recorded by which of its codes was read, never by its number.

`result` is one of:

| `result` | title | `verdict` |
|---|---|---|
| `verified` | Verified | `valid` |
| `verified_photo_not_checked` | Verified, photo not checked | `valid` |
| `verified_check_online` | Verified, check online | `valid` |
| `verified_key_file` | Verified by key file | `valid` |
| `photo_does_not_match` | Photo does not match | `valid` |
| `expired` | Expired | `expired` |
| `not_yet_valid` | Not yet valid | `not_yet_valid` |
| `not_genuine` | Not genuine | `forged` |
| `altered` | Altered | `tampered` |
| `not_readable` | Not readable | `malformed` |
| `phone_needs_sync` | This phone needs to sync | `device_stale` |
| `key_file_ended` | Key file ended | `device_stale` |
| `no_matching_key` | No matching key | `device_stale` or `tampered` |
| `read_not_verified` | Read, not verified | `unverified` |
| `number_only` | Number only | `unverified` |
| `not_finished` | Not finished | as it stood |

`no_matching_key` is what a verifier shows when none of its keys opens the
code and it does not judge the code by its epoch (§11). `verdict` keeps what §8 gave.
`not_finished` is a code that was read and whose result never reached the
screen. `verified_key_file` is a pass read with an anchored key file's key
(§19.5), its photo checked or not, as `photo` says; a photo that does not
match is `photo_does_not_match`, whatever key read the code.
`key_file_ended` is a code a key file's keys opened after the file ended:
whoever sent the file sends a newer one, so the screen never says to sync.
In a
file of samples each code is prefixed `sample_`
(`sample_verified`) and each title begins "Demo:", so a sample is never
counted as a check.

### 18.3 Times

Every time in the file is UTC, in the form `2026-11-15T06:22:07.375Z`, to
the millisecond. `time_zone` and `utc_offset_minutes` say where the device
was, and the days in `scope` are that zone's.

### 18.4 What the file covers

`scope.kind` is `day` with `date`, `range` with `from` and `to`, or `all`.
The dates are the device's own days, as `2026-11-15`.

When the list was narrowed before it was exported, `scope.filters` says how:
`result` (`Verified`, `Qualified`, `Refused` or `No verdict`), `site` (a
host), `organization` (a name) and `credential_id_contains` (the text
searched for), each present only when it applied. A file with `filters` is a
part of what its dates held, and MUST NOT be read as all of it.

The file is named
`ovx-scan-history_<host, all-sites or demo>_<yyyymmddThhmmssZ>.json`.

## 19. Key file

A **key file** carries what a verifier needs to read one issuer's CL03 codes
without a site: the reading keys of some epochs (§7) and the issuer's signing
keys, each with its certificates. It is how codes made on a workstation, or by
an issuer that runs no site, are read (DESIGN §11r). A verifier MAY accept key
files. One that does presents what it reads with one as §19.5 says.

`ovcrypto/keyfile.py` is the reference. Where this section and the module
disagree, the module is correct and this section is a bug.
`vectors/keyfile.json` pins it, with a case for every refusal, and
`scripts/make-key-file.py` makes key files on a workstation. OVX's reader,
`ios/OVX/KeyFiles`, agrees with it on every case (DESIGN §11r).

A key file is named `<name>.cl03key` and sent as `application/octet-stream`:
the extension, not a media type, tells a phone what it is.

### 19.1 The file

```
"CL03KF" 6 | version 1 | reserved 1
| issuedAt 4 | notAfter 4
| nameLen 1 | name N
| epochCount 1 | { epoch 4 | tier 1 | notBefore 4 | notAfter 4 } *
| trustCount 1 | { keyId 4 | notBefore 4 | notAfter 4
                 | certCount 1 | { derLen 2 | DER } * } *
| kdf 1 | iterations 4 | salt 16 | nonce 12
| sealed (32 × epochCount + 16)
```

Everything before `sealed` is the **clear part**. A verifier can show it
before it has the passphrase, and nothing in it is secret. `sealed` holds the
epochs' reading keys, in the order the clear part lists the epochs:

```
key    = PBKDF2-HMAC-SHA256(passphrase, salt, iterations, 32)
sealed = AES-256-GCM(key, nonce, plaintext = { key 32 } × epochCount,
                     aad = the clear part)                 ciphertext ‖ tag (16)
```

- `version` is 1 and `reserved` 0.
- `name` is UTF-8, 1 to 64 bytes: what the verifier calls the file. It
  identifies nothing (§19.3).
- `notAfter` is the file's end. `notAfter` − `issuedAt` MUST be above zero
  and at most 31 days (2,678,400 s), a bundle's longest lease (§9).
- `epochCount` is 1 to 32. Each (`epoch`, `tier`) appears once, `tier` 0
  public or 1 restricted, and an epoch with a restricted key has its public
  one too, since §8 opens the public section first. An epoch's `notBefore`
  and `notAfter` are informational, as a bundle's are (§9).
- `trustCount` is 1 to 16. Each `keyId` appears once, with `notBefore` <
  `notAfter`, and has 1 to 3 certificates, the leaf first, each issued by the
  one after it. A pinned CA is never in the file, as in §9.1.
- `kdf` 1 is PBKDF2-HMAC-SHA256, the only one. `iterations` is 600,000 to
  2,000,000, so that opening a file takes a phone seconds at most. The
  passphrase is the UTF-8 of its NFC form.
- A key in the plaintext is a raw X25519 private key, as a bundle's `wrapped`
  key is once unwrapped (§9).

A verifier MUST refuse a file that breaks any of these, or that has bytes
after `sealed`.

A maker of key files MUST draw `salt` and `nonce` at random for each file and
MUST refuse a passphrase under 12 characters. It SHOULD end the file no later
than its leaves' certificates end. The passphrase reaches the verifier by some
other way than the file does.

### 19.2 Who stands behind it

Each trust entry is judged at the trusted time, and is one of two kinds:

- **Certified**: its certificate validates to one of the build's pinned CAs
  by §9.2's rule, directly or through an Organization CA (a site's System CA
  in docs/MANAGED-PKI.md). Such a CA names its site's domain, which a site's
  bundle is matched against. A key file has no paired site, so the domain is
  shown, not matched. It is vouched for, as a key from a site is.
- **Anchored**: its chain ends in a self-signed certificate inside the file,
  the **anchor**, which is the leaf itself for a self-signed key. Each
  certificate's signature MUST verify by the next one's key, and the anchor's
  by its own. Each MUST be valid at the trusted time and be ECDSA P-256,
  signed with SHA-256 or SHA-384. A CA certificate in the chain, the anchor
  of a longer one included, MUST have basicConstraints CA and `keyCertSign`.
  The leaf MUST meet what §9.2 asks of a credential's key: `digitalSignature`,
  not a CA, the credential EKU and no unknown critical extension. An anchored
  entry's window MUST lie inside its leaf's validity.

An entry's key is its leaf's: a key file carries no key apart from its
certificates.

A file's entries MUST be all certified or all anchored, and an anchored
file's entries MUST share one anchor. A verifier MUST refuse any other file,
and one with an entry of neither kind. A key file never vouches for a bundle,
a revocation feed or a log key statement: its keys sign credentials only.

A verifier MUST refuse a file with a leaf that carries the infrastructure EKU.
That is a site's deployment key, which belongs on its site's signer and never
in a file that is sent around.

The **fingerprint** of an anchored file is the SHA-256 of its anchor's DER
SPKI, shown as 16 groups of 4 upper-case hex digits. It is what a person
compares with the sender's.

A file's **id** is its fingerprint when anchored, and the SHA-256 of its first
entry's leaf's DER SPKI when certified.

A deny-list (§9.2) withdraws a key file's entry by fingerprint only, from
whichever site's bundle it came. A key id is its own deployment's, and the
same number in a key file names another key. An entry is refused when its
leaf's fingerprint is denied, or, when certified, its Organization CA's. An
anchored file whose anchor's fingerprint is denied is refused whole.

§8 step 6 holds for both kinds: when the leaf names an organization,
`issuer_id` MUST equal it.

### 19.3 Accepting one

A verifier:

1. reads the clear part, and refuses a file that §19.1 or §19.2 refuses, whose
   `notAfter` has passed by the trusted clock, or whose `issuedAt` is later
   than the trusted clock's now + 300 s. Without that bound, a file dated
   ahead would outlive §19.1's 31 days;
2. shows, before it asks for the passphrase, the name; the leaf's
   organization (`O`) and common name, as the file states them; who certified
   the leaf: the pinned CA, "itself" for a self-signed key, or the anchor's
   common name; the fingerprint of an anchored file; the epochs and tiers it
   opens; and its end;
3. opens `sealed` with the passphrase. A failure is reported as a wrong
   passphrase or a changed file, which it cannot tell apart, and nothing is
   kept. Success shows that the clear part is what the passphrase's holder
   sealed;
4. asks for the device owner's authentication, as for a pairing;
5. keeps the reading keys only wrapped by its own Secure Enclave key, as a
   bundle's are, keeps the clear part, and discards the file and the
   passphrase.

A file is known by its id (§19.2); its name identifies nothing. A file with
the id of one the verifier holds replaces that one when its `issuedAt` is
later, and is refused otherwise.

### 19.4 Reading with one

A key file is a key source of its own, beside the sites (DESIGN §11k). A code
whose public section one of its reading keys opens is checked against that
file's trust entries alone, the ones §19.2 accepted (§8, step 4), never a
site's, and a site's codes are never checked against a file's. When a site's key and a file's both open
a code, the site's reading is taken.

The file stops reading at its `notAfter`, and an entry at its leaf
certificate's end, both by the trusted clock, as a bundle's lease does.
Nothing renews it but a newer file.

A key file has no revocation filter, so §8 step 10 never flags a code read
with one. It has no log key either: what it reads goes into no site's
activity log (§15).

### 19.5 Presenting a result

A result read with an **anchored** key MUST NOT be presented as one that a
site or a pinned CA vouches for. It is:
- never in the color or under the title of a plain pass;
- named for its key file;
- never said to be issued by the organization the certificate names. That is
  the file's own claim, which nobody has checked: the document was signed by
  the key in the file.

Its verdict (§11) is unchanged. `valid` read with an anchored key is still
`valid`, presented as a pass with a qualification, and a refusal is presented
as the refusal it is, naming the key file.

A result read with a **certified** key is presented as a site's is, naming the
pinned CA as the issuer's certifier and, through an Organization CA, that
CA's domain. It MUST also carry a band, in the color of a pass with a
qualification, that says it was read with a key file, and it names the key
file in place of the site. So every result read with a key file carries that
color somewhere.

In the scan history (§18.2), a record read with a key file has `site` null and
`key_file` set. `valid` read with an anchored key is `verified_key_file`,
"Verified by key file".

## 20. Site list

A reader MAY be made to trust only **supported sites**: hosts it may pair
with, each with its **anchors**, the CAs and any raw keys allowed to vouch
for keys there (§9.2).
- The reader's build compiles in its default sites, the host it takes site
  lists from, and the CA that certifies their key.
- A site list adds sites and withdraws them.
- **Hosts.** A reader takes a site's host from the address it paired with,
  lowercased.
  - A host that is an IP address is never supported.
  - So is one that, once lowercased, is not ASCII letters, digits, hyphens
    and dots.

This section is a design until `ovcrypto/sitelist.py` and its vectors exist.

```
"CL03SL" 6 | version 1 | reserved 1
| issuedAt 4 | notAfter 4
| entryCount 2 | { action 1 | patternLen 1 | pattern N
                 | nameLen 1 | name N
                 | caCount 1 | { derLen 2 | der N } * } *
| sig 64
```

Integers are big-endian and unsigned. Times are seconds since 1970-01-01 UTC,
as in §9.

Signed bytes are `"OfflineVerifier/v1/site-list" 0x00` followed by everything
from `"CL03SL"` through the last entry. `sig` uses §6.1's encoding, and is
made by the key of the certificate sent beside the list.

- **`action`** is one of two values. Any other refuses the list.
  - **1 adds a site**, with `caCount` of 1 to 4.
  - **2 withdraws a pattern**, with `nameLen` 0 and `caCount` 0.
- **`pattern`** is a host name or a wildcard.
  - **A host name:**
    - has two labels or more, each 1-63 lowercase letters, digits or
      hyphens, neither starting nor ending with a hyphen;
    - takes a label beginning `xn--` as written: an A-label, never decoded;
    - has a last label that is not all digits, so no IPv4 address is one;
    - has no trailing dot, and is at most 253 bytes.
  - **A wildcard** is `*.` followed by such a host name. It matches a host
    with exactly one more label in front: `*.example.org` matches
    `a.example.org`, but neither `example.org` nor `a.b.example.org`.
- **`name`** is what a reader shows for an added site: UTF-8, 1-64 bytes, with
  no code point in Unicode's categories Cc, Cf, Zl or Zp.
- **`der`** is a CA certificate, at most 4096 bytes.
  - It is judged when it vouches for a key, at the trusted time, as a pinned
    CA is: basicConstraints with cA true, key usage `keyCertSign`, and a P-256
    key.
- **Order and size.**
  - Entries are in ascending byte order of `pattern`, each pattern once.
  - A list has 0 to 1024 entries, and is at most 256 KiB.

### 20.1 Transport

`GET /api/v1/site-list/`, on the host the build names, answers
`{"list": "<base64 CL03SL>", "chain": ["<base64 DER certificate>"]}`.
- `chain` holds exactly one certificate, the list key's. The CA the build
  compiles is never sent.
- The request carries no identifier and no cookie.

### 20.2 Client rules

A reader MUST refuse a list unless all of these hold:

1. **The certificate.** `chain` holds exactly one certificate. It validates
   at the trusted time directly under the CA the build compiles for site
   lists, and under no other. It has:
   - ECDSA P-256 with SHA-256 or SHA-384;
   - key usage with `digitalSignature`, critical or not;
   - basicConstraints absent, or with cA false;
   - the site-list EKU `2.25.195449750565970907562665581081746257696`, and
     neither of §9.2's two EKUs;
   - no unknown critical extension;
   - a subjectAltName whose dNSNames include the build's list host,
     compared whole as lowercase ASCII, with no wildcard.
2. **The signature.** `sig` verifies over the signed bytes with that key.
3. **The parse.** The list parses whole, with nothing after `sig`:
   `version` 1, `reserved` 0, every `action` known, every pattern and name
   as above, the entries in order, and within the limits.
4. **The window.** `issuedAt` ≤ now + 300 s, `notAfter` > `issuedAt`, and
   `notAfter` − `issuedAt` ≤ 31 days.
5. **The order.** `issuedAt` is later than the held list's, unless the list
   is byte for byte the one held.

An accepted list replaces the one held. The reader keeps it through a reset.
A CA certificate the reader cannot parse drops only itself, and an addition
left with none. The rest of the list stands.

### 20.3 Supported sites

For a host H, a reader works from the build's defaults and the list it
holds:

1. **Candidates** are the build's default patterns that match H, and the
   list's entries that match H. If any default pattern matches H, the list's
   additions are left out.
2. **The most specific candidate decides:** an exact host before a wildcard,
   and a withdrawal before a default of the same pattern.
3. **The result.**
   - If that candidate is a withdrawal, or there is no candidate, H is not
     supported.
   - Otherwise H's anchors are that entry's: its CAs, and for a default, the
     raw keys the build binds to it.
4. **An ended list.** Once now > the held list's `notAfter`, its additions
   no longer count. Its withdrawals still do.

At a supported site, the reader judges bundles, feeds and statements (§9.2,
§14, §15.1) with H's anchors in place of the build's. H is the host the
reader paired with. The reader pairs, syncs and re-keys with no other host,
and reads no code with a site that is not supported.
