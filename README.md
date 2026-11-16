# CL03

**CL03** is a QR code and the way it is validated: the signed credential a
printed document carries, encrypted in two tiers under one signature, and
read by a phone **with no network**. The phone says whether the document is
genuine, unchanged and within its validity dates.

This repository hosts the CL03 specification, published under
[CC BY 4.0](#licence).

## The specification

<!-- editions:begin -->
The current edition is **v1.2** (wire format v1, 12 November 2026). Read it in [SPEC.md](SPEC.md), or as printed:

| Edition | Date | As printed |
|---|---|---|
| v1.2 | 12 November 2026 | [PDF, A4](pdf/cl03-spec%20-%20v1.2%20-%20A4.pdf) · [PDF, Letter](pdf/cl03-spec%20-%20v1.2%20-%20Letter.pdf) |
| v1.1 | 12 November 2026 | [PDF, A4](pdf/cl03-spec%20-%20v1.1%20-%20A4.pdf) · [PDF, Letter](pdf/cl03-spec%20-%20v1.1%20-%20Letter.pdf) |
<!-- editions:end -->

SPEC.md is the text of the current edition, the same words as its PDF. v1.2
has the text of v1.1, and its colophon adds the licence.

A published edition is never changed: a correction is a new version, and
every edition published here stays in [pdf/](pdf/). The specification's
version is the document's own. The wire format has its own version, carried
in every credential.

### What it covers

| Section | |
|---|---|
| §1 to §8 | The credential: the QR string, the payload and its two encrypted sections, the claims, the signed bytes, the key schedule and the verification order |
| §9 | The key bundle a verifying device syncs: its keys, its trust list, and who may sign |
| §10, §14 | Revocation: the filter, and the signed feed that carries it |
| §11 | The verdicts a verifier reports |
| §12 | The portrait symbol, a second code that carries the holder's photograph |
| §13 | The ticket QR, which hands a phone one operation: enrol, sync or re-key |
| §15, §16 | The device's activity log, and the organizations a device works for |
| §17 | Attachments, carried inside the credential or split across part symbols |

### In brief

- **The QR string** is `CL03:` followed by Base45 (RFC 9285), so the whole
  code stays in QR alphanumeric mode.
- **Two tiers under one signature.** The public section holds the document's
  provenance, and the restricted section the holder's details. Each is
  encrypted to the audience key of its tier (X25519, HKDF-SHA256,
  AES-256-GCM). The issuer's signature covers the public claims and a SHA-256
  of the restricted section, so a device that holds only the public-tier key
  verifies the whole credential and cannot read the holder's details.
- **The signature comes before trust.** The verification order is normative
  (§8), and nothing decrypted is trusted until the signature verifies:
  decryption only proves that the sender held an audience key, and every
  verifying device holds one.
- **A stale device is not a bad document.** A device without the key for a
  credential's epoch reports `device_stale`, a statement about the device
  and never about the document (§11).
- **Revocation is advisory offline.** A hit in the revocation filter means
  "confirm online", and does not change the verdict (§10, §14).

## Implementations

The offline verification system built on this specification, the reader app
together with the sites that issue the credentials, is **the CL03
implementation**.

### Reader

**[OVX CL03 Reader](https://apps.apple.com/app/id6835029462)**, for iPhone,
on the App Store. It reads a CL03 code with the camera and validates it on
the phone, offline. A phone is paired with an organization's site, keeps
that organization's keys up to date, and can then show the details a
document carries for it.

### Systems

These systems implement the specification and use it in service. Both run
**Verify**, a National ID verification site: an operator checks a person's
Philippine National ID against the Philippine Statistics Authority's eVerify
service and prints a verification document. The document carries a CL03
credential and its portrait symbol, and the site pairs the phones that
verify it.

| Site | |
|---|---|
| [clik.philsys.gov.ph](https://clik.philsys.gov.ph/) | Verify PSA, running for the Philippine Statistics Authority |
| [verify.x.trl.ph](https://verify.x.trl.ph/) | The TRL Experience Center, at the Technical Resource Lab (TRL) |

## Licence

The CL03 specification, in every form in this repository (SPEC.md and the
PDFs in pdf/), is licensed under the **Creative Commons Attribution 4.0
International** licence,
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The full text is
in [LICENSE](LICENSE).

You may copy and redistribute the specification, and adapt it, for any
purpose, commercial ones included, as long as you give appropriate credit,
link to the licence, and say whether you changed it. Credit it as follows,
and name the edition you used:

> CL03 specification. © 2026 Ateneo de Manila University, Business Insights
> Laboratory for Development, Technical Resource Lab (Ateneo BUILD-TRL).
> Licensed under CC BY 4.0. https://github.com/Ateneo-BUILD/CL03

The licence covers the specification and nothing else:

- The names and logos of Ateneo de Manila University, Ateneo BUILD and TRL
  are not licensed under CC BY 4.0, which licenses no trademark rights (its
  Section 2(b)(2)). They are on the printed editions to say who prepared the
  specification.
- The implementations listed above are separate works, under their own
  terms.
- The [code of conduct](CODE_OF_CONDUCT.md) is adapted from the Contributor
  Covenant, which that file credits.

## Contributing

Questions, corrections and proposals are welcome.
[CONTRIBUTING.md](CONTRIBUTING.md) says how to send one, and how a change
reaches the specification. A security flaw is reported privately, as
[SECURITY.md](SECURITY.md) describes, and not in an issue. The
[code of conduct](CODE_OF_CONDUCT.md) applies to everyone who takes part,
and [CONTRIBUTORS.md](CONTRIBUTORS.md) names those who have contributed.

## Prepared by

Ateneo BUILD-TRL: the Business Insights Laboratory for Development (Ateneo
BUILD) and the Technical Resource Lab (TRL), John Gokongwei School of
Management, Ateneo de Manila University.
[trl.ph](https://trl.ph) · [ateneo.edu/jgsom/build](https://ateneo.edu/jgsom/build)

The author and the contact for the specification are named on the cover and
in the colophon of each printed edition.
