# Security

CL03 is a format for signed, encrypted credentials. A flaw in the
specification can matter to everyone who relies on a CL03 code, so please
report one privately, and not in a public issue.

## What to report here

A weakness in the specification itself: something in the format, or in the
rules an issuer or a verifier follows, that would let a credential be forged,
altered or replayed, read by a device that should not read it, or accepted
when it should be refused. Wording that would lead a careful implementer to
build something unsafe counts as well.

The current edition is the one that is maintained. Say which edition and
which section you mean.

## How to report

1. Use **Report a vulnerability** on this repository's
   [Security tab](https://github.com/Ateneo-BUILD/CL03/security/advisories/new).
   The report is private to the maintainers.
2. If you cannot use that, write to rlozada@ateneo.edu.

Say what an attacker needs and what they gain. A credential or a sequence of
bytes that shows the flaw helps most. Use invented data: never send a real
person's details or the code from a real document.

## What happens next

We read every report, confirm that we have received it, and tell you what we
conclude. A confirmed flaw is corrected in a new edition of the
specification, since a published edition is never changed. With your
agreement, you are named in [CONTRIBUTORS.md](CONTRIBUTORS.md).

Please give us time to correct the specification, and to tell those who run
CL03 systems, before you publish.

## Implementations

A flaw in one implementation, and not in the specification, goes to whoever
runs it:

- **OVX CL03 Reader**: its
  [support page](https://ritchielozada.com/verifyx/support/).
- **VerifyX - CL03 Reader**: its
  [support page](https://verify.x.trl.ph/static/branding/verifyx/support.html).
- **A site that issues CL03 credentials**: the organization that operates it.

If you cannot tell whether a flaw is in the specification or in an
implementation, report it here, privately, and we will pass it on.
