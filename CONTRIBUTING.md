# Contributing

Questions, corrections and proposals for the CL03 specification are welcome.
This page says how to send one, and how a change reaches the specification.

## Ways to contribute

- **Ask a question.** If a section is unclear, open an issue. An unclear rule
  is a defect in the text.
- **Report an error.** Name the edition and the section, quote the words, and
  say what you expected them to say.
- **Propose a change.** Open an issue that says what should change and why. A
  change to what is on the wire affects credentials already printed and
  phones already paired, so say what it does to them.
- **Tell us about an implementation.** If you have built a reader or an
  issuer from this specification, open an issue. We will consider listing it
  in the README.

A security flaw is the exception. Do not open an issue for one: report it
privately, as [SECURITY.md](SECURITY.md) describes.

## What makes a report easy to act on

- The edition (v1.2, say) and the section number.
- For a disagreement between the text and what an implementation does, the
  bytes involved, in hex or as the QR string.
- Invented data only. Never post a real person's details or the code from a
  real document.

## How a change reaches the specification

SPEC.md and the PDFs are published here from the repository of the CL03
implementation, where the text is written beside the reference code and its
test vectors. So:

- A pull request against SPEC.md is welcome as a way to show the wording you
  propose, but it is not merged as it stands. An accepted change is made at
  the source and arrives here with the next edition.
- A published edition is never edited. A correction is a new version, and
  earlier editions stay in [pdf/](pdf/).
- Pull requests to the other files, this one included, are merged in the
  usual way.

## Licence of contributions

By contributing, you agree that your contribution is licensed under
[CC BY 4.0](LICENSE), the licence of the specification, and that you have the
right to offer it.

## Credit

People whose reports or proposals change the specification are named in
[CONTRIBUTORS.md](CONTRIBUTORS.md), with their agreement.

## Conduct

The [code of conduct](CODE_OF_CONDUCT.md) applies to issues, pull requests
and every other place where this specification is discussed.
