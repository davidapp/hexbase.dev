# Security Policy

hexbase.dev is a local-first developer tool site: the tools parse files, packets,
tokens and certificates entirely in the browser, and a small Cloudflare Worker
handles share links. If you found a vulnerability, we genuinely want to hear
about it.

## Reporting a vulnerability

- **Email:** [support@hexbase.dev](mailto:support@hexbase.dev)
- **Machine-readable:** <https://hexbase.dev/.well-known/security.txt> (RFC 9116)

Please include enough detail to reproduce — a crafted input file or a request
transcript is ideal. You can expect a first reply within a few days.

## Scope

- The Worker API (`/api/*`), share links (`/s/*`), and rate limiting
- The client-side parsers (`src/core/**`): a crafted input that makes a parser
  hang, crash the tab, or mislead the user about what the bytes contain is a
  bug worth reporting; anything that escalates beyond the page is a
  vulnerability
- Data-handling claims: anything that contradicts the privacy policy
  (e.g. tool input leaving the browser without an explicit Share) is treated
  as a serious bug

Out of scope: issues in Cloudflare's platform itself, and reports that require
a compromised browser or machine.

## Disclosure

No bounty program — this is a free site — but reporters are credited (with
permission) in the fix's release notes. Please give us a few days to ship a
fix before public disclosure; the deployed site (`main`) is the only supported
version.
