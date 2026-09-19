# Contributing to hexbase.dev

Thanks for looking. The best contributions to this project are **parsers that
teach** — code that walks a format field by field *and* explains what each
field means. If you know a binary format well, this is the place to put that
knowledge where people will actually meet it.

## Ground rules

- **Local-first is non-negotiable.** Tool input never leaves the browser
  except through the explicit Share button. No analytics scripts, no third-
  party assets, no CDNs — the site loads nothing from other origins, and the
  Content-Security-Policy enforces it.
- **Zero runtime dependencies on the frontend.** Plain TypeScript, no
  framework. The Worker's only dependency is Hono.
- **Every parser is tested** against a real, redistributable specimen.
- **Notes are for humans.** A `Region`'s `note` should explain *why* the field
  exists or what the value implies, not restate its name.

## Getting started

```bash
npm install
npm run types        # generates Worker env types (needed for typecheck)
npm test             # vitest — core parsers, decoders, tools
npm run typecheck    # site/core and worker tsconfigs
npm run dev          # vite build + wrangler dev → http://localhost:8787
```

CI runs test → typecheck → build on every pull request; it needs no secrets,
so it works for forks.

## Adding a file format parser (the most common contribution)

Formats the inspector can *identify* but not yet *walk* are the `detect`-only
stubs in `src/core/formats/index.ts` — each is an open `good first issue`.
A complete parser is four pieces:

1. **Parser** — `src/core/formats/<format>.ts` exporting a `FormatDef`
   (`id`, `name`, `detect(bytes)`, `parse(bytes) → ParseResult`). Build the
   `Region` tree with `region(name, offset, length, { value, note, flag,
   children })` from `src/core/region.ts`; use `ByteReader` from
   `src/core/bytes.ts` for reading. Register it in the `FORMATS` array in
   `index.ts` — order matters: specific magics before weak ones (`MZ`, `BM`
   are last) — and delete the stub.
2. **Specimen** — a small, genuinely valid file in `public/demo/`. Prefer
   generating it in `scripts/make-demos.mjs`: constructed formats (ELF, PE,
   WASM, PDF, PNG, WAV) are built there in plain JavaScript and run on any OS;
   the macOS-toolchain section is only for formats that need Apple tools.
   Never commit a file you don't have the right to redistribute.
3. **Tests** — add the specimen to `EXPECTED` in `test/demos.test.ts` (it
   asserts every demo detects as its format) and structural assertions in
   `test/formats.test.ts` (dimensions, chunk names, checksums — whatever a
   reader of that format would check first).
4. **Gallery + guide** — add the demo to `DEMO_GROUPS` in `site/js/demos.ts`
   with a one-line "what to look for". A format guide entry in
   `scripts/format-content-*.mjs` is optional but very welcome (see below for
   its license).

## Adding a packet layer

`src/core/packet/<layer>.ts` exports a `LayerFn` (`(bytes, off, ctx) →
LayerResult`); register it in `LAYERS` in `decode.ts` and wire the transition
from the layer below (EtherType, IP protocol number, or port). Add a sample to
`samples.ts` — samples are *generated* with correct checksums, not pasted —
and tests in `test/packet.test.ts`.

## Pull requests

- One parser or one fix per PR. Small PRs get reviewed quickly.
- `npm test && npm run typecheck && npm run build` must pass locally.
- Describe how you verified it: which specimen, which viewer you compared
  against (`file`, `xxd`, Wireshark, `openssl asn1parse`, …).
- Screenshots for anything visible.

## Licensing of contributions

- **Code** you contribute is licensed under the project's MIT license.
- **Educational prose** (format guides, "§ Learn" and FAQ text) is licensed
  CC BY-NC-ND 4.0 like the rest of the site's content — by contributing prose
  you agree to that. Write it in your own words; don't paste from specs or
  other sites.

## Reporting security issues

Not in a public issue — see [SECURITY.md](SECURITY.md).
