import { ByteReader, formatSize } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

const CKSUM_ALGS: Record<number, string> = { 0: 'none', 1: 'SHA-1', 2: 'MD5', 3: 'SHA-256', 4: 'SHA-512' }

/**
 * xar (eXtensible ARchive) — the container behind macOS .pkg installers and
 * .xip archives (how Xcode ships). A binary header + zlib-compressed XML
 * table of contents + heap of file data.
 */
export const xar: FormatDef = {
  id: 'xar',
  name: 'xar archive (.pkg/.xip)',
  detect: (b) => startsWith(b, sigOf('xar!')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []

    try {
      const r = new ByteReader(bytes, 4)
      const headerSize = r.u16be()
      const version = r.u16be()
      const tocCompressed = Number(r.u64be())
      const tocUncompressed = Number(r.u64be())
      const cksumAlg = r.u32be()

      regions.push(
        region('Header', 0, headerSize, {
          value: `xar v${version}`,
          note: 'macOS .pkg installers, .xip archives and Safari extensions are all xar files. List one with: xar -tf file.pkg',
          children: [
            region('Magic', 0, 4, { value: '"xar!"', flag: 'ok' }),
            region('Header size', 4, 2, { value: `${headerSize} B` }),
            region('Version', 6, 2, { value: String(version) }),
            region('TOC length (compressed)', 8, 8, { value: formatSize(tocCompressed) }),
            region('TOC length (uncompressed)', 16, 8, { value: formatSize(tocUncompressed) }),
            region('Checksum algorithm', 24, 4, { value: `${cksumAlg} — ${CKSUM_ALGS[cksumAlg] ?? 'unknown'}`, note: 'Algorithm used for the TOC checksum stored at the start of the heap.' }),
          ],
        }),
      )

      const tocStart = headerSize
      if (tocStart + tocCompressed <= bytes.length) {
        const isZlib = bytes[tocStart] === 0x78
        regions.push(
          region('Table of contents (zlib XML)', tocStart, tocCompressed, {
            value: `${formatSize(tocCompressed)} → ${formatSize(tocUncompressed)}`,
            note: `An XML document listing every file, its offsets in the heap, checksums and — for .pkg — the install scripts. ${isZlib ? 'Starts with 0x78: a zlib stream.' : ''} Signatures (pkgutil --check-signature) also live here.`,
          }),
        )
        const heapStart = tocStart + tocCompressed
        if (heapStart < bytes.length) {
          regions.push(
            region('Heap (file data)', heapStart, bytes.length - heapStart, {
              value: formatSize(bytes.length - heapStart),
              note: 'Concatenated file contents, individually compressed, located via the TOC offsets. First bytes are usually the TOC checksum.',
            }),
          )
        }
      } else {
        warnings.push('TOC extends past end of file — truncated download?')
      }

      summary.push(`xar v${version}, TOC ${formatSize(tocCompressed)} (${formatSize(tocUncompressed)} uncompressed), ${CKSUM_ALGS[cksumAlg] ?? '?'} checksums`)
      summary.push('If this is a .pkg: pkgutil --expand file.pkg outdir · if a .xip: xip --expand file.xip')
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }

    return { format: 'xar archive (.pkg/.xip)', summary, regions, warnings }
  },
}
