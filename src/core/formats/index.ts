import { bytesToHex } from '../bytes'
import { region, type ParseResult } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'
import { png } from './png'
import { jpeg } from './jpeg'
import { gif } from './gif'
import { zip } from './zip'
import { gzip } from './gzip'
import { elf } from './elf'
import { pe } from './pe'
import { riff } from './riff'
import { bmp } from './bmp'
import { mp4 } from './mp4'
import { pdf } from './pdf'
import { sqlite } from './sqlite'
import { wasm } from './wasm'
import { tar } from './tar'
import { macho } from './macho'
import { jvmClass } from './jvm'

export type { FormatDef } from './def'

/** Formats we can identify but do not (yet) walk structurally. */
function stub(id: string, name: string, sig: number[], note: string, offset = 0): FormatDef {
  return {
    id,
    name,
    detect: (b) => startsWith(b, sig, offset),
    parse(bytes): ParseResult {
      return {
        format: name,
        summary: [note],
        regions: [
          region('Magic bytes', offset, sig.length, {
            value: bytesToHex(new Uint8Array(sig)),
            note,
            flag: 'ok',
          }),
        ],
        warnings: ['detailed structure parsing for this format is not implemented yet — magic-byte identification only'],
      }
    },
  }
}

const STUBS: FormatDef[] = [
  stub('7z', '7-Zip archive', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], '"7z¼¯\'\\x1c" — 7-Zip archive, LZMA/LZMA2 compression.'),
  stub('rar', 'RAR archive', sigOf('Rar!\x1a\x07'), '"Rar!" — RAR archive (byte 7 distinguishes v4 from v5).'),
  stub('xz', 'XZ compressed data', [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], '"\\xFD7zXZ\\0" — XZ container around an LZMA2 stream.'),
  stub('zstd', 'Zstandard compressed data', [0x28, 0xb5, 0x2f, 0xfd], 'Zstandard frame magic 0xFD2FB528 (stored little-endian).'),
  stub('bzip2', 'bzip2 compressed data', sigOf('BZh'), '"BZh" + block-size digit — bzip2, Burrows-Wheeler transform.'),
  stub('ogg', 'Ogg container', sigOf('OggS'), '"OggS" — Ogg page header (Vorbis, Opus, Theora live inside).'),
  stub('flac', 'FLAC audio', sigOf('fLaC'), '"fLaC" — Free Lossless Audio Codec stream.'),
  stub('mp3', 'MP3 audio (ID3 tag)', sigOf('ID3'), '"ID3" — an ID3v2 metadata tag; MPEG audio frames follow it.'),
  stub('tiff-le', 'TIFF image (little-endian)', [0x49, 0x49, 0x2a, 0x00], '"II*\\0" — Intel byte order. TIFF is a directory of tagged fields (EXIF reuses it).'),
  stub('tiff-be', 'TIFF image (big-endian)', [0x4d, 0x4d, 0x00, 0x2a], '"MM\\0*" — Motorola byte order.'),
  stub('woff2', 'WOFF2 web font', sigOf('wOF2'), '"wOF2" — Brotli-compressed OpenType font.'),
  stub('woff', 'WOFF web font', sigOf('wOFF'), '"wOFF" — zlib-compressed OpenType font.'),
  stub('parquet', 'Apache Parquet', sigOf('PAR1'), '"PAR1" — columnar data file; the real metadata sits in the footer.'),
  stub('pcap', 'pcap capture', [0xd4, 0xc3, 0xb2, 0xa1], 'Little-endian pcap magic (µs timestamps). Try extracting one frame and pasting it into the Packet Decoder →'),
  stub('pcap-be', 'pcap capture (big-endian)', [0xa1, 0xb2, 0xc3, 0xd4], 'Big-endian pcap magic.'),
  stub('pcapng', 'pcapng capture', [0x0a, 0x0d, 0x0d, 0x0a], 'pcapng Section Header Block. Try extracting one frame and pasting it into the Packet Decoder →'),
  stub('ico', 'Windows icon', [0x00, 0x00, 0x01, 0x00], 'ICO header — a directory of BMP/PNG images at multiple sizes.'),
]

/** Ordered registry — most specific magics first; weak 2-byte magics (MZ, BM) last. */
export const FORMATS: FormatDef[] = [
  png,
  jpeg,
  gif,
  gzip,
  elf,
  macho,
  jvmClass,
  wasm,
  sqlite,
  pdf,
  zip,
  mp4,
  riff,
  tar,
  ...STUBS,
  bmp,
  pe,
]

export function detectFormat(bytes: Uint8Array): FormatDef | null {
  return FORMATS.find((f) => f.detect(bytes)) ?? null
}
