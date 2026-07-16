#!/usr/bin/env node
/**
 * Regenerates public/demo/* — the representative demo files for the hex inspector.
 *
 * Run on macOS (uses sips, zip, sqlite3, plutil, hdiutil, xar, iconutil, clang,
 * javac, afconvert, ditto). Outputs are committed to git, so this only needs to
 * run when a demo should change. Constructed formats (ELF, PE, WASM, PDF, PNG,
 * WAV) are genuinely valid: the ELF runs on Linux, the PE on Windows, the WASM
 * instantiates, the PDF opens.
 */
import { execSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { deflateSync } from 'node:zlib'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const out = join(root, 'public', 'demo')
mkdirSync(out, { recursive: true })
const work = mkdtempSync(join(tmpdir(), 'hexbase-demos-'))

const sh = (cmd, cwd = work) => execSync(cmd, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
const put = (name, bytes) => writeFileSync(join(out, name), bytes)

// ---------------------------------------------------------------- helpers

const ascii = (s) => [...s].map((c) => c.charCodeAt(0))
const u16le = (v) => [v & 0xff, (v >> 8) & 0xff]
const u32le = (v) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]
const u32be = (v) => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
const u64le = (v) => [...u32le(v % 2 ** 32), ...u32le(Math.floor(v / 2 ** 32))]

function cat(...parts) {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)))
  const buf = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0))
  let off = 0
  for (const a of arrays) {
    buf.set(a, off)
    off += a.length
  }
  return buf
}

let CRC_TABLE = null
function crc32(bytes) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      CRC_TABLE[n] = c >>> 0
    }
  }
  let c = 0xffffffff
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

const README_TEXT = `hexbase.dev demo archive
========================

Every file in this archive exists to be taken apart.
Open it in the hex inspector and follow the offsets.

Fun fact: this ZIP's real index (the central directory)
lives at the END of the file, not the beginning.
`

// ---------------------------------------------------------------- 1. PNG (constructed, displays a real 48x48 gradient)

function makePng() {
  const W = 48
  const H = 48
  const raw = []
  for (let y = 0; y < H; y++) {
    raw.push(0) // filter: none
    for (let x = 0; x < W; x++) {
      raw.push((x * 255 / W) | 0, (y * 255 / H) | 0, 0x99, 255)
    }
  }
  const chunk = (type, data) => {
    const td = cat(ascii(type), data)
    return cat(u32be(data.length), td, u32be(crc32(td)))
  }
  return cat(
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    chunk('IHDR', [...u32be(W), ...u32be(H), 8, 6, 0, 0, 0]),
    chunk('tEXt', [...ascii('Software'), 0, ...ascii('hexbase.dev demo generator')]),
    chunk('tEXt', [...ascii('Comment'), 0, ...ascii('open me in the hex inspector')]),
    chunk('pHYs', [...u32be(2835), ...u32be(2835), 1]),
    chunk('IDAT', deflateSync(Buffer.from(raw))),
    chunk('IEND', []),
  )
}
put('demo.png', makePng())

// ---------------------------------------------------------------- 2-4. JPEG / GIF / BMP via sips from the PNG

sh(`sips -s format jpeg ${join(out, 'demo.png')} --out demo.jpg >/dev/null`)
sh(`sips -s format gif ${join(out, 'demo.png')} --out demo.gif >/dev/null`)
sh(`sips -s format bmp ${join(out, 'demo.png')} --out demo.bmp >/dev/null`)
for (const f of ['demo.jpg', 'demo.gif', 'demo.bmp']) put(f, readFileSync(join(work, f)))

// ---------------------------------------------------------------- 5. WAV (constructed, playable 440 Hz beep)

function makeWav() {
  const rate = 8000
  const seconds = 0.4
  const n = Math.floor(rate * seconds)
  const samples = []
  for (let i = 0; i < n; i++) {
    const env = Math.min(1, i / 200, (n - i) / 200) // fade in/out
    const v = Math.round(Math.sin((2 * Math.PI * 440 * i) / rate) * 12000 * env)
    samples.push(...u16le(v < 0 ? v + 0x10000 : v))
  }
  const dataLen = samples.length
  return cat(
    ascii('RIFF'), u32le(36 + dataLen), ascii('WAVE'),
    ascii('fmt '), u32le(16), u16le(1), u16le(1), u32le(rate), u32le(rate * 2), u16le(2), u16le(16),
    ascii('data'), u32le(dataLen), samples,
  )
}
put('demo.wav', makeWav())

// ---------------------------------------------------------------- 6. M4A (real AAC in an MP4 container via afconvert)

sh(`afconvert -f m4af -d aac ${join(out, 'demo.wav')} demo.m4a`)
put('demo.m4a', readFileSync(join(work, 'demo.m4a')))

// ---------------------------------------------------------------- 7-9. ZIP / gzip / tar from a small doc tree

writeFileSync(join(work, 'readme.txt'), README_TEXT)
mkdirSync(join(work, 'docs'), { recursive: true })
writeFileSync(join(work, 'docs', 'magic-numbers.md'), '# Magic numbers\n\nPNG: 89 50 4E 47 · ZIP: PK.. · ELF: 7F 45 4C 46\n')
writeFileSync(join(work, 'docs', 'endianness.md'), '# Endianness\n\nThe names come from Gulliver\'s Travels (Danny Cohen, 1980).\n')
sh('zip -X -9 -q demo.zip readme.txt docs/magic-numbers.md docs/endianness.md')
put('demo.zip', readFileSync(join(work, 'demo.zip')))
sh('gzip -9 -N -k readme.txt && mv readme.txt.gz demo.txt.gz')
put('demo.txt.gz', readFileSync(join(work, 'demo.txt.gz')))
sh('tar --format=ustar -cf demo.tar readme.txt docs')
put('demo.tar', readFileSync(join(work, 'demo.tar')))

// ---------------------------------------------------------------- 10. SQLite (real database, 512-byte pages)

sh(`sqlite3 demo.sqlite "PRAGMA page_size=512; PRAGMA application_id=0x68657862; PRAGMA user_version=7; CREATE TABLE magic(format TEXT PRIMARY KEY, signature TEXT, since INTEGER); INSERT INTO magic VALUES('PNG','89504E47',1996),('ZIP','504B0304',1989),('ELF','7F454C46',1988),('SQLite','53514C69',2004); CREATE INDEX idx_since ON magic(since);"`)
put('demo.sqlite', readFileSync(join(work, 'demo.sqlite')))

// ---------------------------------------------------------------- 11. Binary plist (real, via plutil)

writeFileSync(
  join(work, 'src.json'),
  JSON.stringify({
    CFBundleName: 'HexbaseDemo',
    CFBundleVersion: '1.0.7',
    build: 42,
    localFirst: true,
    formats: ['png', 'zip', 'elf', 'bplist'],
    limits: { maxFileMB: 64, shareKB: 256 },
  }),
)
sh('plutil -convert binary1 -o demo.plist src.json')
put('demo.plist', readFileSync(join(work, 'demo.plist')))

// ---------------------------------------------------------------- 12. DMG (real UDZO image via hdiutil)

mkdirSync(join(work, 'dmgsrc'), { recursive: true })
writeFileSync(join(work, 'dmgsrc', 'readme.txt'), 'This volume lives inside a UDIF disk image.\nThe interesting part is the 512-byte koly block at the END of the .dmg file.\n')
sh('hdiutil create -srcfolder dmgsrc -format UDZO -volname HexbaseDemo -quiet demo.dmg')
put('demo.dmg', readFileSync(join(work, 'demo.dmg')))

// ---------------------------------------------------------------- 13. xar (real, via xar)

sh('xar -cf demo.xar readme.txt docs')
put('demo.xar', readFileSync(join(work, 'demo.xar')))

// ---------------------------------------------------------------- 14. icns (real, via iconutil)

mkdirSync(join(work, 'demo.iconset'), { recursive: true })
sh(`sips -z 16 16 ${join(out, 'demo.png')} --out demo.iconset/icon_16x16.png >/dev/null`)
sh(`sips -z 32 32 ${join(out, 'demo.png')} --out demo.iconset/icon_16x16@2x.png >/dev/null`)
sh(`sips -z 32 32 ${join(out, 'demo.png')} --out demo.iconset/icon_32x32.png >/dev/null`)
sh('iconutil -c icns demo.iconset -o demo.icns')
put('demo.icns', readFileSync(join(work, 'demo.icns')))

// ---------------------------------------------------------------- 15. AppleDouble (real ._ file via ditto --sequesterRsrc)

writeFileSync(join(work, 'noted.txt'), 'The metadata about this file travels in a separate ._ container.\n')
sh('xattr -w dev.hexbase.note "Every ._ file on your USB stick is an AppleDouble container" noted.txt')
sh('ditto -c -k --sequesterRsrc noted.txt sequestered.zip')
sh('unzip -o -q sequestered.zip -d sequestered')
put('apple-double.bin', readFileSync(join(work, 'sequestered', '__MACOSX', '._noted.txt')))

// ---------------------------------------------------------------- 16. Mach-O (real arm64 binary via clang)

writeFileSync(join(work, 'hello.c'), '#include <stdio.h>\nint main(void){ puts("hello from a Mach-O"); return 0; }\n')
sh('clang -Oz -o demo.macho hello.c && strip demo.macho')
put('demo.macho', readFileSync(join(work, 'demo.macho')))

// ---------------------------------------------------------------- 17. Java class (real, via javac)

writeFileSync(join(work, 'Demo.java'), 'public class Demo {\n  public static void main(String[] args) {\n    System.out.println("hello from the JVM");\n  }\n}\n')
sh('javac Demo.java')
put('Demo.class', readFileSync(join(work, 'Demo.class')))

// ---------------------------------------------------------------- 18. ELF (constructed 168-byte static x86-64 Linux executable — it really runs)

function makeElf() {
  const msg = ascii('Hello, hexbase\n')
  const code = [
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1        (sys_write)
    0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1        (stdout)
    0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, // lea rsi, [rip+16] (msg)
    0xba, 0x0f, 0x00, 0x00, 0x00, // mov edx, 15
    0x0f, 0x05, // syscall
    0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60       (sys_exit)
    0x31, 0xff, // xor edi, edi
    0x0f, 0x05, // syscall
  ]
  const fileSize = 120 + code.length + msg.length
  // e_ident is exactly 16 bytes: magic(4) class data version osabi abiver pad(7)
  const ident = new Uint8Array(16)
  ident.set([0x7f, ...ascii('ELF'), 2, 1, 1, 0, 0])
  const ehdr = [
    ...ident,
    ...u16le(2), ...u16le(0x3e), ...u32le(1),
    ...u64le(0x400078), // entry
    ...u64le(64), // phoff
    ...u64le(0), // shoff
    ...u32le(0), ...u16le(64), ...u16le(56), ...u16le(1), ...u16le(0), ...u16le(0), ...u16le(0),
  ]
  const phdr = [
    ...u32le(1), ...u32le(5), // PT_LOAD, R+X
    ...u64le(0), ...u64le(0x400000), ...u64le(0x400000),
    ...u64le(fileSize), ...u64le(fileSize), ...u64le(0x1000),
  ]
  return cat(ehdr, phdr, code, msg)
}
put('demo.elf', makeElf())

// ---------------------------------------------------------------- 19. PE (constructed 1 KiB x64 Windows executable — mov eax,42; ret)

function makePe() {
  const buf = new Uint8Array(0x400)
  const dv = new DataView(buf.buffer)
  buf.set(ascii('MZ'), 0)
  dv.setUint32(0x3c, 0x40, true)
  buf.set(ascii('PE\0\0'), 0x40)
  let p = 0x44
  const w16 = (v) => { dv.setUint16(p, v, true); p += 2 }
  const w32 = (v) => { dv.setUint32(p, v, true); p += 4 }
  const w64 = (v) => { dv.setBigUint64(p, BigInt(v), true); p += 8 }
  // COFF
  w16(0x8664); w16(1); w32(0x66aa0000); w32(0); w32(0); w16(240); w16(0x0022)
  // Optional header (PE32+)
  w16(0x020b); p += 2 // magic + linker version
  w32(0x200); w32(0); w32(0) // code/init/uninit sizes
  w32(0x1000); w32(0x1000) // entry point, base of code
  w64(0x140000000) // image base
  w32(0x1000); w32(0x200) // section/file alignment
  w16(6); w16(0); w16(0); w16(0); w16(6); w16(0) // OS/image/subsystem versions
  w32(0) // win32 version
  w32(0x2000); w32(0x200) // size of image / headers
  w32(0) // checksum
  w16(3) // subsystem: console
  w16(0x8160) // dll characteristics: HIGH_ENTROPY | ASLR | NX | TERMINAL_SERVER_AWARE
  w64(0x100000); w64(0x1000); w64(0x100000); w64(0x1000) // stack/heap
  w32(0); w32(16) // loader flags, number of RVAs
  p += 16 * 8 // empty data directories
  // Section table: .text
  buf.set(ascii('.text'), p); p += 8
  w32(0x10); w32(0x1000); w32(0x200); w32(0x200)
  w32(0); w32(0); w16(0); w16(0)
  w32(0x60000020) // CODE | EXECUTE | READ
  // code at raw 0x200
  buf.set([0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3], 0x200) // mov eax,42; ret
  return buf
}
put('demo.exe', makePe())

// ---------------------------------------------------------------- 20. WASM (constructed module exporting add(i32,i32) — it instantiates)

put(
  'demo.wasm',
  Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // type: (i32,i32)->i32
    0x03, 0x02, 0x01, 0x00, // function
    0x07, 0x07, 0x01, 0x03, ...ascii('add'), 0x00, 0x00, // export "add"
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, // code: local.get 0/1, i32.add
  ]),
)

// ---------------------------------------------------------------- 21. PDF (constructed with a correct xref — it opens)

function makePdf() {
  const content = 'BT /F1 16 Tf 24 100 Td (Hello from hexbase.dev) Tj ET'
  const objs = {
    1: '<< /Type /Catalog /Pages 2 0 R >>',
    2: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    3: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 280 140] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    4: `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    5: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  }
  let doc = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'
  const offsets = {}
  for (const [num, body] of Object.entries(objs)) {
    offsets[num] = doc.length
    doc += `${num} 0 obj\n${body}\nendobj\n`
  }
  const xref = doc.length
  doc += 'xref\n0 6\n0000000000 65535 f \n'
  for (let i = 1; i <= 5; i++) doc += String(offsets[i]).padStart(10, '0') + ' 00000 n \n'
  doc += `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`
  return Buffer.from(doc, 'latin1')
}
put('demo.pdf', makePdf())

// ---------------------------------------------------------------- report

rmSync(work, { recursive: true, force: true })
const files = execSync(`ls ${out}`).toString().trim().split('\n').sort()
let total = 0
for (const f of files) {
  const size = statSync(join(out, f)).size
  total += size
  console.log(String(size).padStart(8), f)
}
console.log(String(total).padStart(8), `TOTAL (${files.length} files)`)
