import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { detectFormat } from '../src/core/formats/index'

const dir = join(__dirname, '..', 'public', 'demo')

const EXPECTED: Record<string, string> = {
  'demo.png': 'png',
  'demo.jpg': 'jpeg',
  'demo.gif': 'gif',
  'demo.bmp': 'bmp',
  'demo.wav': 'riff',
  'demo.m4a': 'mp4',
  'demo.zip': 'zip',
  'demo.txt.gz': 'gzip',
  'demo.tar': 'tar',
  'demo.sqlite': 'sqlite',
  'demo.plist': 'bplist',
  'demo.dmg': 'dmg',
  'demo.xar': 'xar',
  'demo.icns': 'icns',
  'apple-double.bin': 'applefork',
  'demo.macho': 'macho',
  'Demo.class': 'class',
  'demo.elf': 'elf',
  'demo.exe': 'pe',
  'demo.wasm': 'wasm',
  'demo.pdf': 'pdf',
}

describe('demo files', () => {
  it('covers every file in public/demo', () => {
    expect(readdirSync(dir).filter((f) => !f.startsWith('.')).sort()).toEqual(Object.keys(EXPECTED).sort())
  })

  // Spot-checks that the parsed *content* is right, so field-misalignment bugs
  // in generated demos can't slip through as "parses without crashing".
  const CONTENT_CHECKS: Record<string, RegExp> = {
    'demo.png': /48 × 48/,
    'demo.jpg': /48 × 48/,
    'demo.elf': /x86-64.*entry point 0x400078|64-bit LSB EXEC/s,
    'demo.exe': /PE32\+.*console|console.*PE32\+/s,
    'demo.macho': /ARM64|x86-64/,
    'demo.sqlite': /512 B pages/,
    'demo.plist': /root: \{/,
    'demo.dmg': /UDIF v4/,
    'Demo.class': /compiled for Java/,
    'demo.wav': /440|PCM/,
  }

  for (const [file, id] of Object.entries(EXPECTED)) {
    it(`${file} → ${id}, parses without crashing`, () => {
      const bytes = new Uint8Array(readFileSync(join(dir, file)))
      const fmt = detectFormat(bytes)
      expect(fmt?.id).toBe(id)
      const out = fmt!.parse(bytes)
      expect(out.regions.length).toBeGreaterThan(0)
      expect(out.summary.length).toBeGreaterThan(0)
      const check = CONTENT_CHECKS[file]
      if (check) expect(out.summary.join(' | ')).toMatch(check)
      console.log(`${file}: ${out.format} | ${out.summary[0]}${out.warnings.length ? ' | WARN: ' + out.warnings.join('; ') : ''}`)
    })
  }

  it('the wasm demo actually instantiates and adds', async () => {
    const bytes = readFileSync(join(dir, 'demo.wasm'))
    const { instance } = await WebAssembly.instantiate(bytes)
    expect((instance.exports.add as (a: number, b: number) => number)(40, 2)).toBe(42)
  })
})
