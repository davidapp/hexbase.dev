import { describe, expect, it } from 'vitest'
import { epochById, interpretNumber, isoUtc, parseDateString, relativeTime } from '../src/core/timestamp'

describe('epoch conversions', () => {
  it('unix seconds / ms / µs / ns agree', () => {
    const ms = Date.UTC(2024, 0, 15, 12, 0, 0)
    expect(epochById('unix_s').toUnixMs(String(ms / 1000))).toBe(ms)
    expect(epochById('unix_ms').toUnixMs(String(ms))).toBe(ms)
    expect(epochById('unix_us').toUnixMs(String(ms * 1000))).toBe(ms)
    expect(epochById('unix_ns').toUnixMs(String(BigInt(ms) * 1000000n))).toBe(ms)
    expect(epochById('unix_ns').fromUnixMs(ms)).toBe((BigInt(ms) * 1000000n).toString())
  })
  it('FILETIME of the unix epoch is 116444736000000000', () => {
    expect(epochById('filetime').fromUnixMs(0)).toBe('116444736000000000')
    expect(epochById('filetime').toUnixMs('116444736000000000')).toBe(0)
  })
  it('.NET ticks of the unix epoch', () => {
    expect(epochById('dotnet').fromUnixMs(0)).toBe('621355968000000000')
  })
  it('NTP era-0 offset', () => {
    expect(epochById('ntp').toUnixMs('2208988800')).toBe(0)
  })
  it('Excel serial date: 25569 = 1970-01-01, 45292 = 2024-01-01', () => {
    expect(epochById('excel1900').toUnixMs('25569')).toBe(0)
    expect(epochById('excel1900').toUnixMs('45292')).toBe(Date.UTC(2024, 0, 1))
  })
  it('Cocoa epoch is 2001-01-01', () => {
    expect(epochById('cocoa').toUnixMs('0')).toBe(Date.UTC(2001, 0, 1))
  })
  it('HFS epoch is 1904-01-01', () => {
    expect(epochById('hfs').toUnixMs('2082844800')).toBe(0)
  })
  it('GPS applies the 18-second leap offset', () => {
    // GPS week 0 started 1980-01-06 00:00:00 UTC; GPS time 0 → unix 315964800 - 18
    expect(epochById('gps').toUnixMs('0')).toBe((315964800 - 18) * 1000)
  })
})

describe('interpretNumber', () => {
  it('prefers unix seconds for 10-digit values', () => {
    const out = interpretNumber('1700000000')
    expect(out[0].epoch.id).toBe('unix_s')
    expect(out[0].plausible).toBe(true)
    expect(isoUtc(out[0].unixMs)).toBe('2023-11-14T22:13:20Z')
  })
  it('prefers unix ms for 13-digit values', () => {
    expect(interpretNumber('1700000000000')[0].epoch.id).toBe('unix_ms')
  })
  it('finds a plausible reading for a FILETIME value', () => {
    const out = interpretNumber('133497696000000000') // 2024-01-15-ish
    const ft = out.find((o) => o.epoch.id === 'filetime')
    expect(ft?.plausible).toBe(true)
  })
})

describe('parse + format', () => {
  it('parses ISO strings', () => {
    expect(parseDateString('2024-01-15T12:00:00Z')).toBe(Date.UTC(2024, 0, 15, 12))
    expect(parseDateString('not a date')).toBeNull()
  })
  it('relative time reads naturally', () => {
    const now = Date.UTC(2024, 0, 15, 12)
    expect(relativeTime(now - 3 * 3600 * 1000, now)).toBe('3 hours ago')
    expect(relativeTime(now + 90 * 1000, now)).toBe('in 1.5 minutes')
    expect(relativeTime(now + 500, now)).toBe('now')
  })
})
