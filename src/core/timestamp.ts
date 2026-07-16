/**
 * Epoch conversions. Everything internal is Unix milliseconds (JS number);
 * tick-based epochs use BigInt at the boundary to avoid precision loss.
 */

export interface EpochDef {
  id: string
  name: string
  unit: string
  origin: string
  note: string
  /** Convert a value in this epoch to Unix milliseconds. */
  toUnixMs(value: string): number
  /** Convert Unix milliseconds to a value in this epoch (as string). */
  fromUnixMs(ms: number): string
}

const FILETIME_UNIX_OFFSET = 116444736000000000n // 100-ns ticks between 1601-01-01 and 1970-01-01
const DOTNET_UNIX_OFFSET = 621355968000000000n // ticks between 0001-01-01 and 1970-01-01
const NTP_UNIX_OFFSET = 2208988800 // seconds between 1900-01-01 and 1970-01-01
const HFS_UNIX_OFFSET = 2082844800 // seconds between 1904-01-01 and 1970-01-01
const COCOA_UNIX_OFFSET = 978307200 // seconds between 1970-01-01 and 2001-01-01
const GPS_UNIX_OFFSET = 315964800 // seconds between 1970-01-01 and 1980-01-06
const GPS_UTC_LEAP = 18 // GPS is ahead of UTC by 18 s (constant since 2017-01-01)
const EXCEL_UNIX_DAYS = 25569 // days between 1899-12-30 and 1970-01-01

function num(value: string): number {
  const v = Number(value.trim())
  if (!Number.isFinite(v)) throw new Error('not a finite number')
  return v
}

function big(value: string): bigint {
  try {
    return BigInt(value.trim())
  } catch {
    throw new Error('not an integer')
  }
}

export const EPOCHS: EpochDef[] = [
  {
    id: 'unix_s',
    name: 'Unix time (seconds)',
    unit: 'seconds',
    origin: '1970-01-01 00:00:00 UTC',
    note: 'The classic time_t. Signed 32-bit versions overflow on 2038-01-19 (the Y2038 problem).',
    toUnixMs: (v) => num(v) * 1000,
    fromUnixMs: (ms) => String(Math.floor(ms / 1000)),
  },
  {
    id: 'unix_ms',
    name: 'Unix time (milliseconds)',
    unit: 'milliseconds',
    origin: '1970-01-01 00:00:00 UTC',
    note: 'What JavaScript Date.now() and Java System.currentTimeMillis() return.',
    toUnixMs: (v) => num(v),
    fromUnixMs: (ms) => String(Math.round(ms)),
  },
  {
    id: 'unix_us',
    name: 'Unix time (microseconds)',
    unit: 'microseconds',
    origin: '1970-01-01 00:00:00 UTC',
    note: 'Common in databases (PostgreSQL) and tracing systems.',
    toUnixMs: (v) => num(v) / 1000,
    fromUnixMs: (ms) => String(Math.round(ms) * 1000),
  },
  {
    id: 'unix_ns',
    name: 'Unix time (nanoseconds)',
    unit: 'nanoseconds',
    origin: '1970-01-01 00:00:00 UTC',
    note: 'Go time.UnixNano(), eBPF, high-resolution log pipelines.',
    toUnixMs: (v) => Number(big(v) / 1000n) / 1000,
    fromUnixMs: (ms) => (BigInt(Math.round(ms)) * 1000000n).toString(),
  },
  {
    id: 'filetime',
    name: 'Windows FILETIME',
    unit: '100-ns ticks',
    origin: '1601-01-01 00:00:00 UTC',
    note: 'NTFS timestamps, Active Directory, registry. 1601 was the start of the 400-year Gregorian cycle in use when Windows NT was designed.',
    toUnixMs: (v) => Number((big(v) - FILETIME_UNIX_OFFSET) / 10000n),
    fromUnixMs: (ms) => (BigInt(Math.round(ms)) * 10000n + FILETIME_UNIX_OFFSET).toString(),
  },
  {
    id: 'dotnet',
    name: '.NET DateTime.Ticks',
    unit: '100-ns ticks',
    origin: '0001-01-01 00:00:00 UTC',
    note: 'C# DateTime.Ticks. 10,000 ticks per millisecond, counted from year 1.',
    toUnixMs: (v) => Number((big(v) - DOTNET_UNIX_OFFSET) / 10000n),
    fromUnixMs: (ms) => (BigInt(Math.round(ms)) * 10000n + DOTNET_UNIX_OFFSET).toString(),
  },
  {
    id: 'ntp',
    name: 'NTP timestamp (seconds)',
    unit: 'seconds',
    origin: '1900-01-01 00:00:00 UTC',
    note: 'The seconds half of the 64-bit NTP format. Rolls over in 2036 (era 1).',
    toUnixMs: (v) => (num(v) - NTP_UNIX_OFFSET) * 1000,
    fromUnixMs: (ms) => String(Math.floor(ms / 1000) + NTP_UNIX_OFFSET),
  },
  {
    id: 'excel1900',
    name: 'Excel serial date (1900 system)',
    unit: 'days (fractional)',
    origin: '1899-12-30 00:00:00',
    note: 'Excel/Sheets date serial. Day 1 = 1900-01-01. Values below 61 are off by one because Excel deliberately treats 1900 as a leap year (a Lotus 1-2-3 compatibility bug).',
    toUnixMs: (v) => (num(v) - EXCEL_UNIX_DAYS) * 86400000,
    fromUnixMs: (ms) => (ms / 86400000 + EXCEL_UNIX_DAYS).toFixed(6).replace(/\.?0+$/, ''),
  },
  {
    id: 'hfs',
    name: 'HFS+ / classic Mac',
    unit: 'seconds',
    origin: '1904-01-01 00:00:00 UTC',
    note: 'Classic Mac OS and HFS+ filesystem timestamps. 1904 was the first leap year of the 20th century.',
    toUnixMs: (v) => (num(v) - HFS_UNIX_OFFSET) * 1000,
    fromUnixMs: (ms) => String(Math.floor(ms / 1000) + HFS_UNIX_OFFSET),
  },
  {
    id: 'cocoa',
    name: 'Apple Cocoa / Core Data',
    unit: 'seconds',
    origin: '2001-01-01 00:00:00 UTC',
    note: 'NSDate timeIntervalSinceReferenceDate. Used in iOS/macOS plists and Core Data stores.',
    toUnixMs: (v) => (num(v) + COCOA_UNIX_OFFSET) * 1000,
    fromUnixMs: (ms) => String(Math.floor(ms / 1000) - COCOA_UNIX_OFFSET),
  },
  {
    id: 'gps',
    name: 'GPS time',
    unit: 'seconds',
    origin: '1980-01-06 00:00:00 UTC',
    note: 'GPS does not apply leap seconds, so it is currently 18 s ahead of UTC (constant since 2017). Conversion here applies that offset.',
    toUnixMs: (v) => (num(v) + GPS_UNIX_OFFSET - GPS_UTC_LEAP) * 1000,
    fromUnixMs: (ms) => String(Math.floor(ms / 1000) - GPS_UNIX_OFFSET + GPS_UTC_LEAP),
  },
]

export function epochById(id: string): EpochDef {
  const def = EPOCHS.find((e) => e.id === id)
  if (!def) throw new Error(`unknown epoch: ${id}`)
  return def
}

export interface Interpretation {
  epoch: EpochDef
  unixMs: number
  /** True when the resulting date lands in a believable range (1970–2120). */
  plausible: boolean
}

const PLAUSIBLE_MIN = Date.UTC(1975, 0, 1)
const PLAUSIBLE_MAX = Date.UTC(2120, 0, 1)

/** All ways to read a bare number as a timestamp, most plausible first. */
export function interpretNumber(value: string): Interpretation[] {
  const out: Interpretation[] = []
  for (const epoch of EPOCHS) {
    try {
      const unixMs = epoch.toUnixMs(value)
      if (!Number.isFinite(unixMs)) continue
      out.push({ epoch, unixMs, plausible: unixMs >= PLAUSIBLE_MIN && unixMs <= PLAUSIBLE_MAX })
    } catch {
      /* not representable in this epoch */
    }
  }
  // Digit-count prior for the Unix family: 10 digits ≈ seconds, 13 ≈ ms, 16 ≈ µs, 19 ≈ ns.
  const digits = value.trim().replace(/^-/, '').length
  const prior: Record<string, number> = { 10: 0, 13: 1, 16: 2, 19: 3 }
  const preferred = ['unix_s', 'unix_ms', 'unix_us', 'unix_ns'][prior[digits] ?? -1]
  out.sort((a, b) => {
    if (a.plausible !== b.plausible) return a.plausible ? -1 : 1
    if (a.epoch.id === preferred) return -1
    if (b.epoch.id === preferred) return 1
    return 0
  })
  return out
}

/** Parse a date-ish string (ISO 8601, RFC 2822, etc.). Returns Unix ms or null. */
export function parseDateString(text: string): number | null {
  const t = text.trim()
  if (!t) return null
  const ms = Date.parse(t)
  return Number.isNaN(ms) ? null : ms
}

export function isoUtc(ms: number): string {
  return new Date(ms).toISOString().replace('.000Z', 'Z')
}

export function relativeTime(ms: number, now: number): string {
  const diff = ms - now
  const abs = Math.abs(diff)
  const units: [number, string][] = [
    [1000, 'second'],
    [60 * 1000, 'minute'],
    [3600 * 1000, 'hour'],
    [86400 * 1000, 'day'],
    [365.25 * 86400 * 1000, 'year'],
  ]
  if (abs < 1500) return 'now'
  let value = abs
  let unit = 'second'
  for (let i = units.length - 1; i >= 0; i--) {
    if (abs >= units[i][0]) {
      value = abs / units[i][0]
      unit = units[i][1]
      break
    }
  }
  const rounded = value >= 10 ? Math.round(value) : Math.round(value * 10) / 10
  const label = `${rounded} ${unit}${rounded === 1 ? '' : 's'}`
  return diff < 0 ? `${label} ago` : `in ${label}`
}
