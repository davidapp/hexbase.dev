/** A labelled span of bytes produced by a parser; nesting describes structure. */
export interface Region {
  name: string
  offset: number
  length: number
  /** Decoded value, shown next to the name. Keep it short. */
  value?: string
  /** Plain-English explanation of what this field means (educational). */
  note?: string
  /** Validation state, e.g. a CRC that checked out or a bad checksum. */
  flag?: 'ok' | 'warn' | 'bad'
  children?: Region[]
}

export interface ParseResult {
  /** Human-readable format name, e.g. "PNG image". */
  format: string
  /** Key facts about the file/packet, one per line. */
  summary: string[]
  regions: Region[]
  warnings: string[]
}

export function region(name: string, offset: number, length: number, extra: Partial<Region> = {}): Region {
  return { name, offset, length, ...extra }
}
