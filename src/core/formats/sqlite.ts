import { ByteReader, formatSize } from '../bytes'
import { region, type ParseResult, type Region } from '../region'
import { startsWith, sigOf, type FormatDef } from './def'

const ENCODINGS: Record<number, string> = { 1: 'UTF-8', 2: 'UTF-16le', 3: 'UTF-16be' }

export const sqlite: FormatDef = {
  id: 'sqlite',
  name: 'SQLite database',
  detect: (b) => startsWith(b, sigOf('SQLite format 3\0')),
  parse(bytes): ParseResult {
    const regions: Region[] = []
    const warnings: string[] = []
    const summary: string[] = []
    try {
      const r = new ByteReader(bytes, 16)
      const pageSizeRaw = r.u16be()
      const pageSize = pageSizeRaw === 1 ? 65536 : pageSizeRaw
      const writeVer = r.u8()
      const readVer = r.u8()
      const reserved = r.u8()
      r.skip(3) // payload fractions (always 64/32/32)
      const changeCounter = r.u32be()
      const pageCount = r.u32be()
      const freelistFirst = r.u32be()
      const freelistCount = r.u32be()
      const schemaCookie = r.u32be()
      const schemaFormat = r.u32be()
      r.u32be() // default cache size
      r.u32be() // largest root btree page
      const encoding = r.u32be()
      const userVersion = r.u32be()
      const incVacuum = r.u32be()
      const appId = r.u32be()
      r.seek(96)
      const versionNumber = r.u32be()
      const verStr = `${Math.floor(versionNumber / 1000000)}.${Math.floor((versionNumber % 1000000) / 1000)}.${versionNumber % 1000}`

      regions.push(
        region('Database header', 0, 100, {
          value: `page ${pageSize} B × ${pageCount}`,
          note: 'Every SQLite file starts with this fixed 100-byte header. The rest of the file is an array of equal-sized pages holding B-trees.',
          children: [
            region('Magic', 0, 16, { value: '"SQLite format 3\\0"', flag: 'ok' }),
            region('Page size', 16, 2, { value: `${pageSize} B`, note: 'Power of two, 512–65536. The value 1 means 65536.' }),
            region('Write/read version', 18, 2, {
              value: `${writeVer}/${readVer} — ${writeVer === 2 ? 'WAL mode' : 'rollback journal'}`,
              note: '2 = write-ahead logging (a -wal companion file may exist); 1 = classic rollback journal.',
            }),
            region('Reserved per page', 20, 1, { value: String(reserved), note: 'Bytes reserved at the end of each page — used by encryption extensions.' }),
            region('Payload fractions', 21, 3, { value: '64/32/32', note: 'Always these values; kept for historical compatibility.' }),
            region('Change counter', 24, 4, { value: String(changeCounter), note: 'Bumped on every transaction — how other processes notice the file changed.' }),
            region('Page count', 28, 4, { value: `${pageCount} pages = ${formatSize(pageCount * pageSize)}` }),
            region('Freelist', 32, 8, { value: `${freelistCount} free pages${freelistFirst ? ` (first trunk: page ${freelistFirst})` : ''}`, note: 'Deleted data leaves free pages behind — VACUUM reclaims them. Free pages can still contain old data!' }),
            region('Schema cookie', 40, 4, { value: String(schemaCookie), note: 'Bumped whenever the schema changes; prepared statements check it.' }),
            region('Schema format', 44, 4, { value: String(schemaFormat) }),
            region('Text encoding', 56, 4, { value: `${encoding} — ${ENCODINGS[encoding] ?? 'invalid'}` }),
            region('User version', 60, 4, { value: String(userVersion), note: 'Free for the application (PRAGMA user_version) — apps use it for migrations.' }),
            region('Incremental vacuum', 64, 4, { value: incVacuum ? 'enabled' : '0 — disabled' }),
            region('Application ID', 68, 4, { value: appId === 0 ? '0 — plain SQLite' : '0x' + appId.toString(16).toUpperCase(), note: 'PRAGMA application_id — lets file(1) identify app-specific formats.' }),
            region('SQLite version', 96, 4, { value: verStr, note: 'Version of the library that last wrote the file.' }),
          ],
        }),
      )

      if (bytes.length > 100) {
        regions.push(
          region('Page 1 (sqlite_schema root)', 100, Math.min(pageSize, bytes.length) - 100, {
            note: 'Page 1 holds the root of the sqlite_schema table — the CREATE statements for every table and index. Page 1 is 100 bytes short because the header lives inside it.',
          }),
        )
        if (bytes.length > pageSize) {
          regions.push(region('Pages 2…N (B-trees)', pageSize, bytes.length - pageSize, { value: `${Math.max(0, pageCount - 1)} more pages`, note: 'Table B-trees keyed by rowid, index B-trees keyed by column values, overflow and freelist pages.' }))
        }
      }

      summary.push(`SQLite ${verStr}, ${pageCount} × ${formatSize(pageSize)} pages (${formatSize(pageCount * pageSize)})`)
      summary.push(`${ENCODINGS[encoding] ?? '?'} text, ${writeVer === 2 ? 'WAL journal' : 'rollback journal'}${freelistCount ? `, ${freelistCount} free pages` : ''}`)
      if (bytes.length !== pageCount * pageSize && pageCount > 0) {
        warnings.push(`file is ${formatSize(bytes.length)} but header says ${formatSize(pageCount * pageSize)} — truncated copy or header out of date`)
      }
    } catch (e) {
      warnings.push(`file truncated: ${e instanceof Error ? e.message : String(e)}`)
    }
    return { format: 'SQLite database', summary, regions, warnings }
  },
}
