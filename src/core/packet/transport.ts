import { ByteReader, hex } from '../bytes'
import { region, type Region } from '../region'
import { inetChecksum, portLabel, pseudoHeader, type Ctx, type LayerFn, type LayerId, type LayerResult } from './net'

/** Pick the application layer by looking at content first, ports second. */
function sniffApp(bytes: Uint8Array, off: number, end: number, srcPort: number, dstPort: number): LayerId {
  if (end - off <= 0) return 'payload'
  const b0 = bytes[off]
  if (end - off >= 5 && b0 >= 20 && b0 <= 23 && bytes[off + 1] === 0x03 && bytes[off + 2] <= 0x04) return 'tls'
  const head = String.fromCharCode(...bytes.subarray(off, Math.min(off + 8, end)))
  if (/^(GET |POST |PUT |DELETE|HEAD |OPTIONS|PATCH |HTTP\/)/.test(head)) return 'http'
  if (srcPort === 53 || dstPort === 53 || srcPort === 5353 || dstPort === 5353) return 'dns'
  if ((srcPort === 123 || dstPort === 123) && end - off >= 48) return 'ntp'
  return 'payload'
}

const TCP_OPTION_NAMES: Record<number, string> = {
  2: 'MSS',
  3: 'Window scale',
  4: 'SACK permitted',
  5: 'SACK',
  8: 'Timestamps',
  34: 'TCP Fast Open',
}

export const tcpLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  const srcPort = r.u16be()
  const dstPort = r.u16be()
  const seq = r.u32be()
  const ack = r.u32be()
  const offByte = r.u8()
  const flagByte = r.u8()
  const dataOffset = (offByte >> 4) * 4
  const window = r.u16be()
  const cksum = r.u16be()
  const urgent = r.u16be()

  const flags: string[] = []
  if (flagByte & 0x02) flags.push('SYN')
  if (flagByte & 0x10) flags.push('ACK')
  if (flagByte & 0x01) flags.push('FIN')
  if (flagByte & 0x04) flags.push('RST')
  if (flagByte & 0x08) flags.push('PSH')
  if (flagByte & 0x20) flags.push('URG')
  if (flagByte & 0x40) flags.push('ECE')
  if (flagByte & 0x80) flags.push('CWR')
  if (offByte & 0x01) flags.push('NS')
  const flagStr = flags.join(', ') || 'none'

  const end = ctx.declaredEnd ?? bytes.length
  const payloadStart = off + dataOffset
  const payloadLen = Math.max(0, end - payloadStart)

  // Checksum: needs the pseudo-header and the complete segment.
  let checksumText = '0x' + hex(cksum, 4)
  let checksumFlag: Region['flag']
  if (ctx.ipPseudo && off + ctx.ipPseudo.length <= bytes.length) {
    const p = ctx.ipPseudo
    const ok = inetChecksum([pseudoHeader(p.src, p.dst, 6, p.length, p.v6), bytes.subarray(off, off + p.length)]) === 0
    checksumText += ok ? ' — valid' : ' — INVALID'
    checksumFlag = ok ? 'ok' : 'bad'
    if (!ok) ctx.warnings.push('TCP checksum is invalid (note: captures of outgoing packets often show bad checksums because of NIC checksum offload)')
  } else {
    checksumText += ' — not verifiable (segment truncated)'
  }

  const children: Region[] = [
    region('Source port', off, 2, { value: portLabel(srcPort) }),
    region('Destination port', off + 2, 2, { value: portLabel(dstPort) }),
    region('Sequence number', off + 4, 4, {
      value: String(seq),
      note: 'Position of this segment\'s first byte in the stream. The initial value is randomized (security), so tools usually display numbers relative to the SYN.',
    }),
    region('Acknowledgment number', off + 8, 4, {
      value: (flagByte & 0x10) ? String(ack) : `${ack} (not meaningful — ACK flag not set)`,
      note: 'The next byte the sender expects to receive — "everything before this arrived".',
    }),
    region('Data offset / flags', off + 12, 2, {
      value: `header ${dataOffset} B, [${flagStr}]`,
      note: 'SYN/ACK/FIN/RST drive the state machine: SYN,SYN+ACK,ACK is the three-way handshake; FIN closes politely; RST slams the door.',
    }),
    region('Window size', off + 14, 2, {
      value: String(window),
      note: 'Flow control: how many more bytes the sender may receive. Scaled by the window-scale option negotiated at SYN time.',
    }),
    region('Checksum', off + 16, 2, { value: checksumText, note: 'Computed over a pseudo-header (src/dst IP + protocol + length) plus the whole segment.', flag: checksumFlag }),
    region('Urgent pointer', off + 18, 2, { value: urgent === 0 ? '0 (unused)' : String(urgent), note: 'Essentially obsolete — telnet-era interrupt mechanism.' }),
  ]

  if (dataOffset > 20) {
    const optChildren: Region[] = []
    const opts: string[] = []
    let p = off + 20
    let guard = 0
    while (p < off + dataOffset && guard++ < 40) {
      const kind = bytes[p]
      if (kind === 0) {
        optChildren.push(region('End of options', p, 1, {}))
        break
      }
      if (kind === 1) {
        optChildren.push(region('NOP (padding)', p, 1, {}))
        p += 1
        continue
      }
      const len = bytes[p + 1] ?? 2
      const name = TCP_OPTION_NAMES[kind] ?? `option ${kind}`
      let value = ''
      if (kind === 2 && len === 4) {
        value = `${(bytes[p + 2] << 8) | bytes[p + 3]} bytes`
        opts.push(`MSS=${value.split(' ')[0]}`)
      } else if (kind === 3 && len === 3) {
        value = `×2^${bytes[p + 2]}`
        opts.push(`WS=${bytes[p + 2]}`)
      } else if (kind === 8 && len === 10) {
        const tsval = new DataView(bytes.buffer, bytes.byteOffset).getUint32(p + 2)
        value = `TSval ${tsval}`
        opts.push('TS')
      } else if (kind === 4) {
        opts.push('SACK-OK')
      }
      optChildren.push(
        region(name, p, Math.max(2, len), {
          value,
          note: kind === 2 ? 'Maximum segment size this host will accept — advertised only in SYN packets.' : kind === 3 ? 'Multiplier for the 16-bit window field, enabling windows beyond 64 KB.' : kind === 8 ? 'Round-trip time measurement + protection against wrapped sequence numbers.' : undefined,
        }),
      )
      p += Math.max(2, len)
    }
    children.push(region('Options', off + 20, dataOffset - 20, { value: opts.join(', '), children: optChildren }))
  }

  ctx.summary.push(`TCP: ${srcPort} → ${dstPort} [${flagStr}] seq=${seq}${flagByte & 0x10 ? ` ack=${ack}` : ''} win=${window} len=${payloadLen}`)

  const next = payloadLen > 0 ? sniffApp(bytes, payloadStart, end, srcPort, dstPort) : undefined
  return {
    region: region('TCP', off, dataOffset, {
      value: `${portLabel(srcPort)} → ${portLabel(dstPort)} [${flagStr}]`,
      note: 'Layer 4. Reliable, ordered byte stream: sequence numbers + acknowledgments + retransmission.',
      children,
    }),
    next: next ? { layer: next, offset: payloadStart } : undefined,
  }
}

export const udpLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  const srcPort = r.u16be()
  const dstPort = r.u16be()
  const length = r.u16be()
  const cksum = r.u16be()
  const end = Math.min(ctx.declaredEnd ?? bytes.length, off + length)

  let checksumText = '0x' + hex(cksum, 4)
  let checksumFlag: Region['flag']
  if (cksum === 0) {
    checksumText += ' — not computed (legal for UDP over IPv4)'
  } else if (ctx.ipPseudo && off + length <= bytes.length) {
    const p = ctx.ipPseudo
    const ok = inetChecksum([pseudoHeader(p.src, p.dst, 17, length, p.v6), bytes.subarray(off, off + length)]) === 0
    checksumText += ok ? ' — valid' : ' — INVALID'
    checksumFlag = ok ? 'ok' : 'bad'
    if (!ok) ctx.warnings.push('UDP checksum is invalid (or the capture shows checksum offload)')
  } else {
    checksumText += ' — not verifiable (datagram truncated)'
  }

  const payloadLen = Math.max(0, end - off - 8)
  ctx.summary.push(`UDP: ${srcPort} → ${dstPort}, ${payloadLen} bytes payload`)

  const next = payloadLen > 0 ? sniffApp(bytes, off + 8, end, srcPort, dstPort) : undefined
  return {
    region: region('UDP', off, 8, {
      value: `${portLabel(srcPort)} → ${portLabel(dstPort)}`,
      note: 'Layer 4. The entire protocol is these 8 bytes: ports, length, checksum. No handshake, no ordering, no retransmission — that is the application\'s problem (or its feature).',
      children: [
        region('Source port', off, 2, { value: portLabel(srcPort) }),
        region('Destination port', off + 2, 2, { value: portLabel(dstPort) }),
        region('Length', off + 4, 2, { value: `${length} B (header + payload)` }),
        region('Checksum', off + 6, 2, { value: checksumText, flag: checksumFlag }),
      ],
    }),
    next: next ? { layer: next, offset: off + 8 } : undefined,
  }
}
