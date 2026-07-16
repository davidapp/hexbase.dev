import { ByteReader, hex } from '../bytes'
import { region, type Region } from '../region'
import { macStr, ipv4Str, type Ctx, type LayerFn, type LayerId, type LayerResult } from './net'

const ETHERTYPES: Record<number, [string, LayerId | null]> = {
  0x0800: ['IPv4', 'ipv4'],
  0x0806: ['ARP', 'arp'],
  0x86dd: ['IPv6', 'ipv6'],
  0x8100: ['802.1Q VLAN', null],
  0x88a8: ['802.1ad QinQ', null],
  0x88cc: ['LLDP', 'payload'],
  0x8863: ['PPPoE Discovery', 'payload'],
  0x8864: ['PPPoE Session', 'payload'],
  0x0842: ['Wake-on-LAN', 'payload'],
}

function macNote(b: Uint8Array, off: number): string | undefined {
  const first = b[off]
  if (first === 0xff && b[off + 1] === 0xff && b[off + 2] === 0xff && b[off + 3] === 0xff && b[off + 4] === 0xff && b[off + 5] === 0xff) {
    return 'ff:ff:ff:ff:ff:ff — broadcast: every host on the LAN segment receives this.'
  }
  const notes: string[] = []
  if (first & 0x01) notes.push('multicast bit set (LSB of first byte)')
  if (first & 0x02) notes.push('locally administered — not a factory-burned address (common for VMs, containers, MAC randomization)')
  if (!(first & 0x02)) notes.push('first 3 bytes are the vendor OUI')
  return notes.join('; ') || undefined
}

export const ethLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  r.skip(12)
  let etherType = r.u16be()
  const children: Region[] = [
    region('Destination MAC', off, 6, { value: macStr(bytes, off), note: macNote(bytes, off) }),
    region('Source MAC', off + 6, 6, { value: macStr(bytes, off + 6), note: macNote(bytes, off + 6) }),
  ]

  // 802.1Q VLAN tag(s)
  let pos = off + 12
  let vlanInfo = ''
  while ((etherType === 0x8100 || etherType === 0x88a8) && r.remaining() >= 4) {
    const tci = r.u16be()
    const vid = tci & 0x0fff
    const pcp = tci >> 13
    children.push(
      region(etherType === 0x8100 ? '802.1Q VLAN tag' : '802.1ad S-tag', pos, 4, {
        value: `VLAN ${vid}, priority ${pcp}`,
        note: 'Inserted between source MAC and EtherType by switches to segment one physical LAN into many virtual ones.',
      }),
    )
    vlanInfo = ` VLAN ${vid}`
    pos += 4
    etherType = r.u16be()
  }

  const [etName, next] = ETHERTYPES[etherType] ?? [
    etherType <= 1500 ? `802.3 length (${etherType})` : `0x${hex(etherType, 4)}`,
    'payload' as LayerId,
  ]
  children.push(
    region('EtherType', pos, 2, {
      value: `0x${hex(etherType, 4)} — ${etName}`,
      note: 'Values ≥ 0x0600 name the payload protocol (Ethernet II). Values ≤ 1500 would instead be an 802.3 length field.',
    }),
  )

  ctx.summary.push(`Ethernet II: ${macStr(bytes, off + 6)} → ${macStr(bytes, off)}${vlanInfo} (${etName})`)

  const headerLen = pos + 2 - off
  return {
    region: region(`Ethernet II${vlanInfo}`, off, headerLen, {
      value: `${etName}`,
      note: 'Layer 2. The 14-byte frame header: who on this LAN segment it is from/to, and what protocol is inside. (The 4-byte FCS trailer is normally stripped before capture.)',
      children,
    }),
    next: next ? { layer: next, offset: off + headerLen } : undefined,
  }
}

const ARP_OPS: Record<number, string> = { 1: 'request', 2: 'reply', 3: 'RARP request', 4: 'RARP reply' }

export const arpLayer: LayerFn = (bytes, off, ctx): LayerResult => {
  const r = new ByteReader(bytes, off)
  const htype = r.u16be()
  const ptype = r.u16be()
  const hlen = r.u8()
  const plen = r.u8()
  const oper = r.u16be()
  const sha = off + 8
  const spa = sha + hlen
  const tha = spa + plen
  const tpa = tha + hlen
  const opName = ARP_OPS[oper] ?? String(oper)

  const senderIp = plen === 4 ? ipv4Str(bytes, spa) : '?'
  const targetIp = plen === 4 ? ipv4Str(bytes, tpa) : '?'
  const senderMac = hlen === 6 ? macStr(bytes, sha) : '?'

  if (oper === 1) ctx.summary.push(`ARP: who has ${targetIp}? Tell ${senderIp}`)
  else if (oper === 2) ctx.summary.push(`ARP: ${senderIp} is at ${senderMac}`)
  else ctx.summary.push(`ARP ${opName}`)

  return {
    region: region(`ARP ${opName}`, off, 8 + 2 * (hlen + plen), {
      value: oper === 1 ? `who has ${targetIp}?` : oper === 2 ? `${senderIp} is at ${senderMac}` : '',
      note: 'Address Resolution Protocol — maps an IPv4 address to a MAC address on the local segment. No authentication, which is why ARP spoofing works.',
      children: [
        region('Hardware type', off, 2, { value: htype === 1 ? '1 — Ethernet' : String(htype) }),
        region('Protocol type', off + 2, 2, { value: ptype === 0x0800 ? '0x0800 — IPv4' : `0x${hex(ptype, 4)}` }),
        region('Address lengths', off + 4, 2, { value: `MAC ${hlen} B, IP ${plen} B` }),
        region('Operation', off + 6, 2, { value: `${oper} — ${opName}` }),
        region('Sender MAC', sha, hlen, { value: senderMac }),
        region('Sender IP', spa, plen, { value: senderIp }),
        region('Target MAC', tha, hlen, { value: hlen === 6 ? macStr(bytes, tha) : '?', note: oper === 1 ? 'All zeroes in a request — that is the unknown being asked for.' : undefined }),
        region('Target IP', tpa, plen, { value: targetIp }),
      ],
    }),
  }
}
