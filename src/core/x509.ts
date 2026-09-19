import {
  content,
  decodeBitString,
  decodeBoolean,
  decodeInteger,
  decodeOid,
  decodeString,
  decodeTime,
  parseDer,
  tagName,
  toRegionTree,
  type Asn1Node,
} from './asn1'
import { bytesToHex } from './bytes'
import { region, type ParseResult, type Region } from './region'

/**
 * X.509 certificate semantics on top of the DER parser: RDNs, validity,
 * key type and size, and the extensions people actually look up.
 */

export const OID_NAMES: Record<string, string> = {
  // RDN attribute types
  '2.5.4.3': 'CN (common name)',
  '2.5.4.4': 'surname',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C (country)',
  '2.5.4.7': 'L (locality)',
  '2.5.4.8': 'ST (state/province)',
  '2.5.4.9': 'street',
  '2.5.4.10': 'O (organization)',
  '2.5.4.11': 'OU (organizational unit)',
  '2.5.4.15': 'businessCategory',
  '2.5.4.17': 'postalCode',
  '2.5.4.42': 'givenName',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC (domain component)',
  '0.9.2342.19200300.100.1.1': 'UID',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionCountry (EV)',
  // signature / key algorithms
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
  // named curves
  '1.2.840.10045.3.1.7': 'P-256 (secp256r1)',
  '1.3.132.0.34': 'P-384 (secp384r1)',
  '1.3.132.0.35': 'P-521 (secp521r1)',
  '1.3.132.0.10': 'secp256k1',
  // extensions
  '2.5.29.14': 'subjectKeyIdentifier',
  '2.5.29.15': 'keyUsage',
  '2.5.29.17': 'subjectAltName',
  '2.5.29.18': 'issuerAltName',
  '2.5.29.19': 'basicConstraints',
  '2.5.29.31': 'cRLDistributionPoints',
  '2.5.29.32': 'certificatePolicies',
  '2.5.29.35': 'authorityKeyIdentifier',
  '2.5.29.37': 'extKeyUsage',
  '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess',
  '1.3.6.1.4.1.11129.2.4.2': 'SCT list (Certificate Transparency)',
  '1.3.6.1.4.1.11129.2.4.3': 'CT poison (precertificate)',
  // EKU purposes
  '1.3.6.1.5.5.7.3.1': 'serverAuth',
  '1.3.6.1.5.5.7.3.2': 'clientAuth',
  '1.3.6.1.5.5.7.3.3': 'codeSigning',
  '1.3.6.1.5.5.7.3.4': 'emailProtection',
  '1.3.6.1.5.5.7.3.8': 'timeStamping',
  '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
  // AIA access methods
  '1.3.6.1.5.5.7.48.1': 'OCSP',
  '1.3.6.1.5.5.7.48.2': 'caIssuers',
  // policy
  '2.23.140.1.2.1': 'CA/B domain-validated (DV)',
  '2.23.140.1.2.2': 'CA/B organization-validated (OV)',
  '2.23.140.1.1': 'CA/B extended-validation (EV)',
}

export function oidLabel(oid: string): string | null {
  return OID_NAMES[oid] ?? null
}

const KEY_USAGE_BITS = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
]

export interface CertFacts {
  subject: string
  issuer: string
  serialHex: string
  notBefore: Date | null
  notAfter: Date | null
  sigAlg: string
  keyAlg: string
  keyDetail: string
  sans: string[]
  isCA: boolean | null
  keyUsage: string[]
  extKeyUsage: string[]
  selfSigned: boolean
  version: number
  /** subjectKeyIdentifier / authorityKeyIdentifier key ids (colon hex), for chain linking. */
  ski: string | null
  aki: string | null
}

export interface CertParse {
  result: ParseResult
  facts: CertFacts
  der: Uint8Array
}

function base64ToDer(base64: string): Uint8Array {
  const cleaned = base64.replace(/[\s\r\n]/g, '')
  if (!/^[A-Za-z0-9+/=_-]+$/.test(cleaned) || cleaned.length < 16) {
    throw new Error('not a certificate: expected PEM armor (-----BEGIN CERTIFICATE-----), base64, or DER bytes')
  }
  const std = cleaned.replaceAll('-', '+').replaceAll('_', '/')
  let bin: string
  try {
    bin = atob(std)
  } catch {
    throw new Error('the base64 payload is malformed')
  }
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g

function rejectPrivateKey(label: string): void {
  if (!/CERTIFICATE/.test(label)) {
    throw new Error(`this is a "${label}" PEM block — paste a CERTIFICATE block (private keys don't belong in browser tools)`)
  }
}

/**
 * Every certificate in the input, in order: all CERTIFICATE PEM blocks of a
 * text (a fullchain.pem yields several), or a single DER / bare-base64 blob.
 * Throws on private-key blocks so nobody learns that habit here.
 */
export function splitPem(input: Uint8Array | string): Uint8Array[] {
  if (typeof input !== 'string') {
    if (input.length > 0 && input[0] === 0x30) return [input] // raw DER: SEQUENCE
    input = new TextDecoder().decode(input)
  }
  const text = input.trim()
  const blocks = [...text.matchAll(PEM_BLOCK)]
  if (blocks.length === 0) return [base64ToDer(text)]
  for (const b of blocks) rejectPrivateKey(b[1])
  return blocks.map((b) => base64ToDer(b[2]))
}

/** Accepts PEM armor, bare base64, or raw DER bytes; returns the (first) certificate's DER. */
export function toDer(input: Uint8Array | string): Uint8Array {
  return splitPem(input)[0]
}

function rdnToString(bytes: Uint8Array, name: Asn1Node): string {
  // Name ::= SEQUENCE OF SET OF AttributeTypeAndValue
  const parts: string[] = []
  for (const set of name.children ?? []) {
    for (const atv of set.children ?? []) {
      const [typeNode, valueNode] = atv.children ?? []
      if (!typeNode || !valueNode) continue
      const oid = decodeOid(bytes, typeNode)
      const label = OID_NAMES[oid]?.match(/^([A-Z]{1,2})\s/)?.[1] ?? OID_NAMES[oid]?.split(' ')[0] ?? oid
      parts.push(`${label}=${decodeString(bytes, valueNode)}`)
    }
  }
  return parts.join(', ') || '(empty)'
}

function generalNames(bytes: Uint8Array, node: Asn1Node): string[] {
  const out: string[] = []
  for (const gn of node.children ?? []) {
    if (gn.tagClass !== 2) continue
    if (gn.tag === 2) out.push(`DNS:${decodeString(bytes, gn)}`)
    else if (gn.tag === 1) out.push(`email:${decodeString(bytes, gn)}`)
    else if (gn.tag === 6) out.push(`URI:${decodeString(bytes, gn)}`)
    else if (gn.tag === 7) {
      const ip = content(bytes, gn)
      out.push(`IP:${ip.length === 4 ? [...ip].join('.') : bytesToHex(ip, ':')}`)
    } else out.push(`${tagName(gn)} (${gn.length} bytes)`)
  }
  return out
}

/** Parse one DER certificate into a byte-level tree + extracted facts. */
export function parseCertificate(der: Uint8Array): CertParse {
  const warnings: string[] = []
  let roots: Asn1Node[]
  try {
    roots = parseDer(der)
  } catch (e) {
    throw new Error(`DER parse failed: ${e instanceof Error ? e.message : String(e)}`)
  }
  const cert = roots[0]
  if (!cert || cert.tagClass !== 0 || cert.tag !== 16 || !cert.children || cert.children.length < 3) {
    throw new Error('not a certificate: expected SEQUENCE { tbsCertificate, signatureAlgorithm, signature }')
  }
  if (roots.length > 1) warnings.push(`${roots.length - 1} extra top-level element(s) after the certificate were ignored`)
  const [tbs, sigAlgNode, sigValNode] = cert.children
  if (!tbs.children?.length) throw new Error('tbsCertificate is empty')

  const facts: CertFacts = {
    subject: '(missing)',
    issuer: '(missing)',
    serialHex: '',
    notBefore: null,
    notAfter: null,
    sigAlg: '(missing)',
    keyAlg: '(missing)',
    keyDetail: '',
    sans: [],
    isCA: null,
    keyUsage: [],
    extKeyUsage: [],
    selfSigned: false,
    version: 1,
    ski: null,
    aki: null,
  }

  // tbsCertificate fields in order, version tag optional
  const fields = [...tbs.children]
  let fi = 0
  const tbsRegions: Region[] = []

  if (fields[fi]?.tagClass === 2 && fields[fi].tag === 0) {
    const versionNode = fields[fi].children?.[0]
    if (versionNode) facts.version = Number(decodeInteger(der, versionNode).value) + 1
    tbsRegions.push(
      region('Version', fields[fi].offset, fields[fi].headerLen + fields[fi].length, {
        value: `v${facts.version}`,
        note: 'INTEGER wrapped in context tag [0]. v3 (value 2) is what enables extensions — v1 certs predate SANs.',
      }),
    )
    fi++
  }

  const serial = fields[fi]
  if (serial?.tag === 2) {
    const { hex: serialHex } = decodeInteger(der, serial)
    facts.serialHex = serialHex
    tbsRegions.push(
      region('Serial number', serial.offset, serial.headerLen + serial.length, {
        value: serialHex.length > 40 ? serialHex.slice(0, 40) + '…' : serialHex,
        note: 'Unique per issuing CA. CAs are required to include ≥64 bits of CSPRNG output since 2016 (hence the long values).',
      }),
    )
    fi++
  }

  const tbsSigAlg = fields[fi]
  if (tbsSigAlg) {
    fi++
  }

  const issuer = fields[fi]
  if (issuer) {
    facts.issuer = rdnToString(der, issuer)
    tbsRegions.push(
      region('Issuer', issuer.offset, issuer.headerLen + issuer.length, {
        value: facts.issuer,
        note: 'Who signed this certificate: a SEQUENCE of relative distinguished names, matched byte-for-byte during chain building.',
      }),
    )
    fi++
  }

  const validity = fields[fi]
  if (validity?.children?.length === 2) {
    facts.notBefore = decodeTime(der, validity.children[0])
    facts.notAfter = decodeTime(der, validity.children[1])
    tbsRegions.push(
      region('Validity', validity.offset, validity.headerLen + validity.length, {
        value: `${facts.notBefore?.toISOString().slice(0, 10) ?? '?'} → ${facts.notAfter?.toISOString().slice(0, 10) ?? '?'}`,
        note: 'UTCTime through 2049, GeneralizedTime after — a Y2K scar written into RFC 5280. Public TLS certs are capped at 398 days.',
        children: [
          region('Not before', validity.children[0].offset, validity.children[0].headerLen + validity.children[0].length, {
            value: facts.notBefore?.toISOString() ?? '(unparsed)',
          }),
          region('Not after', validity.children[1].offset, validity.children[1].headerLen + validity.children[1].length, {
            value: facts.notAfter?.toISOString() ?? '(unparsed)',
          }),
        ],
      }),
    )
    fi++
  }

  const subject = fields[fi]
  if (subject) {
    facts.subject = rdnToString(der, subject)
    tbsRegions.push(
      region('Subject', subject.offset, subject.headerLen + subject.length, {
        value: facts.subject,
        note: 'Who the certificate is about. For public TLS the CN is decorative — browsers only trust the subjectAltName list.',
      }),
    )
    fi++
  }

  const spki = fields[fi]
  if (spki?.children?.length === 2) {
    const [alg, keyBits] = spki.children
    const algOid = alg.children?.[0] ? decodeOid(der, alg.children[0]) : '?'
    facts.keyAlg = OID_NAMES[algOid] ?? algOid
    let keyNote = 'AlgorithmIdentifier + the public key packed in a BIT STRING.'
    if (algOid === '1.2.840.113549.1.1.1') {
      // RSA: bit string wraps SEQUENCE { modulus, publicExponent }
      try {
        const { bits } = decodeBitString(der, keyBits)
        const rsa = parseDer(bits)[0]
        const modulus = rsa.children?.[0]
        const exponent = rsa.children?.[1]
        if (modulus && exponent) {
          const modContent = content(bits, modulus)
          const modBits = (modContent.length - (modContent[0] === 0 ? 1 : 0)) * 8
          facts.keyDetail = `RSA-${modBits}, e=${decodeInteger(bits, exponent).value}`
          keyNote = `RSA modulus of ${modBits} bits. The leading 0x00 in the INTEGER just keeps it positive — DER integers are signed.`
        }
      } catch {
        warnings.push('could not parse the RSA key inside the BIT STRING')
      }
    } else if (algOid === '1.2.840.10045.2.1') {
      const curveOid = alg.children?.[1] ? decodeOid(der, alg.children[1]) : '?'
      facts.keyDetail = `ECDSA on ${OID_NAMES[curveOid] ?? curveOid}`
      keyNote = 'Elliptic-curve key: the curve is named in the algorithm parameters, the BIT STRING holds the uncompressed point.'
    } else if (algOid === '1.3.101.112' || algOid === '1.3.101.113') {
      facts.keyDetail = facts.keyAlg
    }
    tbsRegions.push(
      region('Subject public key info', spki.offset, spki.headerLen + spki.length, {
        value: facts.keyDetail || facts.keyAlg,
        note: keyNote,
      }),
    )
    fi++
  }

  // remaining: optional [1]/[2] unique IDs, then [3] extensions
  for (; fi < fields.length; fi++) {
    const f = fields[fi]
    if (f.tagClass === 2 && f.tag === 3) {
      const extSeq = f.children?.[0]
      const extRegions: Region[] = []
      for (const ext of extSeq?.children ?? []) {
        const kids = ext.children ?? []
        const oid = kids[0] ? decodeOid(der, kids[0]) : '?'
        const name = OID_NAMES[oid] ?? oid
        const critical = kids[1]?.tag === 1 ? decodeBoolean(der, kids[1]) : false
        const valueNode = kids[kids.length - 1]
        let value = ''
        let note = critical ? 'critical — a validator that does not understand this extension MUST reject the certificate' : ''
        try {
          const inner = valueNode?.tag === 4 ? parseDer(content(der, valueNode))[0] : undefined
          if (oid === '2.5.29.17' && inner) {
            facts.sans = generalNames(content(der, valueNode), inner)
            value = facts.sans.slice(0, 8).join(', ') + (facts.sans.length > 8 ? ` … (${facts.sans.length} total)` : '')
            note = 'The names browsers actually check. DNS entries may use one leftmost wildcard (*.example.com).'
          } else if (oid === '2.5.29.19') {
            const ca = inner?.children?.[0]?.tag === 1 ? decodeBoolean(content(der, valueNode), inner.children[0]) : false
            facts.isCA = ca
            const pathLen = inner?.children?.find((c) => c.tag === 2)
            value = ca ? `CA:TRUE${pathLen ? `, pathlen:${decodeInteger(content(der, valueNode), pathLen).value}` : ''}` : 'CA:FALSE'
            note = 'Whether this certificate may sign other certificates. Leaf certs say CA:FALSE.'
          } else if (oid === '2.5.29.15' && inner) {
            const { unused, bits } = decodeBitString(content(der, valueNode), inner)
            const names: string[] = []
            for (let bit = 0; bit < bits.length * 8 - unused && bit < KEY_USAGE_BITS.length; bit++) {
              if (bits[bit >> 3] & (0x80 >> (bit & 7))) names.push(KEY_USAGE_BITS[bit])
            }
            facts.keyUsage = names
            value = names.join(', ') || '(none)'
          } else if (oid === '2.5.29.37' && inner) {
            const src = content(der, valueNode)
            facts.extKeyUsage = (inner.children ?? []).map((c) => {
              const o = decodeOid(src, c)
              return OID_NAMES[o] ?? o
            })
            value = facts.extKeyUsage.join(', ')
          } else if (oid === '2.5.29.14' && valueNode) {
            const inner2 = parseDer(content(der, valueNode))[0]
            value = bytesToHex(content(content(der, valueNode), inner2), ':')
            facts.ski = value
            note = 'Hash of this certificate’s own key; children reference it via authorityKeyIdentifier to link the chain.'
          } else if (oid === '2.5.29.35' && inner && valueNode) {
            // AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier, [1] issuer, [2] serial }
            const src = content(der, valueNode)
            const kid = inner.children?.find((c) => c.tagClass === 2 && c.tag === 0)
            if (kid) {
              facts.aki = bytesToHex(content(src, kid), ':')
              value = `keyid:${facts.aki}`
            }
            note = 'Which key signed this certificate — it should equal the issuer’s subjectKeyIdentifier; that equality is how chains are linked.'
          } else if (oid === '1.3.6.1.4.1.11129.2.4.2') {
            value = `${valueNode?.length ?? 0} bytes of signed certificate timestamps`
            note = 'Proof the cert was logged in public Certificate Transparency logs — required by Chrome and Safari.'
          } else if (valueNode) {
            value = `${valueNode.length} bytes`
          }
        } catch {
          warnings.push(`extension ${name}: could not parse its inner structure`)
          value = value || `${valueNode?.length ?? 0} bytes (unparsed)`
        }
        extRegions.push(
          region(name, ext.offset, ext.headerLen + ext.length, {
            value: critical ? `${value}  ⚠ critical` : value,
            note: note || `OID ${oid}. Extension bodies are DER nested inside an OCTET STRING — matryoshka encoding.`,
          }),
        )
      }
      tbsRegions.push(
        region('Extensions', f.offset, f.headerLen + f.length, {
          value: `${extRegions.length} extension${extRegions.length === 1 ? '' : 's'}`,
          note: 'The v3 extension list — where SANs, key usage and the CA bit actually live.',
          children: extRegions,
        }),
      )
    }
  }

  const sigOid = sigAlgNode.children?.[0] ? decodeOid(der, sigAlgNode.children[0]) : '?'
  facts.sigAlg = OID_NAMES[sigOid] ?? sigOid
  facts.selfSigned = facts.subject === facts.issuer

  const regions: Region[] = [
    region('Certificate', cert.offset, cert.headerLen + cert.length, {
      value: `${der.length} bytes DER`,
      note: 'SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } — the outer envelope of every X.509 cert.',
      children: [
        region('tbsCertificate', tbs.offset, tbs.headerLen + tbs.length, {
          value: 'the signed part',
          note: '"To be signed" — every byte here is covered by the signature below. Change one and the signature breaks.',
          children: tbsRegions,
        }),
        region('Signature algorithm', sigAlgNode.offset, sigAlgNode.headerLen + sigAlgNode.length, {
          value: facts.sigAlg,
          note: 'Must match the algorithm inside tbsCertificate — a mismatch is an attack signal (alg-substitution).',
        }),
        region('Signature value', sigValNode.offset, sigValNode.headerLen + sigValNode.length, {
          value: `${sigValNode.length - 1} bytes`,
          note: "The issuer's signature over tbsCertificate, as a BIT STRING. Verify it with the issuer's public key, not this cert's.",
        }),
      ],
    }),
  ]

  const validityStr = describeValidity(facts)
  const summary = [
    `subject: ${facts.subject}`,
    `issuer: ${facts.issuer}${facts.selfSigned ? ' (self-signed)' : ''}`,
    validityStr,
    `key: ${facts.keyDetail || facts.keyAlg} · signature: ${facts.sigAlg}`,
  ]
  if (facts.sans.length) summary.push(`SANs: ${facts.sans.slice(0, 6).join(', ')}${facts.sans.length > 6 ? ` … (${facts.sans.length})` : ''}`)

  return {
    result: { format: `X.509 certificate (v${facts.version})`, summary, regions, warnings },
    facts,
    der,
  }
}

export function describeValidity(facts: CertFacts, now = new Date()): string {
  if (!facts.notBefore || !facts.notAfter) return 'validity: (unparsed)'
  const from = facts.notBefore.toISOString().slice(0, 10)
  const to = facts.notAfter.toISOString().slice(0, 10)
  if (now < facts.notBefore) return `validity: ${from} → ${to} — NOT YET VALID`
  if (now > facts.notAfter) {
    const days = Math.floor((now.getTime() - facts.notAfter.getTime()) / 86400000)
    return `validity: ${from} → ${to} — EXPIRED ${days} day${days === 1 ? '' : 's'} ago`
  }
  const days = Math.floor((facts.notAfter.getTime() - now.getTime()) / 86400000)
  return `validity: ${from} → ${to} — valid, ${days} day${days === 1 ? '' : 's'} remaining`
}

export interface ChainLink {
  index: number
  role: 'leaf' | 'intermediate' | 'root'
  /** Index of the certificate in this list whose subject matches this one's issuer, if present. */
  issuedBy: number | null
  /** Whether AKI/SKI key identifiers confirm the link (null when either side lacks the extension). */
  keyIdMatch: boolean | null
  notes: string[]
}

/**
 * How the certificates of a pasted chain relate: who issued whom, by name
 * (issuer = subject) and by key identifier (AKI = SKI). This is linkage, not
 * signature verification — it tells you the chain is assembled correctly.
 */
export function describeChain(certs: CertParse[]): ChainLink[] {
  return certs.map((c, i) => {
    const f = c.facts
    const notes: string[] = []
    const issuerIdx = certs.findIndex((o, j) => j !== i && o.facts.subject === f.issuer)
    const issuedBy = f.selfSigned ? i : issuerIdx >= 0 ? issuerIdx : null
    const isIssuerOfSomeone = certs.some((o, j) => j !== i && o.facts.issuer === f.subject && !o.facts.selfSigned)
    const role: ChainLink['role'] = f.selfSigned ? 'root' : isIssuerOfSomeone ? 'intermediate' : 'leaf'
    let keyIdMatch: boolean | null = null
    if (f.selfSigned) {
      notes.push('self-signed: issuer and subject are the same name')
      if (f.aki && f.ski) keyIdMatch = f.aki === f.ski
    } else if (issuedBy !== null) {
      const issuer = certs[issuedBy].facts
      notes.push(`issuer matches subject of #${issuedBy + 1}`)
      if (f.aki && issuer.ski) {
        keyIdMatch = f.aki === issuer.ski
        notes.push(keyIdMatch ? `authorityKeyIdentifier matches #${issuedBy + 1}’s subjectKeyIdentifier` : `authorityKeyIdentifier does NOT match #${issuedBy + 1}’s subjectKeyIdentifier — wrong intermediate?`)
      }
    } else {
      notes.push(role === 'leaf' && certs.length > 1 ? 'issuer not found in this chain' : 'issuer not in this chain — the root usually lives in the client’s trust store, not in the served chain')
    }
    return { index: i, role, issuedBy, keyIdMatch, notes }
  })
}

/** Generic view for non-certificate DER: still show the full ASN.1 tree. */
export function parseAnyDer(der: Uint8Array): ParseResult {
  const nodes = parseDer(der)
  return {
    format: 'DER-encoded ASN.1',
    summary: [`${nodes.length} top-level element${nodes.length === 1 ? '' : 's'}, ${der.length} bytes`],
    regions: toRegionTree(der, nodes, oidLabel),
    warnings: ['not recognized as a certificate — showing the raw ASN.1 structure'],
  }
}
