import { humanize } from './format'

/**
 * The one place internal backend tokens become human labels.
 *
 * Every function here is a *mechanical* transformation of a token the backend
 * already emits: a lookup in a table that already existed elsewhere in the
 * product, or `humanize` (snake_case to sentence case). None of them interpret
 * a value. A token that is not in a table is never given a meaning it did not
 * already carry — `unknown` stays "Unknown", `not_configured` stays "Not
 * configured" — because an invented reading of a backend token is a fabricated
 * security claim.
 *
 * Tokens that cannot be humanised at all (engine module paths such as
 * `correlation.ml.controller_bridge`, digests, dataset run ids) are not mapped
 * here on purpose. Those are provenance, and provenance belongs behind a
 * disclosure — see `ProvenanceDetails`.
 */

/**
 * The canonical internal-variable -> human-term map, lifted out of
 * `packet/primitives.tsx` so the Gateway Config grid, the packet assessment
 * explanation and the explainability view can no longer disagree about what
 * `esp.dh_group` is called.
 */
export const CONFIG_TERM_LABELS: Record<string, string> = {
  'ike.version': 'IKE version',
  'ike.encryption': 'IKE encryption',
  'ike.integrity': 'IKE integrity',
  'ike.dh_group': 'IKE DH group',
  'esp.encryption': 'ESP encryption',
  'esp.integrity': 'ESP integrity',
  'esp.dh_group': 'ESP DH group',
  'esp.pfs': 'PFS enabled',
  mode: 'Mode',
  address_family: 'Address family',
  'traffic.profile': 'Traffic profile',
  capture_filter: 'Capture filter',
  security_posture: 'Security posture',
}

/**
 * Standard spellings for the algorithm tokens the control plane offers.
 *
 * The control plane names these the way the protocol documents abbreviate them
 * (`aes128gcm16`, `modp4096`, `sha384`). Mechanical humanisation turns them into
 * "Aes128gcm16" and "Modp4096", which is not a spelling of anything: an analyst
 * reading a security summary should recognise AES-128-GCM and MODP group 4096
 * immediately. These are the canonical algorithm names, so mapping them changes
 * only the rendering — the token the backend sent is unchanged and stays
 * available in provenance.
 */
const CRYPTO_LABELS: Record<string, string> = {
  // Symmetric encryption
  aes128: 'AES-128',
  aes256: 'AES-256',
  aes128gcm16: 'AES-128-GCM',
  aes256gcm16: 'AES-256-GCM',
  aes128cbc: 'AES-128-CBC',
  aes256cbc: 'AES-256-CBC',
  // Integrity
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512',
  // Diffie-Hellman groups
  modp1024: 'MODP-1024',
  modp2048: 'MODP-2048',
  modp3072: 'MODP-3072',
  modp4096: 'MODP-4096',
  // Key exchange
  ecdh: 'ECDH',
  dh14: 'DH-14',
  dh19: 'DH-19',
  dh20: 'DH-20',
}

/**
 * The readable form of an operator-declared profile value: criticality, mission
 * impact, role.
 *
 * The store sends these as slugs (`high`, `operational-communications`). They are
 * operator judgements about an asset, not finding severities, so they are word
 * cased here rather than rendered as bare tokens or given severity casing. The
 * raw value stays available in provenance.
 */
export function declaredValueLabel(value: string | null | undefined): string {
  if (!value) return ''
  return humanize(value)
}

/** Acronyms the backend emits lower-case that must not render as "Mlp"/"Ike". */
const ACRONYMS: Record<string, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  icmp: 'ICMP',
  esp: 'ESP',
  ah: 'AH',
  ike: 'IKE',
  ipsec: 'IPsec',
  ipsec_esp: 'IPsec/ESP',
  dns: 'DNS',
  tcp: 'TCP',
  udp: 'UDP',
  sip: 'SIP',
  rtp: 'RTP',
  voip: 'VoIP',
  dtls: 'DTLS',
  sctp: 'SCTP',
  bgp: 'BGP',
  ml: 'ML',
  ai: 'AI',
  pcap: 'pcap',
  jsonl: 'JSONL',
  xdp: 'XDP',
  sha: 'SHA',
  spi: 'SPI',
}

/**
 * The human term for an internal configuration variable. Unknown variables fall
 * back to mechanical humanisation rather than being dropped, so an unplanned
 * variable still reads as words and its raw key stays available in provenance.
 *
 * The acronym table is consulted before humanising, so a planned `ipv4` reads
 * "IPv4" rather than the title-cased "Ipv4" -- the same token must not read two
 * ways on two screens.
 */
export function configTermLabel(variable: string | null | undefined): string {
  if (!variable) return ''
  const key = variable.toLowerCase()
  return CONFIG_TERM_LABELS[variable] ?? CRYPTO_LABELS[key] ?? ACRONYMS[key] ?? humanize(variable)
}

/**
 * A human label for a hyphen/underscore compound slug (`ml-mismatch` ->
 * `ML mismatch`). Each part goes through the same acronym table as a bare tag,
 * so a compound never mixes a shouted acronym with a title-cased word.
 */
export function compoundLabel(slug: string): string {
  return slug
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => (/^\d+$/.test(part) ? part : (ACRONYMS[part.toLowerCase()] ?? humanize(part))))
    .join(' ')
}

/**
 * A human label for a short protocol/traffic tag (`voip` -> `VoIP`). Shares one
 * acronym table with `acronymLabel`, so the same token never reads two ways on
 * two screens.
 */
export function trafficLabel(tag: string): string {
  return ACRONYMS[tag.toLowerCase()] ?? humanize(tag)
}

/**
 * A human label for any short lowercase token that may be an acronym. Used for
 * enum-ish values such as `evidence_type` (`observation`) and `artifact_type`
 * (`pcap`), which are words already and only need casing, never interpretation.
 */
export function acronymLabel(token: string | null | undefined): string {
  if (!token) return '—'
  return ACRONYMS[token.toLowerCase()] ?? humanize(token)
}

/**
 * A human label for a machine status token (`no_drift` -> `No drift`). Strictly
 * mechanical: the token is restated, never re-graded, so an `indeterminate` or
 * `unknown` status cannot be promoted into a reassuring word.
 */
export function statusLabel(token: string | null | undefined): string {
  if (!token) return '—'
  return humanize(token)
}

/* ------------------------------------------------------------ evidence types */

/**
 * What kind of artifact an evidence reference points at.
 *
 * These are the three `artifact_type` values the backend defines
 * (`correlation/models/evidence.py`), and each entry says what that artifact
 * *is* — the question an analyst answers first. The wording stays inside what
 * the backend already documents about them: `artifact_type` "says what the
 * bytes are", and a capture "proves bytes were observed, never that an
 * interpretation is correct".
 *
 * This is description, not interpretation. It assigns no severity, draws no
 * conclusion about the traffic, and is keyed only by a token the backend sent.
 */
export const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  pcap: 'Packet capture',
  xdp_jsonl: 'Live capture log',
  audit_jsonl: 'Capture audit log',
}

/**
 * One sentence on what each artifact type is for, shown above the reference
 * list so the catalogue is readable without opening anything.
 *
 * Every sentence restates the backend's own documented role for the artifact and
 * stops there. The fallbacks in `evidenceTypeMeaning` are deliberately explicit
 * that nothing is known about an unregistered type rather than producing a
 * plausible-sounding sentence.
 */
export const EVIDENCE_TYPE_MEANINGS: Record<string, string> = {
  pcap:
    'A packet capture file. It proves which bytes crossed the link, but it does not by itself confirm that an interpretation of them is correct.',
  xdp_jsonl:
    'The JSONL capture log the live XDP feed appends to while packets are observed. Each line is one observed packet record, so findings about live traffic are read from this log.',
  audit_jsonl:
    'The JSONL audit log derived from a live capture, recording the observation events behind what was captured.',
}

/**
 * Which feed an artifact arrived from. The backend keeps this deliberately
 * distinct from `artifact_type` ("the two are related, not interchangeable"), and
 * because a feed name is storage/implementation provenance rather than something
 * an analyst reasons about, it is only ever rendered inside a disclosure.
 */
export const EVIDENCE_SOURCE_LABELS: Record<string, string> = {
  training_pcap: 'Training capture feed',
  live_xdp: 'Live XDP feed',
  audit_tap: 'Audit tap feed',
  swanctl: 'swanctl control log',
}

/** A readable name for the kind of evidence, e.g. `xdp_jsonl` -> "Live capture log". */
export function evidenceTypeLabel(type: string | null | undefined): string {
  if (!type) return 'Untyped artifact'
  return EVIDENCE_TYPE_LABELS[type.toLowerCase()] ?? compoundLabel(type)
}

/**
 * What that kind of evidence is, in one sentence. An unregistered type says so
 * plainly instead of borrowing another type's description, because a confident
 * wrong sentence here would misdescribe the basis of a finding.
 */
export function evidenceTypeMeaning(type: string | null | undefined): string {
  if (!type) {
    return 'This reference declares no artifact type, so what the underlying bytes are is not stated.'
  }
  const known = EVIDENCE_TYPE_MEANINGS[type.toLowerCase()]
  if (known) return known
  return `The backend recorded this artifact as "${type}". No description of that kind is registered in the product, so it is shown exactly as it was sent.`
}

/** A readable name for the capture feed. Provenance only — never a primary label. */
export function evidenceSourceLabel(source: string | null | undefined): string {
  if (!source) return '—'
  return EVIDENCE_SOURCE_LABELS[source.toLowerCase()] ?? compoundLabel(source)
}

/**
 * How an assessment refers to itself in prose: its scenario and slot, which is
 * how the experiment names a run. Used wherever an `assessment_id` would
 * otherwise be the only handle an analyst has — filter dropdowns, evidence
 * columns, report rows — with the id itself kept adjacent as provenance.
 *
 * Falls back to the id rather than to a blank, so an assessment whose header
 * carries no scenario still identifies itself.
 */
export function assessmentLabel(assessment: {
  assessment_id?: string | null
  scenario?: string | null
  slot?: string | null
}): string {
  const parts = [
    assessment.scenario ? humanize(assessment.scenario) : null,
    assessment.slot ? compoundLabel(assessment.slot) : null,
  ].filter((part): part is string => Boolean(part))
  return parts.length > 0 ? parts.join(' · ') : (assessment.assessment_id ?? '—')
}