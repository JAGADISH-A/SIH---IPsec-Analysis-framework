import { Fingerprint, KeyRound, Lock } from 'lucide-react'
import { Section, SectionHeading } from './Section.tsx'

const PROTOCOLS = [
  {
    icon: KeyRound,
    abbr: 'IKEv2',
    title: 'Key exchange & negotiation',
    body: 'Authenticated establishment of Security Associations. Sentinel decodes the initiator and responder SPIs, the exchange type, the message id, every proposed transform, the PRF, the DH group and the PFS flag.',
    rfc: 'RFC 7296',
    fields: ['Initiator SPI', 'Responder SPI', 'Exchange Type', 'Message ID', 'Encryption', 'Integrity', 'DH Group'],
  },
  {
    icon: Lock,
    abbr: 'ESP',
    title: 'Confidentiality & integrity',
    body: 'Encrypts and authenticates the payload of every tunneled datagram. Each ESP header is decoded to its SPI, sequence number, payload length, next header, algorithms and, where applicable, the inner flow being protected.',
    rfc: 'RFC 4303',
    fields: ['SPI', 'Sequence Number', 'Payload Length', 'Encryption Algorithm', 'Integrity Algorithm', 'Tunnel Mode'],
  },
  {
    icon: Fingerprint,
    abbr: 'AH',
    title: 'Authentication only',
    body: 'Signs packets for integrity and origin authenticity without encrypting them, for traffic where confidentiality is not required. The authentication data length is visible on the wire, which the rules treat as an exposure.',
    rfc: 'RFC 4302',
    fields: ['SPI', 'Sequence Number', 'Authentication Data', 'Next Header'],
  },
]

/** IPsec protocol section — presented as a reference table, like documentation. */
export function Protocols() {
  return (
    <Section>
      <div className="py-14 lg:py-16">
        <SectionHeading
          index="04"
          eyebrow="Protocol coverage"
          title="The IPsec stack, decoded"
          subtitle="Three protocols Sentinel speaks fluently — from negotiation to wire format, with the field names an analyst already expects to see."
        />

        <div className="mt-10 grid gap-px overflow-hidden rounded-md border border-edge bg-edge lg:grid-cols-3">
          {PROTOCOLS.map(({ icon: Icon, abbr, title, body, rfc, fields }) => (
            <article key={abbr} className="flex flex-col bg-night-950 p-5">
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2.5">
                  <span className="flex size-9 items-center justify-center rounded border border-edge bg-night-900 text-accent-300">
                    <Icon className="size-4" aria-hidden />
                  </span>
                  <span className="mono-tab text-[16px] font-bold text-mist">{abbr}</span>
                </span>
                <span className="mono-tab rounded border border-edge px-1.5 py-0.5 text-[10px] text-mist-faint">
                  {rfc}
                </span>
              </div>

              <h3 className="mt-3 text-[13.5px] font-semibold text-accent-400">{title}</h3>
              <p className="mt-1.5 flex-1 text-[12.5px] leading-relaxed text-mist-dim">{body}</p>

              <div className="mt-4 border-t border-edge pt-3">
                <div className="label">Decoded fields</div>
                <ul className="mt-1.5 flex flex-wrap gap-1">
                  {fields.map((field) => (
                    <li key={field} className="chip mono-tab">
                      {field}
                    </li>
                  ))}
                </ul>
              </div>
            </article>
          ))}
        </div>
      </div>
    </Section>
  )
}
