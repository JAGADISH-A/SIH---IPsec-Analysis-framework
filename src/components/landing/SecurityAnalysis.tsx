import { Activity, Gauge, KeyRound, Radar, Route } from 'lucide-react'
import { riskStyle } from '../analyzer/workspaceTheme.ts'
import { Section, SectionHeading } from './Section.tsx'
import type { RiskLevel } from '../../types/security'

const LENSES = [
  {
    icon: KeyRound,
    title: 'Cryptographic configuration',
    body: 'Cipher suites, integrity algorithms, PRF and HMAC choices, key lengths and DH groups, checked against RFC 8247 and RFC 8221 guidance.',
    example: { severity: 'high' as RiskLevel, text: 'IKE_SA_INIT proposing ENCR_DES / PRF_HMAC_MD5 with MODP group 1' },
  },
  {
    icon: Radar,
    title: 'Protocol anomalies',
    body: 'Out-of-order handshakes, unexpected exchange types, malformed notification payloads and replayed sequence numbers.',
    example: { severity: 'medium' as RiskLevel, text: 'CREATE_CHILD_SA received before IKE_SA_AUTH completed' },
  },
  {
    icon: Route,
    title: 'Tunnel behaviour',
    body: 'SA lifetimes, rekey cadence, dead-peer detection and the phase-1 / phase-2 posture maintained by each tunnel.',
    example: { severity: 'low' as RiskLevel, text: 'Phase-2 SA lifetime of 8 hours exceeds the recommended 1 hour' },
  },
  {
    icon: Activity,
    title: 'Traffic patterns',
    body: 'Volume bursts, ESP encapsulating a single inner flow, endpoint profiles and the rhythm of an SA negotiation.',
    example: { severity: 'critical' as RiskLevel, text: 'ESP_NULL association observed — payload confidentiality is disabled' },
  },
  {
    icon: Gauge,
    title: 'Risk indicators',
    body: 'One severity per packet, composited from every lens above, so triage starts from the Risk column rather than from a log line.',
    example: { severity: 'medium' as RiskLevel, text: 'Packet 1023 · MEDIUM · legacy 3DES-CBC child SA' },
  },
]

/** Security analysis section — the rule engine explained through real findings. */
export function SecurityAnalysis() {
  return (
    <Section alt>
      <div className="py-14 lg:py-16">
        <SectionHeading
          index="05"
          eyebrow="Security assessment"
          title="Beyond dissection — actual security judgment"
          subtitle="Dissecting a header tells you what a packet is. It does not tell you whether the configuration is safe. Sentinel runs five lenses over every frame and returns a severity with a remediation you can act on."
        />

        <div className="mt-10 grid gap-px overflow-hidden rounded-md border border-edge bg-edge lg:grid-cols-2">
          {LENSES.map(({ icon: Icon, title, body, example }) => {
            const style = riskStyle(example.severity)
            return (
              <article key={title} className="flex gap-3.5 bg-night-950 p-5">
                <span className="flex size-8 shrink-0 items-center justify-center rounded border border-edge bg-night-900 text-accent-300">
                  <Icon className="size-4" aria-hidden />
                </span>
                <div className="min-w-0">
                  <h3 className="text-[14px] font-semibold text-mist">{title}</h3>
                  <p className="mt-1.5 text-[12.5px] leading-relaxed text-mist-dim">{body}</p>

                  {/* Example finding, painted with the analyzer's own risk colours. */}
                  <div
                    className="mt-3 flex items-start gap-2 rounded-[3px] border-l-[3px] bg-night-900 px-2.5 py-2"
                    style={{ borderLeftColor: style.color }}
                  >
                    <span
                      className="ws-risk mt-px shrink-0"
                      style={{ color: style.color, background: style.background, borderColor: style.color }}
                    >
                      {style.label}
                    </span>
                    <span className="mono-tab min-w-0 text-[11px] leading-snug text-mist-dim">{example.text}</span>
                  </div>
                </div>
              </article>
            )
          })}
        </div>
      </div>
    </Section>
  )
}
