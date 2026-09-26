import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { SEVERITIES, SEVERITY_LABEL } from '../../types/evidence'
import { RestrictedNotice, SEVERITY_TONE } from '../../components/common/Evidence.tsx'
import { useSystemHealth } from '../../hooks/queries'
import { env } from '../../config/env'
import type { ReactNode } from 'react'

/**
 * Methodology documentation.
 *
 * This page is part of the product surface on purpose: a research tool whose
 * judgements cannot be traced back to published definitions has no defensible
 * output. Everything stated here is also enforced in the UI.
 */
export function DocumentationPage() {
  const health = useSystemHealth()

  return (
    <PageScroll>
      <PageHeader
        title="Documentation"
        description="How this platform decides what it reports: definitions, severity ladder, confidence semantics, and the limits of the current build."
        meta={
          <>
            <span>IPsec / IKE analysis</span>
            <span className="font-mono">v1.0</span>
          </>
        }
      />

      <PageBody>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <div className="flex flex-col gap-4">
            <Section id="what-this-is" title="What this platform is">
              <p>
                IPsec Sentinel analyses IKE and ESP/AH traffic and reports what it observed. It dissects captures,
                reconstructs security associations, evaluates the negotiated configuration against a rule set, runs
                classification models over the resulting metadata, and correlates the outcome into findings and an
                overall posture.
              </p>
              <p>
                The separation matters. <strong>Observations</strong> come from the wire and can be checked against a
                capture. <strong>Classifications</strong> are inferences and carry a confidence. <strong>Findings</strong>{' '}
                are judgements that cite observations as evidence. A finding you cannot trace to a packet range is a
                bug, not a result.
              </p>
            </Section>

            <Section id="severity" title="Severity ladder">
              <p>
                Severity is assigned by the analysis engine from the detected condition, not by the operator and not by a
                user-supplied score. It is a fixed ladder so that counts are comparable over time.
              </p>
              <table className="mt-3 w-full text-left text-[12px]">
                <thead className="border-b border-edge text-[10.5px] uppercase tracking-wide text-mist-faint">
                  <tr>
                    <th scope="col" className="py-1.5 pr-3 font-medium">Severity</th>
                    <th scope="col" className="py-1.5 pr-3 font-medium">Meaning</th>
                    <th scope="col" className="py-1.5 font-medium">Operator action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge/60">
                  {SEVERITIES.map((severity) => (
                    <tr key={severity}>
                      <th scope="row" className="py-2 pr-3">
                        <span
                          className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10.5px] font-medium uppercase ${SEVERITY_TONE[severity]}`}
                        >
                          {SEVERITY_LABEL[severity]}
                        </span>
                      </th>
                      <td className="py-2 pr-3 text-mist-dim">{SEVERITY_MEANING[severity]}</td>
                      <td className="py-2 text-mist-faint">{SEVERITY_ACTION[severity]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>

            <Section id="confidence" title="Confidence semantics">
              <p>
                Confidence expresses how much the platform trusts a classification or an overall assessment. It is
                never a severity and never a probability of attack.
              </p>
              <ul className="mt-2 flex flex-col gap-1.5">
                {(['high', 'medium', 'low', 'unknown'] as const).map((band) => (
                  <li key={band} className="flex items-start gap-2">
                    <span className="min-w-24 font-mono text-[11px] uppercase text-mist-faint">{band}</span>
                    <span className="text-mist-dim">{CONFIDENCE_MEANING[band]}</span>
                  </li>
                ))}
              </ul>
              <div className="mt-3">
                <RestrictedNotice>
                  A null confidence is rendered as <strong>Unknown</strong> everywhere in this application. It is never
                  rounded to 0%, and it is never replaced with a default. The traffic classifier, for example, reports
                  a flow as <code>unknown</code> with its best guess recorded separately as the proposed label.
                </RestrictedNotice>
              </div>
              <p className="mt-2 text-[11px] text-mist-faint">
                Band thresholds: high ≥ 0.85, medium ≥ 0.6, low below 0.6, unknown when no estimate exists.
              </p>
            </Section>

            <Section id="evidence" title="Evidence model">
              <p>
                Every finding references one or more evidence records. Each record names the artefact it came from (a
                capture id), the exact field or packet range, the raw value as observed, the source component, and its
                own confidence.
              </p>
              <ul className="mt-2 flex list-disc flex-col gap-1 pl-5 text-mist-dim">
                <li>
                  <span className="text-mist">packet</span> — a raw frame with decoded protocol fields.
                </li>
                <li>
                  <span className="text-mist">negotiated-parameters</span> — a value from an IKE exchange (proposal,
                  transform, key exchange method).
                </li>
                <li>
                  <span className="text-mist">security-association</span> — the state of an inbound or outbound SA.
                </li>
                <li>
                  <span className="text-mist">configuration</span> — a declared configuration recorded with an
                  experiment or capture.
                </li>
                <li>
                  <span className="text-mist">model-output</span> — an inference, always with a confidence.
                </li>
                <li>
                  <span className="text-mist">correlation</span> — a derived conclusion linking other records.
                </li>
              </ul>
            </Section>

            <Section id="protocols" title="Protocol coverage">
              <p>
                The dissector covers the parts of RFC 7296 and RFC 4301/4302 needed to answer security questions, not
                the full specifications.
              </p>
              <div className="mt-2 grid gap-2 sm:grid-cols-2">
                {PROTOCOL_COVERAGE.map((entry) => (
                  <div key={entry.name} className="rounded-md border border-edge bg-night-900 p-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[12.5px] font-medium text-mist">{entry.name}</span>
                      <span
                        className={
                          entry.complete
                            ? 'text-[10.5px] uppercase text-success'
                            : 'text-[10.5px] uppercase text-warning'
                        }
                      >
                        {entry.complete ? 'Complete' : 'Partial'}
                      </span>
                    </div>
                    <p className="mt-1 text-[11.5px] leading-relaxed text-mist-dim">{entry.scope}</p>
                  </div>
                ))}
              </div>
            </Section>
          </div>

          <div className="flex flex-col gap-4">
            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Current build</h2>
              <dl className="mt-2 flex flex-col gap-1.5 text-[12px]">
                <Row label="Data source" value={env.useMockData ? 'Simulated (no backend)' : `${env.apiBaseUrl}`} />
                <Row
                  label="Services"
                  value={
                    health.data
                      ? `${health.data.services.filter((service) => service.status === 'operational').length}/${health.data.services.length} operational`
                      : 'Checking…'
                  }
                />
                <Row label="TShark integration" value="Not connected" />
                <Row label="Testbed control" value="Not connected" />
                <Row label="ML inference" value="Simulated outputs" />
              </dl>
              <p className="mt-3 text-[11px] leading-relaxed text-mist-faint">
                Every figure in this build comes from a deterministic dataset defined in the frontend. Nothing is
                measured from a real network, and the platform says so wherever a number could otherwise be mistaken for
                an observation.
              </p>
            </Panel>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Triage workflow</h2>
              <ol className="mt-2 flex list-decimal flex-col gap-1.5 pl-5 text-[11.5px] leading-relaxed text-mist-dim">
                <li>Read the finding: observed, expected, impact, recommendation.</li>
                <li>Open each evidence record and confirm the raw value in the artefact.</li>
                <li>Check the confidence. Below 0.6, verify by hand before acting.</li>
                <li>Compare against a known-good configuration, ideally from an experiment with declared ground truth.</li>
                <li>Record the decision. Triage status and notes are operator annotations and stay auditable.</li>
                <li>Never edit severity or evidence — those belong to the analysis engine.</li>
              </ol>
            </Panel>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Known limitations</h2>
              <ul className="mt-2 flex list-disc flex-col gap-1.5 pl-5 text-[11.5px] leading-relaxed text-mist-dim">
                <li>Traffic classification uses observable metadata only. It cannot see application content.</li>
                <li>Encrypted payloads are not decrypted. ESP analysis is limited to headers and SPI/sequence state.</li>
                <li>Certificates are read for validity, chain and algorithm, not verified against a live trust store.</li>
                <li>Model outputs in this build are illustrative, not the result of running a trained classifier.</li>
                <li>Session reconstruction assumes one IKE association per capture context; interleaved peers may need manual review.</li>
              </ul>
            </Panel>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Standards references</h2>
              <ul className="mt-2 flex flex-col gap-1 font-mono text-[11px] text-mist-dim">
                {STANDARDS.map((standard) => (
                  <li key={standard}>{standard}</li>
                ))}
              </ul>
            </Panel>
          </div>
        </div>
      </PageBody>
    </PageScroll>
  )
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <Panel padded>
      <h2 id={id} className="text-[13px] font-semibold tracking-wide text-mist">
        {title}
      </h2>
      <div className="mt-2 flex flex-col gap-2 text-[12.5px] leading-relaxed text-mist-dim">{children}</div>
    </Panel>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-mist-faint">{label}</dt>
      <dd className="text-right text-mist">{value}</dd>
    </div>
  )
}

const SEVERITY_MEANING: Record<(typeof SEVERITIES)[number], string> = {
  critical: 'An active or imminent compromise of tunnel security.',
  high: 'A serious weakness that materially weakens the tunnel.',
  medium: 'A weakness worth fixing; exploitation is constrained.',
  low: 'Hardening advice or a deviation with limited impact.',
  informational: 'An observation recorded for completeness.',
  unknown: 'The engine could not classify this condition.',
}

const SEVERITY_ACTION: Record<(typeof SEVERITIES)[number], string> = {
  critical: 'Respond now',
  high: 'Schedule remediation',
  medium: 'Plan remediation',
  low: 'Track',
  informational: 'No action',
  unknown: 'Investigate',
}

const CONFIDENCE_MEANING: Record<'high' | 'medium' | 'low' | 'unknown', string> = {
  high: '≥ 0.85. The model was consistent across the features it uses; treat as reliable.',
  medium: '0.6 – 0.85. Consistent but sensitive to assumptions; verify before acting.',
  low: '< 0.6. Weak signal. Treat as a hypothesis and confirm from evidence.',
  unknown: 'No estimate was produced. Do not substitute a number for this.',
}

const PROTOCOL_COVERAGE: { name: string; scope: string; complete: boolean }[] = [
  { name: 'IKEv1', scope: 'Main mode, aggressive mode, transforms, pre-shared keys and certificates.', complete: true },
  { name: 'IKEv2', scope: 'Exchange types, proposals, traffic selectors, child SA rekey, EAP.', complete: true },
  { name: 'ESP', scope: 'SPI, sequence numbers, anti-replay window, header only (payload is encrypted).', complete: true },
  { name: 'AH', scope: 'SPI, sequence, ICV length and integrity check presence.', complete: true },
  { name: 'Certificates', scope: 'Chain, validity, key usage, signature algorithm. Revocation is not checked.', complete: false },
  { name: 'Rekey and lifetime', scope: 'Soft/hard expiry, ISAs, child SA lifetime abuse detection.', complete: true },
  { name: 'Traffic classification', scope: 'Metadata-derived classes with confidence and an explicit unknown.', complete: true },
  { name: 'Attack inference', scope: 'Downgrade, replay, fuzzing and malformed-response patterns. Heuristic.', complete: false },
]

const STANDARDS = [
  'RFC 7296 — Internet Key Exchange Protocol Version 2 (IKEv2)',
  'RFC 2407 — The ISAKMP Protocol (IKEv1)',
  'RFC 4301 — IP Security Architecture (IPsec)',
  'RFC 4302 — IP Encapsulating Security Payload (ESP)',
  'RFC 4303 — IP Authentication Header (AH)',
  'RFC 8247 — Cryptographic Algorithms for IKEv2 and IPsec',
  'NIST SP 800-52 — TLS / IPsec cryptographic configuration guidance',
]
