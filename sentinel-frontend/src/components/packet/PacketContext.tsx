import { useCallback, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { ApiRequestError } from '@/api/client'
import { ErrorState, Spinner } from '@/components/states'
import { formatSpi, type CaptureRow } from '@/lib/packetRows'
import { formatBytes, formatNumber, formatPercent, formatUtc } from '@/lib/format'
import {
  acronymLabel,
  configTermLabel,
  declaredValueLabel,
  statusLabel,
  trafficLabel,
} from '@/lib/labels'
import type { AssessmentBundle, Finding, RiskContribution } from '@/types'

/**
 * The contextual block that appears under the packet stream once an analyst
 * selects a packet.
 *
 * Every value here comes from one of exactly three places, and the label on
 * each card says which:
 *
 *   CONFIGURED — `bundle.expected`, the parameters the assessment was run
 *                against. The analytics plane has no runtime observation of any
 *                IPsec cryptographic parameter (see `correlation/artifacts.py`,
 *                `observed_evidence_values`), so nothing in this group is a
 *                statement about the traffic on the wire.
 *   OBSERVED    — the packet record from the capture feed, and the assessment
 *                window counters that were measured from it.
 *   ASSESSED    — `bundle.risk`, the scoring engine's own result.
 *
 * The panel never derives one group from another. A configured cipher is never
 * shown as observed, an unavailable value is never turned into `disabled`, and
 * `false` is only ever rendered where the backend published `false`.
 */

/**
 * The backend's provenance tag for a finding raised from configured
 * parameters (`correlation/risk/models.py`, `SOURCE_EXPECTED_CONFIGURATION`).
 */
const CONFIGURATION_SOURCE = 'EXPECTED_CONFIGURATION'

/* ------------------------------------------------------------ primitives */

/** A backend value the store did not publish. Never replaced by a guess. */
export function NotAvailable() {
  return <span className="ls-na">Not available</span>
}

export function Kv({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="ls-kv">
      {items.map(([label, value]) => (
        <div className="ls-kv-row" key={label}>
          <dt className="ls-kv-key">{label}</dt>
          <dd className="ls-kv-val">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Mono({
  children,
  className = '',
}: {
  children: ReactNode
  className?: string
}) {
  return <span className={`ls-mono ${className}`.trim()}>{children}</span>
}

/* ------------------------------------------------------- packet details */

/**
 * The selected packet's own record, as a compact grid.
 *
 * This is the packet as the capture feed recorded it — SPI, sequence, length and
 * the endpoints exist whether or not any assessment ever observed its SPI — so
 * every field here is OBSERVED and none of it is read from the assessment.
 *
 * Deliberately *not* a card. It is the identity strip at the top of the
 * investigation window, so it carries no heading of its own and no close /
 * previous / next controls: those belong to the window, not to the record.
 */
export function PacketDetailGrid({ row }: { row: CaptureRow }) {
  const packet = row.packet.packet
  // `toCaptureRow` substitutes an em dash when the feed carried no address, so a
  // dash means "the record has none", not "the value is unknown". Either way it
  // is not an address and is not shown as one.
  return (
    <dl className="ls-pkt-grid" aria-label="Packet details">
      {(
        [
          ['Time', row.time, row.timeTitle],
          ['Source', row.source !== '\u2014' ? row.source : null],
          ['Destination', row.destination !== '\u2014' ? row.destination : null],
          ['Protocol', row.protocol || null],
          ['Length', formatBytes(row.length)],
          ['SPI', row.spi === null ? null : formatSpi(row.spi)],
          ['Sequence', typeof packet.sequence === 'number' ? String(packet.sequence) : null],
          ['Info', row.info || null],
        ] as Array<[string, string | null, string | undefined]>
      ).map(([label, value, title]) => (
        <div className="ls-pkt-cell" key={label} title={title ?? (value ?? undefined)}>
          <dt className="ls-pkt-key">{label}</dt>
          <dd className="ls-pkt-val ls-mono">{value ?? <NotAvailable />}</dd>
        </div>
      ))}
    </dl>
  )
}

/* --------------------------------------------------- ipsec configuration */

/**
 * The tunnel parameters this assessment was configured with.
 *
 * Marked CONFIGURED as a whole, and labelled per row where a row is not
 * configuration at all. The two gateway rows are the honest exception: the
 * assessment's `expected` block has no endpoint fields — the backend only
 * records the peers it saw in the capture — so those two rows are marked
 * `observed` rather than being folded into the configured state.
 */
export function IpsecConfiguration({
  bundle,
  observed,
  collapsed,
  onToggle,
}: {
  bundle: AssessmentBundle
  observed: AssessmentBundle['observed'] | null
  collapsed: boolean
  onToggle: () => void
}) {
  const expected = bundle.expected
  // IKE and ESP carry their own `dh_group` in the expected block
  // (`correlation/adapters/expected_state.py`), so the IKE group's value must
  // come from `ike` and not from the child SA's field.
  const ike = expected.ike
  const esp = expected.esp

  return (
    <section className="ls-card" aria-label="IPsec configuration">
      <header className="ls-card-head">
        <h2 className="ls-card-title">IPsec Configuration</h2>
        <span className="ls-state ls-state-configured">configured</span>
        <button
          type="button"
          className="ls-collapse"
          onClick={onToggle}
          aria-expanded={!collapsed}
          title={collapsed ? 'Expand configuration' : 'Collapse configuration'}
        >
          <span aria-hidden="true">{collapsed ? '▼' : '▲'}</span>
          <span className="sr-only">{collapsed ? 'Expand' : 'Collapse'}</span>
        </button>
      </header>

      {collapsed ? null : (
        <>
          <p className="ls-card-note">
            The parameters this assessment was configured with. These describe how the tunnel was
            set up, not what was observed on the wire.
          </p>
          <div className="ls-groups">
            <Group title="IKE Configuration">
              <Kv
                items={[
                  [
                    'IKE Version',
                    ike?.version === undefined || ike?.version === null ? (
                      <NotAvailable />
                    ) : (
                      <Mono>IKEv{formatNumber(ike.version)}</Mono>
                    ),
                  ],
                  ['DH Group', ike?.dh_group ? <Mono>{ike.dh_group}</Mono> : <NotAvailable />],
                  [
                    'PFS',
                    // `esp.pfs` is the only PFS field the backend publishes, so
                    // it is read from the child SA and shown here. The title
                    // says so rather than letting the placement imply it came
                    // from the IKE block.
                    esp?.pfs === undefined || esp?.pfs === null ? (
                      <NotAvailable />
                    ) : (
                      <span title="The child SA's PFS setting (expected.esp.pfs).">
                        {esp.pfs ? 'enabled' : 'disabled'}
                      </span>
                    ),
                  ],
                ]}
              />
            </Group>

            <Group title="Child SA (ESP)">
              <Kv
                items={[
                  ['Mode', expected.mode ? statusLabel(expected.mode) : <NotAvailable />],
                  ['Encryption', esp?.encryption ? <Mono>{esp.encryption}</Mono> : <NotAvailable />],
                  ['Integrity / Auth', esp?.integrity ? <Mono>{esp.integrity}</Mono> : <NotAvailable />],
                ]}
              />
            </Group>

            <Group title="Network Parameters">
              <Kv
                items={[
                  [
                    'Address Family',
                    expected.address_family ? acronymLabel(expected.address_family) : <NotAvailable />,
                  ],
                  [
                    'Gateway A',
                    observed?.endpoints?.a ? (
                      <>
                        <Mono>{observed.endpoints.a}</Mono>
                        <ObservedTag />
                      </>
                    ) : (
                      <NotAvailable />
                    ),
                  ],
                  [
                    'Gateway B',
                    observed?.endpoints?.b ? (
                      <>
                        <Mono>{observed.endpoints.b}</Mono>
                        <ObservedTag />
                      </>
                    ) : (
                      <NotAvailable />
                    ),
                  ],
                  [
                    'Traffic Profile',
                    expected.traffic?.profile ? trafficLabel(expected.traffic.profile) : <NotAvailable />,
                  ],
                ]}
              />
            </Group>
          </div>
        </>
      )}
    </section>
  )
}

export function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="ls-group">
      <h3 className="ls-group-title">{title}</h3>
      {children}
    </div>
  )
}

/**
 * Marks a single row whose value came from the capture rather than from
 * configuration, so it cannot be misread as part of the CONFIGURED group above
 * it. Used for the gateways, which exist only as observed peers.
 */
export function ObservedTag() {
  return <span className="ls-state ls-state-observed ls-state-row">observed</span>
}

/**
 * A panel whose subject the backend published nothing for.
 *
 * Used to keep the three-panel layout intact when a packet has no assessment:
 * collapsing the grid to a single card would make the window resize under the
 * analyst, and an empty column labelled honestly is better than a missing one.
 */
export function PanelUnavailable({
  title,
  state,
  stateClass,
  children,
}: {
  title: string
  state: string
  stateClass: string
  children: ReactNode
}) {
  return (
    <section className="ls-card ls-panel" aria-label={title}>
      <header className="ls-card-head">
        <h2 className="ls-card-title">{title}</h2>
        <span className={`ls-state ${stateClass}`}>{state}</span>
      </header>
      <div className="ls-card-body">
        <p className="ls-empty">{children}</p>
      </div>
    </section>
  )
}

/* ---------------------------------------------------- observed traffic */

/**
 * What the captured traffic actually showed, and the one inference the pipeline
 * published on top of it.
 *
 * This panel exists because the configuration panel next to it is not evidence.
 * A configured cipher is a statement about how the tunnel was built; nothing in
 * `observed` records which cipher protected a given packet, because
 * `ObservedState` deliberately models no encryption, integrity or IKE-SA fields.
 * So the two panels cannot be merged, and no configured value is repeated here.
 *
 * Provenance, per the label on each group:
 *   OBSERVED — measured from the capture: counters, endpoint peers, SPIs, and the
 *              protocol-presence flags the parser set.
 *   INFERRED — `bundle.ml`: the traffic-profile classifier's output. A model
 *              prediction, not a measurement, and labelled as one.
 *   UNKNOWN  — the backend published `null` where the field exists. Not a zero
 *              and not a guess.
 */
export function ObservedTraffic({ bundle }: { bundle: AssessmentBundle }) {
  const observed = bundle.observed
  const present = observed?.present === true
  const ml = bundle.ml
  const mlPresent = ml?.present === true

  return (
    <section className="ls-card ls-panel" aria-label="Observed traffic">
      <header className="ls-card-head">
        <h2 className="ls-card-title">Observed Traffic</h2>
        <span className="ls-state ls-state-observed">observed</span>
        <span className="ls-card-sub" title="Where each value in this panel comes from">
          from the capture
        </span>
      </header>

      <div className="ls-card-body">
        <p className="ls-card-note">
          Runtime evidence measured from the captured traffic. No cryptographic parameter appears
          here, because none is observable on the wire.
        </p>

        {!present ? (
          <p className="ls-empty">
            No observed state. The pipeline recorded no authoritative observation for this
            assessment, so there is nothing measured to show. Values are not inferred.
          </p>
        ) : (
          <>
            <Group title="Activity">
              <Kv
                items={[
                  [
                    'Packets',
                    <Mono>{formatNumber(observed.packets_seen)}</Mono>,
                  ],
                  ['Bytes', <Mono>{formatNumber(observed.bytes_seen)}</Mono>],
                  [
                    'Encapsulation',
                    observed.mode ? (
                      <span title="Authoritative SA state, not derived from the wire">
                        {statusLabel(observed.mode)}
                      </span>
                    ) : (
                      <span className="ls-state ls-state-na ls-state-row">unknown</span>
                    ),
                  ],
                  [
                    'Observation at',
                    <Mono>{observed.timestamp_ns ? formatUtc(observed.timestamp_ns) : 'Not available'}</Mono>,
                  ],
                ]}
              />
            </Group>

            <Group title="Protocol evidence">
              <Kv
                items={[
                  [
                    'ESP',
                    observed.esp_seen === undefined ? (
                      <NotAvailable />
                    ) : (
                      <span className="ls-obs-flag" data-seen={observed.esp_seen ? 'yes' : 'no'}>
                        {observed.esp_seen ? 'seen' : 'not seen'}
                      </span>
                    ),
                  ],
                  [
                    'IKE',
                    observed.ike_seen === undefined ? (
                      <NotAvailable />
                    ) : (
                      <span className="ls-obs-flag" data-seen={observed.ike_seen ? 'yes' : 'no'}>
                        {observed.ike_seen ? 'seen' : 'not seen'}
                      </span>
                    ),
                  ],
                  [
                    'AH',
                    observed.ah_seen === undefined ? (
                      <NotAvailable />
                    ) : (
                      <span className="ls-obs-flag" data-seen={observed.ah_seen ? 'yes' : 'no'}>
                        {observed.ah_seen ? 'seen' : 'not seen'}
                      </span>
                    ),
                  ],
                  [
                    'NAT-T',
                    observed.ike_nat_t_seen === undefined ? (
                      <NotAvailable />
                    ) : (
                      <span className="ls-obs-flag" data-seen={observed.ike_nat_t_seen ? 'yes' : 'no'}>
                        {observed.ike_nat_t_seen ? 'seen' : 'not seen'}
                      </span>
                    ),
                  ],
                  [
                    'Tunnel',
                    observed.tunnel_seen === undefined ? (
                      <NotAvailable />
                    ) : (
                      <span className="ls-obs-flag" data-seen={observed.tunnel_seen ? 'yes' : 'no'}>
                        {observed.tunnel_seen ? 'seen' : 'not seen'}
                      </span>
                    ),
                  ],
                  [
                    'SA active',
                    observed.active === undefined ? (
                      <NotAvailable />
                    ) : (
                      <span className="ls-obs-flag" data-seen={observed.active ? 'yes' : 'no'}>
                        {observed.active ? 'active' : 'inactive'}
                      </span>
                    ),
                  ],
                ]}
              />
            </Group>

            {observed.packets_a_to_b || observed.packets_b_to_a ? (
              <Group title="Directional volume">
                <Kv
                  items={[
                    [
                      'A \u2192 B',
                      <Mono>
                        {formatNumber(observed.packets_a_to_b ?? 0)} pkts /{' '}
                        {formatBytes(observed.bytes_a_to_b ?? 0)}
                      </Mono>,
                    ],
                    [
                      'B \u2192 A',
                      <Mono>
                        {formatNumber(observed.packets_b_to_a ?? 0)} pkts /{' '}
                        {formatBytes(observed.bytes_b_to_a ?? 0)}
                      </Mono>,
                    ],
                  ]}
                />
              </Group>
            ) : null}

            {observed.spis && observed.spis.length > 0 ? (
              <Group title={`Observed SPIs (${observed.spis.length})`}>
                <ul className="ls-spi-list">
                  {observed.spis.map((entry) => (
                    <li key={entry.spi} className="ls-spi-row">
                      {/* `SpiEntry.spi` arrives from the backend as a string,
                          so it is shown verbatim rather than reformatted. */}
                      <Mono>{String(entry.spi)}</Mono>
                      <span className="ls-dim">{entry.direction}</span>
                      <span className="ls-dim">{formatNumber(entry.packet_count)} pkts</span>
                    </li>
                  ))}
                </ul>
              </Group>
            ) : null}

            <Group title="ML inference">
              <span className="ls-state ls-state-inferred ls-state-row">inferred</span>
              {!mlPresent ? (
                <p className="ls-empty ls-mt-sm">
                  Not run. {ml?.reason ?? 'The pipeline published no classifier result for this assessment.'}
                </p>
              ) : (
                <Kv
                  items={[
                    [
                      'Traffic class',
                      ml.traffic_class ? (
                        <span title="Predicted by the traffic-profile classifier">
                          {trafficLabel(ml.traffic_class)}
                        </span>
                      ) : (
                        <span className="ls-state ls-state-na ls-state-row">unknown</span>
                      ),
                    ],
                    [
                      'Confidence',
                      ml.classification_confidence === null ||
                      ml.classification_confidence === undefined ? (
                        <span className="ls-state ls-state-na ls-state-row">not available</span>
                      ) : (
                        <Mono>{formatPercent(ml.classification_confidence)}</Mono>
                      ),
                    ],
                    [
                      'Model',
                      ml.model_version ? <Mono>{ml.model_version}</Mono> : <NotAvailable />,
                    ],
                  ]}
                />
              )}
            </Group>
          </>
        )}
      </div>
    </section>
  )
}

/* ------------------------------------------------ configuration findings */

/**
 * The findings this assessment raised about its configuration.
 *
 * Rendered exactly as the backend published them: id, severity, title, reason
 * and the score contribution the scoring engine recorded for that finding in
 * `risk.score_detail.contributions`. Nothing is generated here.
 *
 * An assessment's findings can come from more than one source, and only the
 * `EXPECTED_CONFIGURATION` ones say anything about how the tunnel was
 * configured. The rest would be mislabelled by a card titled "configuration",
 * so they are left out — the count is this filtered list, and the overall risk
 * score may still account for findings shown elsewhere.
 */
export function ConfigurationFindings({
  findings,
  contributions,
  assessmentId,
  score,
  severity,
  collapsed,
  loading,
  error,
  onRetry,
  onToggle,
  onAskAi,
}: {
  findings: Finding[]
  contributions: Map<string, RiskContribution>
  assessmentId: string | null
  /** The assessment's overall score and severity, as the engine published them. */
  score: number | null
  severity: string | null
  collapsed: boolean
  loading: boolean
  error: ApiRequestError | null
  onRetry: () => void
  onToggle: () => void
  onAskAi?: (finding: Finding) => void
}) {
  const configurationFindings = findings.filter(
    (finding) => finding.source === CONFIGURATION_SOURCE,
  )

  // Per-finding disclosure. Collapsed is the default because the backend reason
  // for a configuration rule is a full paragraph of policy prose: it is correct
  // but it is not a summary, and three of them open at once would bury the
  // titles the analyst is scanning for. The collapsed row keeps the fields that
  // identify the finding; the full reason, the provenance and the recorded
  // values are one click away.
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set())
  const toggle = useCallback((id: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  return (
    <section className="ls-card" aria-label="Configuration findings">
      <header className="ls-card-head">
        <h2 className="ls-card-title">Configuration Findings</h2>
        <span
          className="ls-count"
          title="Configuration-sourced findings the backend published for this assessment"
        >
          ({formatNumber(configurationFindings.length)})
        </span>
        {/* The engine's own verdict, shown as assessed rather than observed: it
            covers the whole assessment, which is why it is labelled separately
            from the configuration findings listed below it. */}
        <span
          className="ls-state ls-state-assessed"
          title="The assessment's overall risk score and severity, exactly as the scoring engine computed them."
        >
          assessed · {score === null ? 'Not available' : formatNumber(score)}
          {severity ? ` / ${severity.toUpperCase()}` : ''}
        </span>
        <button
          type="button"
          className="ls-collapse"
          onClick={onToggle}
          aria-expanded={!collapsed}
          title={collapsed ? 'Expand findings' : 'Collapse findings'}
        >
          <span aria-hidden="true">{collapsed ? '▼' : '▲'}</span>
          <span className="sr-only">{collapsed ? 'Expand' : 'Collapse'}</span>
        </button>
      </header>

      {collapsed ? null : (
        <>
          <p className="ls-card-note">
            Raised by the assessment from its configured parameters (source{' '}
            <span className="ls-mono">{CONFIGURATION_SOURCE}</span>). These describe how the
            tunnel was configured, not what was observed on the wire.
          </p>

          {loading ? (
            <div className="ls-state-row-block">
              <Spinner />
              <span>Loading findings…</span>
            </div>
          ) : error ? (
            <ErrorState error={error} onRetry={onRetry} />
          ) : configurationFindings.length === 0 ? (
            <p className="ls-empty">
              This assessment raised no configuration findings.
            </p>
          ) : (
            <ul className="ls-findings">
              {configurationFindings.map((finding) => {
                const open = expanded.has(finding.finding_id)
                return (
                  <li className="ls-finding" key={finding.finding_id} data-severity={finding.severity}>
                    <div className="ls-finding-head">
                      <span className="ls-sev" data-sev={finding.severity}>
                        {String(finding.severity ?? '').toUpperCase()}
                      </span>
                      <span className="ls-finding-title">{finding.title}</span>
                    </div>

                    {/* Identifies the finding and what it cost. The rule id is
                        shown next to the finding id because the id alone does not
                        say which rule fired. */}
                    <div className="ls-finding-meta">
                      <Mono>{finding.finding_id}</Mono>
                      <Mono className="ls-dim">{finding.rule_id}</Mono>
                      <Contribution value={contributions.get(finding.finding_id)} />
                    </div>

                    {/* Collapsed: a clamped summary, so the height stays bounded
                        however long the backend prose is. */}
                    {finding.reason ? (
                      <p className={`ls-finding-reason${open ? '' : ' ls-clamp-2'}`}>
                        {finding.reason}
                      </p>
                    ) : null}

                    <div className="ls-finding-actions">
                      <button
                        type="button"
                        className="ls-btn ls-btn-ghost"
                        onClick={() => toggle(finding.finding_id)}
                        aria-expanded={open}
                        title={open ? 'Hide the full finding record' : 'Show the full finding record'}
                      >
                        <span aria-hidden="true">{open ? '\u25bc' : '\u25b6'}</span>{' '}
                        {open ? 'Less' : 'Details'}
                      </button>
                      <button
                        type="button"
                        className="ls-btn ls-btn-ai"
                        onClick={() => onAskAi?.(finding)}
                        title="Ask the explanation service about this finding"
                      >
                        ✦ Ask AI
                      </button>
                      {assessmentId && (
                        <Link
                          className="ls-btn ls-btn-ghost"
                          to={`/findings/${encodeURIComponent(assessmentId)}/${encodeURIComponent(
                            finding.finding_id,
                          )}`}
                        >
                          View Details →
                        </Link>
                      )}
                    </div>

                    {open ? <FindingDetail finding={finding} /> : null}
                  </li>
                )
              })}
            </ul>
          )}
        </>
      )}
    </section>
  )
}

/**
 * The full finding record, shown only when the analyst asks for it.
 *
 * Everything here is a field the backend published for this finding. The
 * configured/observed distinction is made explicit because the two columns are
 * frequently *not* both present: a configuration rule usually has a
 * `related_variable` and an `expected_value` but a null `observed_value`,
 * because nothing about the running SA is observable. That null is the point of
 * the finding, not a gap in it.
 */
function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="ls-finding-detail">
      <Kv
        items={[
          ['Rule', <Mono>{finding.rule_id}</Mono>],
          ['Category', finding.category ? declaredValueLabel(finding.category) : <NotAvailable />],
          [
            'Variable',
            finding.related_variable ? configTermLabel(finding.related_variable) : <NotAvailable />,
          ],
          ['Condition', finding.condition ? <Mono>{finding.condition}</Mono> : <NotAvailable />],
          [
            'Expected value',
            finding.expected_value === null || finding.expected_value === undefined ? (
              <NotAvailable />
            ) : (
              <Mono>{JSON.stringify(finding.expected_value)}</Mono>
            ),
          ],
          [
            'Observed value',
            // Left explicitly absent when the backend published null. A
            // configuration finding does not imply the value was seen on the
            // wire, and rendering anything here would claim otherwise.
            finding.observed_value === null || finding.observed_value === undefined ? (
              <span className="ls-state ls-state-na ls-state-row">not observed</span>
            ) : (
              <Mono>{JSON.stringify(finding.observed_value)}</Mono>
            ),
          ],
          [
            'Evidence type',
            finding.evidence_type ? declaredValueLabel(finding.evidence_type) : <NotAvailable />,
          ],
          ['Confidence', finding.confidence === null ? <NotAvailable /> : <Mono>{formatPercent(finding.confidence)}</Mono>],
          ['Model', finding.model_version ? <Mono>{finding.model_version}</Mono> : <NotAvailable />],
          ['Policy', finding.risk_policy_version ? <Mono>{finding.risk_policy_version}</Mono> : <NotAvailable />],
          ['Description', finding.description || <NotAvailable />],
        ]}
      />
      {finding.evidence_refs && finding.evidence_refs.length > 0 ? (
        <p className="ls-finding-evidence">
          {finding.evidence_refs.length} evidence reference
          {finding.evidence_refs.length === 1 ? '' : 's'} published with this finding.
        </p>
      ) : null}
    </div>
  )
}

/**
 * The backend's own per-finding score contribution.
 *
 * `added` is what the scoring engine credited this finding after the category
 * cap, so it can be lower than the finding's nominal `weight`. When the two
 * differ the weight is shown alongside it, because a finding worth 12 that only
 * contributed 8 is a fact about the policy, not a discrepancy to be tidied away.
 */
export function Contribution({ value }: { value: RiskContribution | undefined }) {
  if (!value) return null
  const capped = value.added !== value.weight
  return (
    <span
      className="ls-contrib"
      title="Credited amount and nominal weight, from the assessment's risk.score_detail"
    >
      Risk score <Mono>+{value.added}</Mono>
      {capped ? <span className="ls-dim"> (weight {value.weight})</span> : null}
    </span>
  )
}

/* -------------------------------------------------------- empty / load */

/** Shown while the assessment for the selected packet is being read. */
export function ContextLoading() {
  return (
    <section className="ls-card" aria-label="Loading assessment">
      <div className="ls-state-row-block">
        <Spinner />
        <span>Reading the assessment for this packet…</span>
      </div>
    </section>
  )
}

export function ContextError({ error, onRetry }: { error: ApiRequestError; onRetry: () => void }) {
  return (
    <section className="ls-card" aria-label="Assessment unavailable">
      <ErrorState error={error} onRetry={onRetry} />
    </section>
  )
}

/**
 * The whole contextual block for a packet with no assessment.
 *
 * The packet is real and stays on screen; only the assessment-derived sections
 * are absent, and they say so rather than rendering a configuration that the
 * store never published for this SPI.
 */
export function NoAssessmentContext({ row }: { row: CaptureRow }) {
  return (
    <section className="ls-card" aria-label="No assessment for this packet">
      <header className="ls-card-head">
        <h2 className="ls-card-title">IPsec Configuration</h2>
        <span className="ls-state ls-state-na">not available</span>
      </header>
      <div className="ls-card-body">
        <p className="ls-empty">
          Not assessed. No assessment in the store observed{' '}
          {row.spi === null ? 'this packet' : `SPI ${formatSpi(row.spi)}`}, so no
          configuration or findings were published for it. The packet record above is still the
          captured one.
        </p>
      </div>
    </section>
  )
}
