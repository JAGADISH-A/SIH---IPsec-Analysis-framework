import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { analyzeWithAI } from '@/api/ai'
import { formatBytes, formatNumber, formatPercent } from '@/lib/format'
import { formatSpi, type CaptureRow } from '@/lib/packetRows'
import type {
  AiAnswerOrigin,
  AiExplainResponse,
  AssessmentBundle,
  CapabilityStatus,
  Finding,
  RiskContribution,
} from '@/types'

/**
 * ASK AI — a modal analyst tool layered over the investigation workspace.
 *
 * It is deliberately *not* another dashboard panel. It is a centred overlay
 * with its own scroll region, its own conversation and its own lifetime, so it
 * can be opened from a packet or from a single finding without disturbing the
 * workspace underneath.
 *
 * Three rules govern every line in this file.
 *
 *  1. **Only the recorded facts are sent.** The context string is assembled
 *     from fields the analytics plane actually published for this packet and
 *     this assessment. A field that does not exist is left out entirely rather
 *     than filled with a plausible value, and each block is prefixed with its
 *     provenance so the service — and the analyst — can tell an observation
 *     from a configuration value.
 *  2. **Configuration is never presented as observation.** The analytics plane
 *     has no runtime observation of PFS or of any negotiated cipher, so those
 *     values are sent under `CONFIGURED`. If a finding says PFS is disabled and
 *     the runtime state was never observed, nothing here may imply otherwise,
 *     and the evidence boundary is spelled out rather than glossed.
 *  3. **No invented answers.** Every AI turn is what `/ai/explain` returned, or
 *     a faithful rendering of why it returned nothing. When the explanation
 *     service is not connected the modal says so and offers nothing else.
 */

/** What the analyst opened the modal on. */
export type AiSubject =
  | {
      kind: 'packet'
      row: CaptureRow
      assessmentId: string | null
      bundle: AssessmentBundle | null
      contribution: null
      finding: null
    }
  | {
      kind: 'finding'
      row: CaptureRow | null
      assessmentId: string
      bundle: AssessmentBundle | null
      contribution: RiskContribution | null
      finding: Finding
    }

type Turn = {
  key: string
  role: 'user' | 'ai'
  text: string
  /** How the backend said the answer was produced, verbatim from its payload. */
  origin?: AiAnswerOrigin
  modelVersion?: string | null
  limitations?: string[]
  status?: CapabilityStatus
}

let turnCounter = 0
const nextKey = () => `turn-${(turnCounter += 1)}`

/**
 * The opening question.
 *
 * There is no default answer to show, so the modal opens empty and offers
 * questions instead of inventing a first turn the analyst did not ask. The
 * suggestions are assembled from what actually exists in this context, so an
 * analyst is never invited to ask about evidence the record does not contain.
 */
const PACKET_QUESTION =
  'What does the capture record for this packet show, and which recorded findings are associated with it?'
const FINDING_QUESTION = 'Why was this finding raised, and what evidence supports it?'

export function AskAiModal({
  subject,
  open,
  minimized,
  onClose,
  onMinimize,
  onRestore,
}: {
  subject: AiSubject | null
  open: boolean
  minimized: boolean
  onClose: () => void
  onMinimize: () => void
  onRestore: () => void
}) {
  // The conversation is component state and the component stays mounted for as
  // long as the modal is open *or* minimized, so minimizing is purely visual:
  // no turn, no pending answer and no typed question is lost.
  const [turns, setTurns] = useState<Turn[]>([])
  const [draft, setDraft] = useState('')
  const [pending, setPending] = useState(false)
  const threadRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const identity = subjectKey(subject)

  // A different packet or finding is a different conversation. Keying on the
  // subject resets the thread rather than carrying one subject's answers into
  // another's, which would be the most damaging kind of confusion this panel
  // could produce.
  useEffect(() => {
    setTurns([])
    setDraft('')
  }, [identity])

  useEffect(() => {
    if (open && !minimized) inputRef.current?.focus()
  }, [open, minimized])

  // Escape closes, the way any layered tool does. The handler is bound to the
  // document and removed with the modal, so it cannot outlive it.
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onClose])

  // Locking the page behind the overlay is what makes the workspace underneath
  // read as dimmed rather than as a page that happens to be covered. Minimized
  // releases the lock: at that point there is no overlay, only the restore
  // button, and the dashboard must be usable again.
  useEffect(() => {
    if (!open || minimized) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [open, minimized])

  useEffect(() => {
    const thread = threadRef.current
    if (thread) thread.scrollTop = thread.scrollHeight
  }, [turns, pending])

  const context = useMemo(() => (subject ? buildContext(subject) : null), [subject])
  const suggestions = useMemo(() => (subject ? suggestionsFor(subject) : []), [subject])

  // The explanation service explains an assessment, and optionally one of its
  // findings. With no assessment in hand there is nothing for it to read, so the
  // panel is inert and says why rather than accepting a question it cannot
  // answer.
  const entityId = subject?.assessmentId ?? null
  const findingId = subject?.kind === 'finding' ? subject.finding.finding_id : null

  const send = useCallback(
    async (text: string) => {
      const asked = text.trim()
      if (!asked || pending || !entityId) return

      const userTurn: Turn = { key: nextKey(), role: 'user', text: asked }
      setTurns((current) => [...current, userTurn])
      setDraft('')
      setPending(true)

      try {
        const result = await analyzeWithAI({
          entityId,
          entityKind: findingId ? 'finding' : 'assessment',
          findingId,
          context: context ?? undefined,
          question: asked,
          // Paired before filtering: the answer that follows a question is the
          // reply to *that* question, so the pair is built while the original
          // indices still line up.
          history: turns
            .map((turn, index) => ({
              question: turn.role === 'user' ? turn.text : null,
              answer:
                turn.role === 'user' && turns[index + 1]?.role === 'ai'
                  ? (turns[index + 1]?.text ?? '')
                  : '',
            }))
            .filter((pair): pair is { question: string; answer: string } =>
              pair.question !== null && pair.answer !== '',
            ),
        })

        if (result.analysis) {
          setTurns((current) => [
            ...current,
            {
              key: nextKey(),
              role: 'ai',
              text: result.analysis?.answer ?? '',
              origin: result.analysis?.origin,
              modelVersion: result.analysis?.model_version ?? null,
              limitations: answerLimitations(result.analysis),
              status: 'available',
            },
          ])
        } else {
          // No payload means the service did not answer. Its own reason is
          // shown verbatim; a substitute answer is never written here.
          setTurns((current) => [
            ...current,
            {
              key: nextKey(),
              role: 'ai',
              text: result.reason,
              limitations: result.health?.model?.reason
                ? [result.health.model.reason]
                : [],
              status: result.status,
            },
          ])
        }
      } finally {
        setPending(false)
      }
    },
    [context, entityId, findingId, pending, turns],
  )

  if (!open || !subject) return null

  if (minimized) {
    return (
      <button
        type="button"
        className="ls-ai-float"
        onClick={onRestore}
        title="Restore the Ask AI conversation"
      >
        <span aria-hidden="true">✦</span> Ask AI
        {turns.length > 0 ? <span className="ls-ai-float-count">{turns.length}</span> : null}
      </button>
    )
  }

  return (
    <div
      className="ls-ai-overlay"
      role="dialog"
      aria-modal="true"
      aria-label="Ask AI"
      onClick={onClose}
    >
      <div className="ls-ai-modal" onClick={(event) => event.stopPropagation()}>
        <header className="ls-ai-head">
          <div className="ls-ai-headings">
            <h2 className="ls-ai-title">
              <span aria-hidden="true">✦</span> Ask AI
            </h2>
            <p className="ls-ai-sub">
              AI analysis for the selected packet / security finding
            </p>
          </div>
          <div className="ls-ai-tools">
            <button
              type="button"
              className="ls-btn ls-btn-ghost"
              onClick={onMinimize}
              title="Minimize without losing this conversation"
              aria-label="Minimize"
            >
              <span aria-hidden="true">–</span>
            </button>
            <button
              type="button"
              className="ls-btn ls-btn-ghost"
              onClick={onClose}
              title="Close and return to the dashboard"
              aria-label="Close"
            >
              <span aria-hidden="true">×</span>
            </button>
          </div>
        </header>

        <SubjectHeader subject={subject} />

        <div className="ls-ai-thread" ref={threadRef}>
          {turns.length === 0 ? (
            <div className="ls-ai-intro">
              <p className="ls-empty">
                No question asked yet. The explanation service answers questions about what
                this assessment recorded — findings, rules, evidence and the assessment score.
                It does not observe the network, so it cannot report anything the record does
                not contain.
              </p>
            </div>
          ) : (
            turns.map((turn) =>
              turn.role === 'user' ? (
                <div className="ls-ai-msg ls-ai-msg-user" key={turn.key}>
                  <p>{turn.text}</p>
                </div>
              ) : (
                <div className="ls-ai-msg ls-ai-msg-ai" key={turn.key}>
                  <p className="ls-ai-prose">{turn.text}</p>
                  <AnswerProvenance turn={turn} />
                </div>
              ),
            )
          )}

          {pending ? (
            <div className="ls-ai-msg ls-ai-msg-ai">
              <p className="ls-ai-prose ls-dim">Asking the explanation service…</p>
            </div>
          ) : null}
        </div>

        <footer className="ls-ai-foot">
          {entityId ? (
            suggestions.length > 0 ? (
              <div className="ls-ai-suggestions">
                {suggestions.map((suggestion) => (
                  <button
                    type="button"
                    className="ls-chip"
                    key={suggestion}
                    onClick={() => send(suggestion)}
                    disabled={pending}
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            ) : null
          ) : (
            <AiUnavailableNote>
              No assessment observed this packet, so the explanation service has nothing to
              read. It explains assessments and their findings; it does not interpret an
              unassessed packet.
            </AiUnavailableNote>
          )}

          <form
            className="ls-ai-input-row"
            onSubmit={(event) => {
              event.preventDefault()
              send(draft)
            }}
          >
            <input
              ref={inputRef}
              className="ls-ai-input"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder={
                subject.kind === 'finding'
                  ? 'Ask a follow-up question about this finding…'
                  : 'Ask a follow-up question about this packet…'
              }
              disabled={!entityId || pending}
            />
            <button type="submit" className="ls-btn ls-btn-ai" disabled={!entityId || pending}>
              Send
            </button>
          </form>
        </footer>
      </div>
    </div>
  )
}

/**
 * Provenance for one answer, taken from the payload rather than inferred from
 * the prose. An answer that came from the deterministic template says so, even
 * though it is not a model response, because the difference changes how far the
 * analyst should trust the wording.
 */
function AnswerProvenance({ turn }: { turn: Turn }) {
  const unavailable = turn.status === 'not_connected' || turn.status === 'unavailable'

  return (
    <>
      <p className="ls-ai-origin">
        {unavailable ? (
          <span className="ls-state ls-state-na">
            {turn.status === 'not_connected'
              ? 'explanation service not connected'
              : 'no explanation returned'}
          </span>
        ) : (
          <>
            <span className="ls-state ls-state-inferred">inferred</span>
            <span className="ls-dim">
              {originLabel(turn.origin)}
              {turn.modelVersion ? ` · ${turn.modelVersion}` : ''}
            </span>
          </>
        )}
      </p>
      {turn.limitations && turn.limitations.length > 0 ? (
        <ul className="ls-reasons">
          {turn.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      ) : null}
    </>
  )
}

function originLabel(origin: AiAnswerOrigin | undefined): string {
  switch (origin) {
    case 'llm':
      return 'model-generated explanation'
    case 'deterministic_template':
      return 'deterministic template'
    case 'glossary':
      return 'glossary'
    case 'fixed_refusal':
      return 'refusal by policy'
    case 'unavailable':
      return 'not available'
    default:
      return 'origin not stated'
  }
}

/**
 * What the payload itself says the answer could not be used for.
 *
 * These are read from the response rather than composed here: the scope and
 * guard blocks record the service's own boundaries (was the question in scope,
 * did a policy guard intervene), and the provider reason records why a
 * configured model did not answer. Reciting them keeps the provenance of every
 * answer visible instead of asking the analyst to trust the prose.
 */
function answerLimitations(analysis: AiExplainResponse | undefined): string[] {
  if (!analysis) return []
  const notes: string[] = []
  if (analysis.scope && !analysis.scope.in_scope) {
    notes.push(`Out of scope: ${analysis.scope.reason}`)
  }
  if (analysis.guard && analysis.guard.status !== 'clean') {
    notes.push(
      analysis.guard.detail
        ? `Policy guard ${analysis.guard.status}: ${analysis.guard.detail}`
        : `Policy guard ${analysis.guard.status}`,
    )
  }
  if (analysis.provider_unavailable_reason) {
    notes.push(`Model provider unavailable: ${analysis.provider_unavailable_reason}`)
  }
  return notes
}

/* ------------------------------------------------------- subject header */

/**
 * What the conversation is about, in one line, with the provenance of each part.
 */
function SubjectHeader({ subject }: { subject: AiSubject }) {
  if (subject.kind === 'packet') {
    const row = subject.row
    return (
      <div className="ls-ai-subject">
        <p className="ls-ai-subject-title">
          Selected Packet #{row.sequence}
          <span className="ls-state ls-state-observed">observed</span>
        </p>
        <p className="ls-dim">
          {row.protocol || 'No protocol label'} · {address(row.source)} → {address(row.destination)}
          {row.spi === null ? '' : ` · SPI ${formatSpi(row.spi)}`}
        </p>
      </div>
    )
  }

  const finding = subject.finding
  return (
    <div className="ls-ai-subject">
      <p className="ls-ai-subject-title">
        Finding · {finding.finding_id}
        <span className="ls-sev" data-sev={finding.severity}>
          {String(finding.severity).toUpperCase()}
        </span>
        <span className="ls-state ls-state-configured">configured</span>
      </p>
      <p className="ls-dim">{finding.title}</p>
      {subject.contribution ? (
        <p className="ls-dim">
          Risk score +{subject.contribution.added}
          {subject.contribution.added !== subject.contribution.weight
            ? ` (weight ${subject.contribution.weight})`
            : ''}
        </p>
      ) : null}
      {subject.row ? (
        <p className="ls-dim">
          Opened from Packet #{subject.row.sequence}
          {subject.row.spi === null ? '' : ` · SPI ${formatSpi(subject.row.spi)}`}
        </p>
      ) : null}
    </div>
  )
}

function address(value: string): string {
  return value === '—' ? 'not recorded' : value
}

/* -------------------------------------------------------------- context */

/**
 * The recorded context sent with a question.
 *
 * Assembled only from fields the backend published, grouped by provenance, with
 * unavailable fields omitted instead of filled. This string is echoed back by
 * the service, so what it contains is exactly what the model was allowed to see.
 */
function buildContext(subject: AiSubject): string {
  const lines: string[] = []

  if (subject.kind === 'packet') {
    const row = subject.row
    const packet = row.packet.packet
    lines.push(
      'OBSERVED — packet record from the capture feed:',
      `- stream position: #${row.sequence} (newest first)`,
      `- captured at: ${row.timeTitle}`,
      `- source: ${address(row.source)}`,
      `- destination: ${address(row.destination)}`,
      `- protocol label: ${row.protocol || 'none published'}`,
      `- classification: ${row.classification}`,
      `- length: ${formatBytes(row.length)}`,
      `- spi: ${row.spi === null ? 'none recorded' : formatSpi(row.spi)}`,
      `- ipsec sequence: ${packet.sequence}`,
      `- feed info: ${row.info || 'none published'}`,
    )
  } else {
    const finding = subject.finding
    lines.push(
      'CONFIGURED — finding raised from configured parameters:',
      `- finding id: ${finding.finding_id}`,
      `- rule id: ${finding.rule_id}`,
      `- title: ${finding.title}`,
      `- severity: ${String(finding.severity).toUpperCase()}`,
      `- source: ${finding.source}`,
      `- related variable: ${finding.related_variable}`,
      `- condition: ${finding.condition}`,
      `- reason: ${finding.reason}`,
    )
    if (finding.observed_value !== null && finding.observed_value !== undefined) {
      lines.push(`- observed value: ${JSON.stringify(finding.observed_value)}`)
    } else {
      lines.push(
        '- observed value: none — this finding is about a configured value, and the corresponding runtime state was not observed',
      )
    }
    if (subject.contribution) {
      lines.push(
        `- score contribution: +${subject.contribution.added} (weight ${subject.contribution.weight}, category ${subject.contribution.category})`,
      )
    }
    if (subject.row) {
      lines.push(
        `OBSERVED — packet this was opened from: #${subject.row.sequence}, ${subject.row.protocol || 'no protocol label'}, ${address(subject.row.source)} → ${address(subject.row.destination)}, spi ${subject.row.spi === null ? 'none recorded' : formatSpi(subject.row.spi)}, info ${subject.row.info || 'none published'}`,
      )
    }
  }

  lines.push(...configurationContext(subject.bundle))
  lines.push(
    '',
    'EVIDENCE BOUNDARY: the analytics plane records configured parameters and observed packet',
    'fields only. It performs no runtime observation of negotiated ciphers, PFS state, key',
    'lifetime or anti-replay counters, so nothing above may be reported as a runtime',
    'observation of those properties.',
  )

  return lines.join('\n')
}

/**
 * The assessed context a finding-level question is about: the configured tunnel
 * parameters, the runtime evidence the capture produced, and the scoring
 * engine's own verdict.
 *
 * Configured and observed stay on separate lines with separate labels, because
 * the single most damaging thing this string could do is present a configured
 * cipher as something that was seen on the wire. The backend models no
 * encryption, integrity or IKE-SA field in its observed state, so no such value
 * can appear in the OBSERVED block — and if one ever did, it would have to come
 * from a field the backend did not define.
 */
function configurationContext(bundle: AssessmentBundle | null): string[] {
  if (!bundle) return []
  const expected = bundle.expected
  const ike = expected.ike
  const esp = expected.esp
  const lines: string[] = ['', 'CONFIGURED — tunnel parameters for this assessment:']

  if (ike?.version !== undefined && ike.version !== null) lines.push(`- ike version: ${ike.version}`)
  if (ike?.dh_group) lines.push(`- ike dh group: ${ike.dh_group}`)
  if (ike?.encryption) lines.push(`- ike encryption: ${ike.encryption}`)
  if (esp?.encryption) lines.push(`- esp encryption: ${esp.encryption}`)
  if (esp?.integrity) lines.push(`- esp integrity: ${esp.integrity}`)
  if (esp?.dh_group) lines.push(`- esp dh group: ${esp.dh_group}`)
  if (esp?.pfs !== undefined && esp.pfs !== null) lines.push(`- esp pfs: ${esp.pfs}`)
  if (expected.mode) lines.push(`- mode: ${expected.mode}`)
  if (expected.address_family) lines.push(`- address family: ${expected.address_family}`)
  if (expected.traffic?.profile) lines.push(`- traffic profile: ${expected.traffic.profile}`)
  if (!lines.slice(1).length) lines.push('- none published by the assessment')

  lines.push(...observedContext(bundle))
  lines.push(...inferenceContext(bundle))

  const score = bundle.risk?.overall_score
  if (typeof score === 'number') {
    lines.push(
      `ASSESSED — risk score ${formatNumber(score)} (${String(bundle.risk.severity).toUpperCase()}), engine ${bundle.risk.risk_engine_version ?? 'unstated'}`,
    )
  }

  return lines
}

/**
 * What the capture measured for the assessment window.
 *
 * Counters and protocol-presence flags only. There is deliberately no cipher,
 * integrity, PFS, lifetime or replay value here, because none of those are
 * observable from the wire and the backend does not model them.
 */
function observedContext(bundle: AssessmentBundle): string[] {
  const observed = bundle.observed
  if (!observed || observed.present !== true) {
    return ['', 'OBSERVED — no observation was published for this assessment, so no runtime value', '  can be reported. Absence of evidence is not evidence of absence. The packet fields', '  above are the only runtime record for this packet.']
  }

  const lines: string[] = ['', 'OBSERVED — measured from the captured traffic:']
  lines.push(`- packets seen: ${formatNumber(observed.packets_seen ?? 0)}`)
  lines.push(`- bytes seen: ${formatNumber(observed.bytes_seen ?? 0)}`)
  if (observed.mode) lines.push(`- encapsulation mode (authoritative SA state): ${observed.mode}`)
  lines.push(`- ESP seen: ${boolWord(observed.esp_seen)}`)
  lines.push(`- IKE seen: ${boolWord(observed.ike_seen)}`)
  lines.push(`- AH seen: ${boolWord(observed.ah_seen)}`)
  lines.push(`- NAT-T seen: ${boolWord(observed.ike_nat_t_seen)}`)
  lines.push(`- tunnel seen: ${boolWord(observed.tunnel_seen)}`)
  lines.push(`- SA active: ${boolWord(observed.active)}`)

  const endpoints = observed.endpoints
  if (endpoints?.a || endpoints?.b) {
    lines.push(`- observed endpoints: a=${endpoints?.a ?? 'none'}, b=${endpoints?.b ?? 'none'}`)
  }
  if (observed.spis && observed.spis.length > 0) {
    lines.push(
      `- observed SPIs: ${observed.spis
        .map((entry) => `${entry.spi} (${entry.direction}, ${formatNumber(entry.packet_count)} pkts)`)
        .join('; ')}`,
    )
  }
  return lines
}

/** The classifier output, labelled inferred so it is never read as a measurement. */
function inferenceContext(bundle: AssessmentBundle): string[] {
  const ml = bundle.ml
  if (!ml || ml.present !== true) {
    return [
      '',
      `INFERRED — not run. ${ml?.reason ?? 'The pipeline published no classifier result for this assessment.'}`,
    ]
  }
  const lines: string[] = ['', 'INFERRED — traffic-profile classifier output (a prediction, not a measurement):']
  lines.push(`- traffic class: ${ml.traffic_class ?? 'unstated'}`)
  if (ml.classification_confidence !== null && ml.classification_confidence !== undefined) {
    lines.push(`- confidence: ${formatPercent(ml.classification_confidence)}`)
  }
  if (ml.model_version) lines.push(`- model: ${ml.model_version}`)
  return lines
}

/** `undefined` means the backend never published the flag; that is not `false`. */
function boolWord(value: boolean | undefined): string {
  if (value === undefined) return 'not published'
  return value ? 'yes' : 'no'
}

/* --------------------------------------------------------- suggestions */

/**
 * Suggested questions, built from what this context actually contains.
 *
 * Each one is answerable from the recorded assessment: nothing here asks about
 * live traffic, negotiated ciphers or PFS state at runtime, because the backend
 * has no observation of those and an answer would have to be invented.
 */
function suggestionsFor(subject: AiSubject): string[] {
  if (subject.kind === 'packet') {
    const suggestions: string[] = []
    if (subject.row.spi !== null) suggestions.push('What does this SPI indicate?')
    suggestions.push('Why is this packet associated with these findings?')
    if (subject.bundle) suggestions.push('What evidence supports these findings?')
    suggestions.push(PACKET_QUESTION)
    return suggestions
  }

  const finding = subject.finding
  const suggestions = [FINDING_QUESTION]
  if (/pfs/i.test(finding.finding_id) || /pfs/i.test(finding.related_variable ?? '')) {
    // Asked of the recorded configuration, not of the wire: the runtime state
    // is explicitly unavailable, so the question does not presume otherwise.
    suggestions.push('Why is PFS relevant to this configuration?')
  }
  if (subject.row?.spi != null) suggestions.push('What does this SPI indicate?')
  suggestions.push('What evidence supports this finding?')
  return suggestions
}

/* ------------------------------------------------------------- helpers */

/**
 * Identity of the current subject. Changing it starts a new conversation; the
 * same packet reopened keeps the one it had.
 */
function subjectKey(subject: AiSubject | null): string {
  if (!subject) return 'none'
  return subject.kind === 'packet'
    ? `packet:${subject.row.key}`
    : `finding:${subject.assessmentId}:${subject.finding.finding_id}`
}

export function AiUnavailableNote({ children }: { children: ReactNode }) {
  return <p className="ls-ai-blocked">{children}</p>
}