import { useCallback, useRef, useState } from 'react'
import { analyzeWithAI } from '@/api/ai'
import { Spinner } from '@/components/states'
import type {
  AiAnalysisResult,
  AiExplainResponse,
  AiOrigin,
  AiScopeIntent,
  CapabilityStatus,
} from '@/types'

/**
 * The AI explanation panel.
 *
 * One rule shapes every decision in this file: the panel must never let a
 * reader mistake generated text for a record. Concretely —
 *
 *  - the four origins are separate visual elements, never one merged blob;
 *  - severity and score are rendered from `analysis.authoritative`, i.e. the
 *    risk engine's own numbers, and never parsed out of the prose;
 *  - when the guard withheld generated text, that is stated visibly rather
 *    than silently swapped for the template, because "the model was overruled"
 *    and "the model wrote this" are very different things to an analyst;
 *  - when the service is down it is one line, and nothing else in the
 *    investigation changes.
 *
 * The panel is additive. It can be collapsed, ignored, or unavailable, and the
 * assessment, findings, evidence and custody around it stay exactly as
 * authoritative as they were before it rendered.
 */

/** How each origin is labelled on screen. The four must be visually distinct. */
const ORIGIN_LABEL: Record<AiOrigin, string> = {
  observed_fact: 'OBSERVED FACT',
  deterministic_assessment: 'DETERMINISTIC ASSESSMENT',
  ml_inference: 'ML INFERENCE',
  ai_explanation: 'AI EXPLANATION',
}

const ORIGIN_CLASS: Record<AiOrigin, string> = {
  observed_fact: 'pw-ai-origin pw-ai-origin-obs',
  deterministic_assessment: 'pw-ai-origin pw-ai-origin-det',
  ml_inference: 'pw-ai-origin pw-ai-origin-ml',
  ai_explanation: 'pw-ai-origin pw-ai-origin-ai',
}

export function AiOriginChip({ origin }: { origin: AiOrigin }) {
  return (
    <span className={ORIGIN_CLASS[origin]} title={ORIGIN_HELP[origin]}>
      {ORIGIN_LABEL[origin]}
    </span>
  )
}

/** Why each label is there, so a hover can teach rather than assert. */
const ORIGIN_HELP: Record<AiOrigin, string> = {
  observed_fact: 'Recorded by the capture, configuration and drift tools. A measurement.',
  deterministic_assessment:
    'Produced by the risk engine from a documented rule. This is the security verdict.',
  ml_inference:
    'A model prediction about traffic shape. It is not a judgement and did not set the severity.',
  ai_explanation:
    'Generated prose from the service. It restates the values above and adds no finding.',
}

/** One plain-language question, chosen from what is actually on screen. */
function defaultQuestion(input: {
  hasFinding: boolean
  severity: string | null
  hasEvidence: boolean
}): string {
  if (input.hasFinding && input.severity) {
    return `Why is this ${input.severity}?`
  }
  if (input.hasEvidence) {
    return 'What evidence supports this assessment?'
  }
  return 'What did the backend record for this assessment?'
}

const INTENT_LABEL: Record<AiScopeIntent, string> = {
  risk_explanation: 'risk rationale',
  expected_vs_observed: 'expected vs observed',
  evidence: 'evidence',
  terminology: 'IPsec definition',
  decision_request: 'decision declined',
  general_ipsec: 'assessment',
  out_of_scope: 'out of scope',
}

/** Human label for where the text came from, which is not always a model. */
function originNote(analysis: AiExplainResponse): string {
  switch (analysis.origin) {
    case 'llm':
      return analysis.model_version
        ? `Written by ${analysis.model_version} and checked against the recorded values.`
        : 'Written by a language model and checked against the recorded values.'
    case 'deterministic_template':
      return (
        'No language model is configured, so this text was assembled by the service from the ' +
        'recorded values. It is not generated prose.'
      )
    case 'glossary':
      return 'This is the service’s own IPsec definition, not model output.'
    case 'fixed_refusal':
      return 'The service declined the question.'
    default:
      return 'The service could not answer from the recorded context.'
  }
}

function StatusPill({ status, connected }: { status: CapabilityStatus; connected: boolean }) {
  if (connected) {
    return <span className="pw-ai-origin pw-ai-origin-det">READ-ONLY SERVICE</span>
  }
  const label = status === 'not_connected' ? 'NOT CONNECTED' : 'UNAVAILABLE'
  return <span className="pw-prov pw-prov-miss">{label}</span>
}

function AuthoritativeStrip({ analysis }: { analysis: AiExplainResponse }) {
  const auth = analysis.authoritative
  return (
    <div className="pw-ai-block">
      <div className="pw-ai-block-head">
        <AiOriginChip origin="deterministic_assessment" />
        <span className="pw-quiet">as recorded by the risk engine</span>
      </div>
      <div className="pw-ai-facts">
        <div>
          <span className="pw-ai-fact-key">severity</span>
          <span className="pw-ai-fact-val">{auth.severity ?? 'not recorded'}</span>
        </div>
        <div>
          <span className="pw-ai-fact-key">risk score</span>
          <span className="pw-ai-fact-val">{auth.risk_score ?? 'not recorded'}</span>
        </div>
        <div>
          <span className="pw-ai-fact-key">policy</span>
          <span className="pw-ai-fact-val">{auth.risk_policy_version ?? 'not recorded'}</span>
        </div>
      </div>
    </div>
  )
}

function MlStrip({ analysis }: { analysis: AiExplainResponse }) {
  const ml = analysis.ml
  return (
    <div className="pw-ai-block">
      <div className="pw-ai-block-head">
        <AiOriginChip origin="ml_inference" />
        <span className="pw-quiet">a prediction, not a verdict</span>
      </div>
      <p className="pw-faint-text">
        {ml.present
          ? `Traffic class ${ml.traffic_class ?? 'not recorded'} at ${
              ml.classification_confidence === null
                ? 'no recorded confidence'
                : `${Math.round(ml.classification_confidence * 100)}% model confidence`
            }${ml.model_version ? ` (${ml.model_version})` : ''}. This did not produce the severity.`
          : (ml.reason ?? 'No ML result was recorded for this assessment.')}
      </p>
      <p className="pw-ai-none">
        The assistant has no confidence of its own to report.
      </p>
    </div>
  )
}

function GuardNotice({ analysis }: { analysis: AiExplainResponse }) {
  if (analysis.guard.status === 'clean') return null
  const names = analysis.guard.violations.join(', ').replace(/_/g, ' ')
  return (
    <div className="pw-ai-block pw-ai-block-guard">
      <div className="pw-ai-block-head">
        <span className="pw-prov pw-prov-miss">GENERATED TEXT WITHHELD</span>
      </div>
      <p className="pw-faint-text">
        The service rejected the model’s answer because it would have {names}. What is shown
        below is the explanation built from the recorded values instead, so the recorded severity
        and score stand unchanged.
      </p>
    </div>
  )
}

function AnswerBlock({ analysis }: { analysis: AiExplainResponse }) {
  return (
    <div className="pw-ai-block">
      <div className="pw-ai-block-head">
        <AiOriginChip origin="ai_explanation" />
        <span className="pw-quiet">{INTENT_LABEL[analysis.scope.intent]}</span>
      </div>
      <p className="pw-ai-prose">{analysis.answer}</p>
      <p className="pw-ai-none">{originNote(analysis)}</p>
      {analysis.scope.intent === 'decision_request' ? (
        <p className="pw-ai-none">
          The assistant explains what was recorded and does not make the call.
        </p>
      ) : null}
    </div>
  )
}

function Thread({
  turns,
  onAsk,
  busy,
  disabled,
}: {
  turns: { question: string; analysis: AiExplainResponse }[]
  onAsk: (question: string) => void
  busy: boolean
  disabled: boolean
}) {
  const [draft, setDraft] = useState('')
  const inputRef = useRef<HTMLInputElement | null>(null)

  const submit = () => {
    const question = draft.trim()
    if (question === '' || busy) return
    onAsk(question)
    setDraft('')
  }

  return (
    <div className="pw-ai-thread">
      {turns.map((turn, index) => (
        <details key={`${turn.question}-${index}`} className="pw-ai-turn">
          <summary>
            <span className="pw-ai-q">{turn.question}</span>
            <span className="pw-quiet"> {turn.analysis.origin.replace(/_/g, ' ')}</span>
          </summary>
          <p className="pw-ai-prose pw-ai-prose-prior">{turn.analysis.answer}</p>
        </details>
      ))}
      <div className="pw-ai-ask">
        <input
          ref={inputRef}
          type="text"
          className="pw-ai-input"
          placeholder="Ask a follow-up about this assessment…"
          value={draft}
          maxLength={500}
          disabled={disabled}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault()
              submit()
            }
          }}
          aria-label="Ask a follow-up about this assessment"
        />
        <button
          type="button"
          className="pw-btn"
          onClick={submit}
          disabled={disabled || busy || draft.trim() === ''}
        >
          {busy ? <Spinner /> : 'Ask AI'}
        </button>
      </div>
    </div>
  )
}

export function AiExplainer({
  assessmentId,
  findingId,
  severity,
  hasEvidence,
  context,
  compact = false,
}: {
  assessmentId: string | null
  /** Narrows the explanation to the finding the analyst selected. */
  findingId?: string | null
  severity: string | null
  hasEvidence: boolean
  /** The investigation summary, shown on request as the exact context used. */
  context?: string
  /** Traffic-drawer variant: tighter spacing, no thread chrome. */
  compact?: boolean
}) {
  const [result, setResult] = useState<AiAnalysisResult | null>(null)
  const [turns, setTurns] = useState<{ question: string; analysis: AiExplainResponse }[]>([])
  const [busy, setBusy] = useState(false)
  const [showContext, setShowContext] = useState(false)

  const hasFinding = Boolean(findingId)

  const ask = useCallback(
    async (question: string) => {
      if (!assessmentId) return
      setBusy(true)
      try {
        const history = turns.map((turn) => ({
          question: turn.question,
          answer: turn.analysis.answer.slice(0, 1200),
        }))
        const next = await analyzeWithAI({
          entityId: assessmentId,
          entityKind: hasFinding ? 'finding' : 'assessment',
          question,
          findingId: findingId ?? null,
          context,
          history,
        })
        setResult(next)
        if (next.analysis) {
          setTurns((current) => [...current, { question, analysis: next.analysis! }])
        }
      } finally {
        setBusy(false)
      }
    },
    [assessmentId, context, findingId, hasFinding, turns],
  )

  const explain = useCallback(() => {
    void ask(defaultQuestion({ hasFinding, severity, hasEvidence }))
  }, [ask, hasEvidence, hasFinding, severity])

  if (!assessmentId) {
    return (
      <p className="pw-faint-text">
        No assessment is selected, so there is nothing recorded to explain.
      </p>
    )
  }

  const analysis = result?.analysis

  return (
    <div className={compact ? 'pw-ai pw-ai-compact' : 'pw-ai'}>
      <div className="pw-ai-head">
        <h4 className="pw-finding-title">AI explanation</h4>
        <StatusPill status={result?.status ?? 'not_connected'} connected={Boolean(result?.connected)} />
      </div>

      <p className="pw-faint-text">
        Explains what the backend recorded for this assessment. It decides nothing: it cannot
        change a severity, a score, a finding, or the configuration, and it has no confidence of
        its own to report.
      </p>

      <div className="pw-ai-legend" aria-label="Where each kind of value comes from">
        <AiOriginChip origin="observed_fact" />
        <AiOriginChip origin="deterministic_assessment" />
        <AiOriginChip origin="ml_inference" />
        <AiOriginChip origin="ai_explanation" />
      </div>

      <div className="pw-ai-actions">
        <button type="button" className="pw-btn" onClick={explain} disabled={busy}>
          {busy ? <Spinner /> : 'Explain with AI'}
        </button>
        {context ? (
          <button
            type="button"
            className="pw-btn pw-btn-quiet"
            onClick={() => setShowContext((open) => !open)}
            aria-expanded={showContext}
          >
            {showContext ? 'Hide context' : 'Show context'}
          </button>
        ) : null}
      </div>

      {showContext && context ? (
        <pre className="code-block mt-2 overflow-x-auto whitespace-pre-wrap p-2.5">{context}</pre>
      ) : null}

      {/*
        A failure is one line and changes nothing else. The assessment, its
        findings and its evidence are untouched by this panel, so the analyst
        loses the explanation and nothing else.
      */}
      {result && !result.connected ? (
        <p className="pw-ai-failure">{result.reason}</p>
      ) : null}

      {analysis ? (
        <>
          <GuardNotice analysis={analysis} />
          <AnswerBlock analysis={analysis} />
          <AuthoritativeStrip analysis={analysis} />
          <MlStrip analysis={analysis} />
          {!compact ? (
            <Thread
              turns={turns.slice(0, -1)}
              onAsk={(question) => void ask(question)}
              busy={busy}
              disabled={false}
            />
          ) : null}
        </>
      ) : null}
    </div>
  )
}
