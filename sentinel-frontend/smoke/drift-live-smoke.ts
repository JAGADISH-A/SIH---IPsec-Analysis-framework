/**
 * Live drift smoke (not part of the shipped app).
 *
 * Runs the real Sentinel drift path against a running analytics API: it reads a
 * genuine per-assessment comparison over HTTP and renders it with the same
 * component the assessment detail page uses.
 *
 * The assertions are derived from the response at runtime rather than written
 * out in advance. That is the point: nothing here knows which variable drifted,
 * what the two values are, how severe it is, or which baseline it was compared
 * against, so this passes for any comparison the backend produces and fails if
 * the UI substitutes a remembered case for the actual data. It also fails if the
 * panel shows a drift verdict for an assessment that has no comparison.
 *
 *   E2E_ASSESSMENT_ID=... npm run smoke:drift-live
 *
 * With no id given, it picks the assessment the backend reports as drifted.
 */
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { AssessmentDriftBlock } from '@/components/packet/AssessmentDriftBlock'
import { getAssessmentDrift } from '@/api/analytics'
import type { AssessmentDriftResponse } from '@/types'

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

const ANALYTICS =
  process.env.VITE_ANALYTICS_API_URL ?? 'http://127.0.0.1:8081'

/** Resolve which assessment to read: the one asked for, or one the backend
 *  currently reports as drifted. */
async function resolveAssessmentId(): Promise<string> {
  const requested = process.env.E2E_ASSESSMENT_ID
  if (requested) return requested
  const summary = (await (await fetch(`${ANALYTICS}/api/v1/drift`)).json()) as {
    assessments?: Record<string, { status?: string }>
  }
  const drifted = Object.entries(summary.assessments ?? {})
    .filter(([, value]) => value.status === 'drift')
    .map(([id]) => id)
  if (drifted.length === 0) throw new Error('the backend reports no drifted assessment to read')
  return drifted.sort()[0]
}

const assessmentId = await resolveAssessmentId()
const drift: AssessmentDriftResponse = await getAssessmentDrift(assessmentId)

console.log(`reading drift for ${assessmentId}`)
console.log(`  status=${drift.status} detected=${drift.drift_detected} read_only=${drift.read_only}`)

const html = renderToStaticMarkup(createElement(AssessmentDriftBlock, { drift }))
const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ')

check(
  'the comparison comes from the read-only per-assessment endpoint',
  drift.read_only === true && drift.assessment_id === assessmentId,
)
check('the rendered page reflects the status the API reported', text.includes(drift.status))

if (drift.status === 'drift') {
  check('a reported drift reads as drift detected', /DRIFT DETECTED/.test(text))
  for (const field of drift.changed_fields) {
    const label = field.label ?? field.variable ?? 'field'
    check(`the changed variable is named: ${label}`, text.includes(label))
    check(
      `the baseline value is shown for ${field.variable}`,
      text.includes(String(field.baseline_value)),
    )
    check(
      `the current value is shown for ${field.variable}`,
      text.includes(String(field.current_value)),
    )
    if (field.finding_id) {
      check(`the API finding id is shown for ${field.variable}`, text.includes(String(field.finding_id)))
    }
    if (field.severity) {
      check(`the API severity is shown for ${field.variable}`, text.includes(String(field.severity)))
    }
  }
  const reported = (drift.risk?.findings ?? []).map((f) => f.finding_id).filter(Boolean)
  for (const finding of reported) {
    check(`the reported finding ${finding} is shown`, text.includes(String(finding)))
  }
  check(
    'the baseline it was compared against is shown',
    drift.baseline?.baseline_id ? text.includes(drift.baseline.baseline_id) : true,
  )
  check(
    'the run the observation came from is shown',
    drift.current?.run_id ? text.includes(drift.current.run_id) : true,
  )
} else if (drift.status === 'no_drift') {
  check('a clean comparison reads as no drift', /No drift detected/.test(text))
  check('a clean comparison shows no findings', !/RISK-DRIFT/.test(text))
} else {
  /* not_configured / indeterminate: an assessment that exists but was not
     compared must not be dressed up with a verdict. */
  check('an uncompared assessment is not shown as drift', !/DRIFT DETECTED/.test(text))
  check('an uncompared assessment is not shown as clean', !/No drift detected/.test(text))
  check(
    "the backend's reason is shown instead",
    drift.reason ? text.includes(drift.reason.slice(0, 40)) : true,
  )
}

console.log('')
if (failures) {
  console.error(`${failures} check(s) failed`)
  process.exit(1)
}
console.log('live drift smoke passed')
process.exit(0)