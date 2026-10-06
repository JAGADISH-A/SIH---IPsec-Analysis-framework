import { Link } from 'react-router-dom'

/**
 * A destination the backend does not support.
 *
 * The navigation keeps the item so the shape of the product is visible and the
 * gap is explicit, but the page states exactly what is missing rather than
 * rendering a placeholder that could be mistaken for a real view. Nothing here
 * is sampled, estimated or invented.
 */
const REASONS: Record<string, string[]> = {
  'report documents': [
    'No component of the analytics plane produces a report document — there is no executive or technical report endpoint to read.',
    'Assessments, findings, evidence and risk scores do exist, and each is reachable from its own page.',
    'Generating a document here would mean the browser composing a report the backend never wrote.',
  ],
  'threat matrix': [
    'No component of the analytics plane computes a threat matrix, likelihood/impact grid or heat map.',
    'The risk engine publishes a single additive score with severity bands and per-category totals — a score, not a matrix.',
    'Rendering one would require the frontend to invent axes and cells the backend never produced.',
  ],
}

export function NotAvailable({ kind }: { kind?: string }) {
  // `kind` names the missing capability and selects the specific reasons. A
  // route that fails to pass it must still render the honest "not available"
  // statement — a blank page here would be a worse lie than a generic one,
  // because it looks like a broken build rather than a missing capability.
  const reasons = (kind ? REASONS[kind] : undefined) ?? [
    'The analytics plane exposes no endpoint for this capability.',
    'Rendering one would require the frontend to invent data the backend never produced.',
  ]

  return (
    <div className="ls-page">
      <header className="ls-page-head">
        <h1 className="ls-title">{label(kind)}</h1>
        <p className="ls-subtitle">Not available</p>
        <span className="ls-state ls-state-na">not available</span>
      </header>

      <section className="ls-card">
        <div className="ls-card-body">
          <p className="ls-empty">
            The backend does not provide this capability, so there is nothing to display. No
            placeholder data is generated.
          </p>
          <ul className="ls-reasons">
            {reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
          <p>
            <Link className="ls-link" to="/">
              Back to Live Screening
            </Link>
          </p>
        </div>
      </section>
    </div>
  )
}

function label(kind: string | undefined): string {
  return (kind ?? 'This capability')
    .split(' ')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}