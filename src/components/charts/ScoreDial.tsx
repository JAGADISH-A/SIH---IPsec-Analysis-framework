import { cx } from '../../lib/cx'
import { POSTURE_LABEL, type SecurityPosture } from '../../types/dashboard'

/**
 * Security score dial.
 *
 * The score is a platform assessment, not a measurement, so the dial always
 * states its method and shows "Unknown" rather than an empty arc when nothing
 * has been assessed.
 */
export function ScoreDial({ posture, size = 168, className }: { posture: SecurityPosture; size?: number; className?: string }) {
  const stroke = 12
  const radius = (size - stroke) / 2
  const circumference = 2 * Math.PI * radius
  const score = posture.score
  const fraction = score === null ? 0 : Math.min(1, Math.max(0, score / 100))
  const tone =
    score === null
      ? 'text-mist-faint'
      : score >= 60
        ? 'text-critical'
        : score >= 40
          ? 'text-warning'
          : score >= 22
            ? 'text-info'
            : 'text-success'

  return (
    <figure className={cx('flex flex-col items-center gap-2', className)} style={{ width: size }}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          role="img"
          aria-label={
            score === null
              ? 'Security score unknown: nothing has been assessed yet.'
              : `Security score ${score} out of 100, grade ${posture.grade}, posture ${POSTURE_LABEL[posture.posture]}.`
          }
        >
          <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            <circle cx={size / 2} cy={size / 2} r={radius} fill="none" strokeWidth={stroke} className="stroke-night-800" />
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              strokeWidth={stroke}
              className={tone}
              strokeLinecap="round"
              strokeDasharray={`${fraction * circumference} ${circumference}`}
            />
          </g>
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className={cx('font-mono text-3xl font-semibold leading-none', tone)}>
            {score === null ? '—' : score}
          </span>
          <span className="mt-1 text-[10px] uppercase tracking-wide text-mist-faint">
            {score === null ? 'Not assessed' : `Grade ${posture.grade}`}
          </span>
        </div>
      </div>
      <figcaption className="text-center text-[11px] text-mist-dim">
        {POSTURE_LABEL[posture.posture]} posture
        {score !== null ? (
          <span className="text-mist-faint"> · {posture.affectedSessions} session(s) affected</span>
        ) : null}
      </figcaption>
    </figure>
  )
}
