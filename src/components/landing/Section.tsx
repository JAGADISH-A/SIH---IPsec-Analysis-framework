import type { ReactNode } from 'react'
import { cx } from '../../lib/cx'

/**
 * Full-bleed band used by every landing section.
 *
 * The band spans the whole viewport and is separated by a single hairline; the
 * content inside uses a wide container so nothing floats in the middle of a
 * large empty field. A faint 32px grid sits behind the hero and the closing
 * call to action for a technical, instrument-panel feel.
 */
export function Section({
  children,
  className,
  alt = false,
  grid = false,
  id,
  innerClassName,
}: {
  children: ReactNode
  className?: string
  /** Sunken band — used to separate adjacent sections. */
  alt?: boolean
  /** Hairline grid backdrop. */
  grid?: boolean
  id?: string
  innerClassName?: string
}) {
  return (
    <section
      id={id}
      className={cx('relative w-full border-t border-edge', alt && 'bg-night-900/60', className)}
    >
      {grid ? <GridBackdrop /> : null}
      <div className={cx('relative mx-auto w-full max-w-[1560px] px-5 lg:px-8', innerClassName)}>
        {children}
      </div>
    </section>
  )
}

/** A document-style heading: title block on the left, supporting copy right. */
export function SectionHeading({
  index,
  eyebrow,
  title,
  subtitle,
  className,
}: {
  index: string
  eyebrow: string
  title: string
  subtitle?: string
  className?: string
}) {
  return (
    <div className={cx('grid gap-x-10 gap-y-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]', className)}>
      <div>
        <div className="flex items-center gap-2.5">
          <span className="mono-tab text-[11px] font-bold text-accent-400">{index}</span>
          <span className="h-px w-6 bg-edge-strong" aria-hidden />
          <span className="label">{eyebrow}</span>
        </div>
        <h2 className="mt-3 text-[26px] font-semibold leading-[1.15] tracking-tight text-mist lg:text-[32px]">
          {title}
        </h2>
      </div>
      {subtitle ? (
        <p className="max-w-xl self-end text-[14px] leading-relaxed text-mist-dim lg:pb-1">{subtitle}</p>
      ) : null}
    </div>
  )
}

function GridBackdrop() {
  return (
    <div
      aria-hidden
      className="pointer-events-none absolute inset-0"
      style={{
        backgroundImage:
          'linear-gradient(to right, rgb(31 41 61 / 0.55) 1px, transparent 1px), linear-gradient(to bottom, rgb(31 41 61 / 0.55) 1px, transparent 1px)',
        backgroundSize: '48px 48px',
        maskImage: 'radial-gradient(120% 90% at 50% 0%, black, transparent 78%)',
        WebkitMaskImage: 'radial-gradient(120% 90% at 50% 0%, black, transparent 78%)',
      }}
    />
  )
}
