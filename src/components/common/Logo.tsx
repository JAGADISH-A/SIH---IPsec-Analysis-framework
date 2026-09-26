import { cx } from '../../lib/cx'

export interface LogoMarkProps {
  size?: number
  className?: string
}

/** Sentinel mark: raked shield with a rising signal arc. */
export function LogoMark({ size = 26, className }: LogoMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      aria-hidden
      className={cx('shrink-0', className)}
    >
      <path
        d="M16 2.5 4 6.9v8.2c0 7.1 4.9 11.8 12 14.4 7.1-2.6 12-7.3 12-14.4V6.9L16 2.5Z"
        fill="rgb(60 224 174 / 0.08)"
        stroke="rgb(60 224 174 / 0.9)"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M11 15a5.5 5.5 0 0 1 10 0"
        stroke="rgb(22 163 146 / 0.95)"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
      <path
        d="M8 19.5a9 9 0 0 1 16 0"
        stroke="rgb(60 224 174 / 0.75)"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="16" cy="15" r="2.3" fill="rgb(125 243 207)" />
    </svg>
  )
}

export interface LogoProps {
  markSize?: number
  className?: string
}

export function Logo({ markSize = 26, className }: LogoProps) {
  return (
    <span className={cx('inline-flex items-center gap-2.5', className)}>
      <LogoMark size={markSize} />
      <span className="flex items-baseline gap-1.5 leading-none">
        <span className="text-[14px] font-bold tracking-wide text-mist">IPsec</span>
        <span className="text-[14px] font-light tracking-[0.18em] text-accent-400">
          SENTINEL
        </span>
      </span>
    </span>
  )
}