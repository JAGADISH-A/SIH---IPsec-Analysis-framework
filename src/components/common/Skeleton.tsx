import { cx } from '../../lib/cx'

/** Shimmering placeholder block used while content is loading. */
export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('animate-pulse rounded-md bg-night-800', className)} aria-hidden />
}