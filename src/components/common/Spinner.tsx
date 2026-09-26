import { cx } from '../../lib/cx'

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      aria-label="Loading"
      role="status"
      className={cx(
        'inline-block size-4 animate-spin rounded-full border-2 border-current border-t-transparent opacity-70',
        className,
      )}
    />
  )
}