import { useCallback, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { cx } from '../../lib/cx'
import { useSearchFilter } from '../../state/searchFilter.tsx'

/**
 * The magnifier in the top navigation. Collapsed it is a single icon; clicking
 * it expands the analyzer's Display Filter region (and, when you are on another
 * route, takes you to the Live Analyzer with the region already open).
 *
 * Clicking it again collapses the region, and the analyzer reflows upward. The
 * icon carries a dot while a filter is applied so the active state stays
 * visible even when the panel is closed.
 */
export function FilterToggle() {
  const { hasQuery, isOpen, open, close, toggle } = useSearchFilter()
  const navigate = useNavigate()
  const location = useLocation()
  const onAnalyzer = location.pathname === '/live' || location.pathname === '/analyzer'

  const onClick = useCallback(() => {
    if (isOpen) {
      close()
      return
    }
    if (!onAnalyzer) {
      navigate('/live')
      open()
      return
    }
    toggle()
  }, [isOpen, onAnalyzer, navigate, open, close, toggle])

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        onClick()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClick])

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={isOpen ? 'Collapse display filter' : 'Open display filter'}
      aria-expanded={isOpen}
      title={isOpen ? 'Collapse display filter' : 'Display filter (Ctrl+K)'}
      className={cx('nav-item relative size-8 justify-center px-0', isOpen && 'nav-item-active')}
    >
      <Search className="size-4" aria-hidden />
      {hasQuery ? (
        <span
          aria-hidden
          className="absolute right-1 top-1 size-1.5 rounded-full bg-accent-400 ring-2 ring-night-900"
        />
      ) : null}
    </button>
  )
}
