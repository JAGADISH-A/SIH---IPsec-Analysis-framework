import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, Filter, History, TriangleAlert, X } from 'lucide-react'
import { cx } from '../../lib/cx'
import { usePacketFilter } from '../../hooks/usePacketFilter'
import {
  FILTER_HISTORY_LIMIT,
  loadFilterHistory,
  saveFilterHistory,
  useSearchFilter,
} from '../../state/searchFilter.tsx'

/** Quick-pick expressions that demonstrate the supported grammar. */
const PRESETS: { label: string; expression: string }[] = [
  { label: 'ESP traffic', expression: 'esp' },
  { label: 'IKEv2 handshakes', expression: 'ikev2' },
  { label: 'ESP or AH', expression: 'esp || ah' },
  { label: 'One host', expression: 'ip.addr == 10.8.0.2' },
  { label: 'Host + ESP', expression: 'ip.addr == 10.8.0.2 && esp' },
  { label: 'High risk', expression: 'risk >= high' },
]

const SYNTAX_HINT =
  'Fields: ip.src · ip.dst · ip.addr · esp · ikev2 · ah · risk · len — combine with && and ||'

/**
 * The analyzer's display filter, in the spirit of a professional packet
 * analyzer's filter box.
 *
 * Collapsed by default: the magnifier in the top navigation (or Ctrl+K, or the
 * Filter button in the toolbar) expands it. The region animates between a
 * zero-height and an auto-height grid track, so the packet list below slides
 * up naturally when it closes and no placeholder is left behind.
 */
export function DisplayFilterBar() {
  const { query, hasQuery, setQuery, clear, isOpen, close } = useSearchFilter()
  const { validate } = usePacketFilter()
  const [draft, setDraft] = useState(query)
  const [history, setHistory] = useState<string[]>(loadFilterHistory)
  const [historyOpen, setHistoryOpen] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  const rootRef = useRef<HTMLDivElement>(null)

  // Keep the draft in step with externally applied filters (history, presets).
  // Adjusting during render rather than in an effect avoids a second paint.
  const [lastQuery, setLastQuery] = useState(query)
  if (query !== lastQuery) {
    setLastQuery(query)
    setDraft(query)
  }

  useEffect(() => {
    if (!isOpen) return
    const frame = requestAnimationFrame(() => inputRef.current?.focus())
    return () => cancelAnimationFrame(frame)
  }, [isOpen])

  useEffect(() => {
    if (!historyOpen) return
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setHistoryOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setHistoryOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [historyOpen])

  const expression = query.trim()
  const validation = useMemo(() => {
    if (!expression) return null
    return validate(expression)
  }, [expression, validate])

  const remember = useCallback((next: string) => {
    setHistory((prev) => {
      const updated = [next, ...prev.filter((item) => item !== next)].slice(0, FILTER_HISTORY_LIMIT)
      saveFilterHistory(updated)
      return updated
    })
  }, [])

  const apply = useCallback(
    (value?: string) => {
      const next = (value ?? draft).trim()
      setQuery(next)
      if (value !== undefined) setDraft(value)
      if (next) remember(next)
      setHistoryOpen(false)
    },
    [draft, remember, setQuery],
  )

  const handleClear = useCallback(() => {
    clear()
    setDraft('')
    setHistoryOpen(false)
  }, [clear])

  const error = validation && !validation.ok ? validation.error : null

  return (
    <div className="ws-collapse" data-open={isOpen ? 'true' : 'false'}>
      <div>
        <div className="ws-bar ws-bar-tight flex-wrap !py-1.5">
          <label htmlFor="display-filter" className="ws-bar-title flex items-center gap-1.5">
            <Filter className="size-3" aria-hidden />
            Display Filter
          </label>

          <div ref={rootRef} className="flex min-w-[240px] flex-[1_1_320px] items-center gap-1">
            <div className="relative min-w-0 flex-1">
              <input
                ref={inputRef}
                id="display-filter"
                type="text"
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') apply()
                  if (event.key === 'Escape') {
                    if (historyOpen) setHistoryOpen(false)
                    else close()
                  }
                }}
                spellCheck={false}
                autoComplete="off"
                placeholder="ip.addr == 10.1.1.1 && esp"
                aria-label="Display filter expression"
                aria-invalid={error ? true : undefined}
                className={cx('ws-input', error && '!border-ws-critical')}
              />
              {historyOpen ? (
                <div className="absolute left-0 top-full z-50 mt-1 w-72 overflow-hidden rounded-[3px] border border-ws-line-strong bg-ws-panel shadow-lg">
                  <div className="ws-section-head">Recent filters</div>
                  {history.length === 0 ? (
                    <div className="px-2.5 py-2.5 text-[11px] text-ws-faint">
                      Nothing yet — applied filters are remembered here.
                    </div>
                  ) : (
                    <ul className="max-h-56 overflow-auto">
                      {history.map((item) => (
                        <li key={item}>
                          <button
                            type="button"
                            onClick={() => apply(item)}
                            className="mono-tab w-full truncate px-2.5 py-1.5 text-left text-[11.5px] text-ws-dim transition-colors hover:bg-ws-hover hover:text-ws-text"
                            title={item}
                          >
                            {item}
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ) : null}
            </div>
            <button
              type="button"
              aria-label="Filter history"
              aria-expanded={historyOpen}
              title="Recent filters"
              onClick={() => setHistoryOpen((wasOpen) => !wasOpen)}
              className={cx('ws-btn ws-btn-icon', historyOpen && 'ws-btn-active')}
            >
              <History className="size-3.5" aria-hidden />
            </button>
          </div>

          <button type="button" className="ws-btn ws-btn-primary" onClick={() => apply()} disabled={!draft.trim()}>
            Apply
          </button>
          <button
            type="button"
            className="ws-btn"
            onClick={handleClear}
            disabled={!hasQuery && !draft.trim()}
            title="Clear the display filter"
          >
            <X className="size-3.5" aria-hidden />
            Clear
          </button>
          <button
            type="button"
            className="ws-btn ws-btn-ghost ws-btn-icon ml-auto"
            onClick={close}
            aria-label="Collapse display filter"
            title="Collapse (Esc)"
          >
            <ChevronDown className="size-3.5" aria-hidden />
          </button>
        </div>

        {/* Validation / active-filter feedback */}
        {error ? (
          <div className="ws-note" data-tone="error" role="alert">
            <TriangleAlert className="mt-px size-3.5 shrink-0" aria-hidden />
            <span className="min-w-0">
              {error} {SYNTAX_HINT}
            </span>
          </div>
        ) : expression ? (
          <div className="ws-note" data-tone="info">
            <Filter className="mt-px size-3.5 shrink-0" aria-hidden />
            <span className="min-w-0 truncate">
              Filtering on <span className="mono-tab font-semibold text-ws-text">{expression}</span>
            </span>
            <button type="button" className="ws-btn ws-btn-ghost ml-auto" onClick={handleClear}>
              Reset
            </button>
          </div>
        ) : null}

        {/* Quick presets */}
        <div className="ws-bar ws-bar-tight flex-wrap !border-b-0">
          <span className="ws-bar-title">Quick filters</span>
          {PRESETS.map((preset) => (
            <button
              key={preset.expression}
              type="button"
              onClick={() => apply(preset.expression)}
              title={preset.expression}
              className={cx(
                'ws-chip transition-colors hover:border-ws-accent hover:text-ws-accent-ink',
                expression === preset.expression && 'border-ws-accent bg-ws-accent-dim text-ws-accent-ink',
              )}
            >
              {preset.label}
            </button>
          ))}
          <span className="ml-auto hidden text-[10.5px] text-ws-faint lg:inline">{SYNTAX_HINT}</span>
        </div>
      </div>
    </div>
  )
}
