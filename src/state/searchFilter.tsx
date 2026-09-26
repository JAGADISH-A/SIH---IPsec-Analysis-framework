import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export interface SearchFilterValue {
  /** Live filter string flowing into any consuming page (e.g. Live Analyzer). */
  query: string
  hasQuery: boolean
  setQuery(query: string): void
  clear(): void
  /**
   * Whether the display-filter region is expanded. Owned globally so the
   * magnifier in the top navigation and the filter bar inside the Live
   * Analyzer stay in lockstep — clicking either one toggles the same panel.
   */
  isOpen: boolean
  open(): void
  close(): void
  toggle(): void
}

const SearchFilterContext = createContext<SearchFilterValue | null>(null)

/** localStorage key holding recently applied display filters. */
export const FILTER_HISTORY_KEY = 'ipsec-sentinel:filter-history'
export const FILTER_HISTORY_LIMIT = 8

export function loadFilterHistory(): string[] {
  try {
    const raw = window.localStorage.getItem(FILTER_HISTORY_KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed.map(String).slice(0, FILTER_HISTORY_LIMIT) : []
  } catch {
    return []
  }
}

export function saveFilterHistory(expressions: string[]): void {
  try {
    window.localStorage.setItem(
      FILTER_HISTORY_KEY,
      JSON.stringify(expressions.slice(0, FILTER_HISTORY_LIMIT)),
    )
  } catch {
    // storage unavailable — history simply stays in memory for this session
  }
}

export function SearchFilterProvider({ children }: { children: ReactNode }) {
  const [query, setQuery] = useState('')
  const [isOpen, setIsOpen] = useState(false)

  const set = useCallback((next: string) => setQuery(next), [])
  const clear = useCallback(() => setQuery(''), [])
  const open = useCallback(() => setIsOpen(true), [])
  const close = useCallback(() => setIsOpen(false), [])
  const toggle = useCallback(() => setIsOpen((wasOpen) => !wasOpen), [])

  const value = useMemo<SearchFilterValue>(
    () => ({
      query,
      hasQuery: query.trim().length > 0,
      setQuery: set,
      clear,
      isOpen,
      open,
      close,
      toggle,
    }),
    [query, set, clear, isOpen, open, close, toggle],
  )

  return <SearchFilterContext.Provider value={value}>{children}</SearchFilterContext.Provider>
}

export function useSearchFilter(): SearchFilterValue {
  const value = useContext(SearchFilterContext)
  if (!value) {
    throw new Error('useSearchFilter must be used within a SearchFilterProvider')
  }
  return value
}
