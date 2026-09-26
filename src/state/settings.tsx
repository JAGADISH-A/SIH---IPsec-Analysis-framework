import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

export type ThemeMode = 'light' | 'dark' | 'system'
export type TableDensity = 'compact' | 'default' | 'relaxed'
export type ConfidenceDisplay = 'always' | 'on-hover' | 'never'
export type DefaultDashboard = 'overview' | 'sessions' | 'findings'

/**
 * User preferences. Every value is cosmetic or behavioural — there is
 * deliberately NO field here for a token, key, password or VPN credential.
 * Nothing in this object is ever sent to a backend.
 */
export interface Settings {
  theme: ThemeMode
  reduceMotion: boolean
  highContrastFocus: boolean
  refreshIntervalMs: number
  timeZone: string
  defaultDashboard: DefaultDashboard
  confidenceDisplay: ConfidenceDisplay
  tableDensity: TableDensity
  notifications: {
    criticalFindings: boolean
    sessionStateChanges: boolean
    experimentStateChanges: boolean
    serviceDegradation: boolean
  }
}

export const DEFAULT_SETTINGS: Settings = {
  theme: 'system',
  reduceMotion: false,
  highContrastFocus: false,
  refreshIntervalMs: 30_000,
  timeZone: 'UTC',
  defaultDashboard: 'overview',
  confidenceDisplay: 'always',
  tableDensity: 'default',
  notifications: {
    criticalFindings: true,
    sessionStateChanges: true,
    experimentStateChanges: false,
    serviceDegradation: true,
  },
}

const STORAGE_KEY = 'ipsec-sentinel.settings.v1'

export const REFRESH_INTERVAL_OPTIONS = [
  { value: 5_000, label: '5 seconds' },
  { value: 15_000, label: '15 seconds' },
  { value: 30_000, label: '30 seconds' },
  { value: 60_000, label: '1 minute' },
  { value: 300_000, label: '5 minutes' },
] as const

export const TIME_ZONE_OPTIONS = [
  'UTC',
  'Europe/London',
  'Europe/Berlin',
  'Asia/Kolkata',
  'Asia/Singapore',
  'America/New_York',
  'America/Los_Angeles',
] as const

/**
 * Reads persisted preferences defensively: unknown keys are dropped, malformed
 * JSON is discarded, and every field is validated against its allowed set.
 * Preferences are cosmetic only — no credential can ever enter this store.
 */
function loadSettings(): Settings {
  if (typeof window === 'undefined') return DEFAULT_SETTINGS
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_SETTINGS
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null) return DEFAULT_SETTINGS
    const input = parsed as Partial<Settings>
    const notifications = (input.notifications ?? {}) as Partial<Settings['notifications']>
    return {
      theme:
        input.theme === 'light' || input.theme === 'dark' || input.theme === 'system'
          ? input.theme
          : DEFAULT_SETTINGS.theme,
      reduceMotion: Boolean(input.reduceMotion),
      highContrastFocus: Boolean(input.highContrastFocus),
      refreshIntervalMs: REFRESH_INTERVAL_OPTIONS.some(
        (option) => option.value === input.refreshIntervalMs,
      )
        ? (input.refreshIntervalMs as number)
        : DEFAULT_SETTINGS.refreshIntervalMs,
      timeZone: TIME_ZONE_OPTIONS.includes(input.timeZone as (typeof TIME_ZONE_OPTIONS)[number])
        ? (input.timeZone as string)
        : DEFAULT_SETTINGS.timeZone,
      defaultDashboard:
        input.defaultDashboard === 'sessions' ||
        input.defaultDashboard === 'findings' ||
        input.defaultDashboard === 'overview'
          ? input.defaultDashboard
          : DEFAULT_SETTINGS.defaultDashboard,
      confidenceDisplay:
        input.confidenceDisplay === 'on-hover' || input.confidenceDisplay === 'never'
          ? input.confidenceDisplay
          : DEFAULT_SETTINGS.confidenceDisplay,
      tableDensity:
        input.tableDensity === 'compact' || input.tableDensity === 'relaxed'
          ? input.tableDensity
          : DEFAULT_SETTINGS.tableDensity,
      notifications: {
        criticalFindings: notifications.criticalFindings ?? true,
        sessionStateChanges: notifications.sessionStateChanges ?? true,
        experimentStateChanges: notifications.experimentStateChanges ?? false,
        serviceDegradation: notifications.serviceDegradation ?? true,
      },
    }
  } catch {
    return DEFAULT_SETTINGS
  }
}

function prefersDark(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return true
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

export interface SettingsContextValue {
  settings: Settings
  /** Theme actually painted right now (system preference already resolved). */
  resolvedTheme: 'light' | 'dark'
  update<K extends keyof Settings>(key: K, value: Settings[K]): void
  updateNotification(key: keyof Settings['notifications'], value: boolean): void
  reset(): void
}

const SettingsContext = createContext<SettingsContextValue | null>(null)

/**
 * Application preferences provider.
 *
 * Owns three things: the persisted preference object, the resolved theme
 * applied to `<html data-theme>`, and the density/motion attributes the data
 * tables and CSS read.
 */
export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(loadSettings)
  const [systemDark, setSystemDark] = useState<boolean>(() => prefersDark())

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const query = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (event: MediaQueryListEvent) => setSystemDark(event.matches)
    query.addEventListener('change', onChange)
    return () => query.removeEventListener('change', onChange)
  }, [])

  const resolvedTheme: 'light' | 'dark' =
    settings.theme === 'system' ? (systemDark ? 'dark' : 'light') : settings.theme

  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('data-theme', resolvedTheme)
    root.setAttribute('data-density', settings.tableDensity)
    root.setAttribute('data-motion', settings.reduceMotion ? 'reduced' : 'full')
    root.setAttribute('data-focus', settings.highContrastFocus ? 'strong' : 'normal')
    root.style.colorScheme = resolvedTheme
  }, [resolvedTheme, settings.tableDensity, settings.reduceMotion, settings.highContrastFocus])

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
    } catch {
      // A storage failure (private mode, quota) must never break the app.
    }
  }, [settings])

  const update = useCallback<SettingsContextValue['update']>((key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }))
  }, [])

  const updateNotification = useCallback<SettingsContextValue['updateNotification']>((key, value) => {
    setSettings((prev) => ({ ...prev, notifications: { ...prev.notifications, [key]: value } }))
  }, [])

  const reset = useCallback(() => setSettings(DEFAULT_SETTINGS), [])

  const value = useMemo<SettingsContextValue>(
    () => ({ settings, resolvedTheme, update, updateNotification, reset }),
    [settings, resolvedTheme, update, updateNotification, reset],
  )

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

export function useSettings(): SettingsContextValue {
  const value = useContext(SettingsContext)
  if (!value) {
    throw new Error('useSettings must be used within a SettingsProvider')
  }
  return value
}

/** Convenience selector used by badges that honour the confidence display. */
export function useConfidenceDisplay(): ConfidenceDisplay {
  return useSettings().settings.confidenceDisplay
}
