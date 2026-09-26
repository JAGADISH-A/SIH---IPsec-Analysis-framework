import {
  Activity,
  BookOpen,
  Database,
  FlaskConical,
  Grid3x3,
  Home,
  LayoutDashboard,
  Radio,
  Settings,
  ShieldAlert,
  Siren,
  FileText,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  /** One-line explanation used in menus and the mobile sheet. */
  description: string
}

/**
 * The product's full route surface.
 *
 * Named `navData` rather than `navItems` so it can never collide with the
 * `NavItems.tsx` component on a case-insensitive filesystem.
 *
 * The bar is deliberately compact: six primary destinations stay visible and
 * everything else lives behind "More". Every entry is a real React Router path —
 * no anchor scrolling anywhere in the product.
 */
export const PRIMARY_NAV_ITEMS: NavItem[] = [
  { to: '/', label: 'Home', icon: Home, description: 'Platform overview' },
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, description: 'Security posture and KPIs' },
  { to: '/live-monitor', label: 'Live Monitor', icon: Radio, description: 'Real-time analysis feed' },
  { to: '/vpn-sessions', label: 'Sessions', icon: Grid3x3, description: 'Analysed VPN sessions' },
  { to: '/findings', label: 'Findings', icon: ShieldAlert, description: 'Evidence-backed findings register' },
  { to: '/reports', label: 'Reports', icon: FileText, description: 'Generate and export assessments' },
]

export const MORE_NAV_ITEMS: NavItem[] = [
  { to: '/traffic', label: 'Traffic Intelligence', icon: Activity, description: 'Volume and classification' },
  { to: '/threat-matrix', label: 'Threat Matrix', icon: Siren, description: 'Likelihood against impact' },
  { to: '/experiments', label: 'Experiments', icon: FlaskConical, description: 'Testbed runs and comparisons' },
  { to: '/dataset', label: 'Dataset', icon: Database, description: 'Capture archive and ingest' },
  { to: '/system-health', label: 'System Health', icon: Activity, description: 'Service status' },
  { to: '/documentation', label: 'Documentation', icon: BookOpen, description: 'Concepts, thresholds, methodology' },
  { to: '/settings', label: 'Settings', icon: Settings, description: 'Display and accessibility preferences' },
]

export const ALL_NAV_ITEMS: NavItem[] = [...PRIMARY_NAV_ITEMS, ...MORE_NAV_ITEMS]

/** Legacy destinations kept alive as redirects. */
export const LEGACY_ROUTES: { from: string; to: string }[] = [
  { from: '/live', to: '/live-monitor' },
  { from: '/analyzer', to: '/live-monitor?view=analyzer' },
  { from: '/pcap', to: '/dataset' },
  { from: '/about', to: '/documentation' },
]
