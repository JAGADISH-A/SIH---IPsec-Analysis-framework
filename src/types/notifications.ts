import type { Timestamped } from './common'

export type NotificationKind = 'finding' | 'capture' | 'system' | 'ai'

export type NotificationTone = 'info' | 'success' | 'warning' | 'danger'

export interface Notification extends Timestamped {
  id: string
  kind: NotificationKind
  title: string
  body: string
  tone: NotificationTone
  read: boolean
}