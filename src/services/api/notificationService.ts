import type { Unsubscribe } from '../../types/common'
import type { Notification } from '../../types/notifications'

/**
 * Notifications feed for the top-bar bell. Mock today, replaceable with a
 * WebSocket/backend push channel without touching the UI.
 */
export interface NotificationService {
  list(): Promise<Notification[]>
  unreadCount(): Promise<number>
  markRead(id: string): Promise<void>
  markAllRead(): Promise<void>
  subscribe(listener: (items: Notification[]) => void): Unsubscribe
}