import type { Unsubscribe } from '../../types/common'
import type { Notification } from '../../types/notifications'
import type { NotificationService } from '../api/notificationService'
import { SimpleEmitter } from './tools'

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

function at(offsetMin: number): string {
  return new Date(Date.now() - offsetMin * 60_000).toISOString()
}

function item(
  id: string,
  kind: Notification['kind'],
  tone: Notification['tone'],
  title: string,
  body: string,
  minutesAgo: number,
  read = false,
): Notification {
  return {
    id,
    kind,
    tone,
    title,
    body,
    read,
    timestamp: at(minutesAgo),
    relativeTimeMs: minutesAgo * 60_000,
  }
}

const INITIAL: Notification[] = [
  item('n1', 'finding', 'danger', 'ESP-NULL detected', '3 ESP packets carry an ESP_NULL SA on 10.8.0.1 → 10.8.0.2.', 4),
  item('n2', 'finding', 'warning', 'Weak IKEv2 suite', 'IKE_SA_INIT proposed DES/HMAC-MD5 — blocked by RFC 8247.', 9),
  item('n3', 'capture', 'info', 'Capture loaded', 'cap-84x20v opened with filter esp.', 47, true),
  item('n4', 'system', 'success', 'Rules refreshed', 'Security rule set SENTINEL-2026.09 updated.', 140, true),
]

/** Canned notification feed simulating engine events (no backend yet). */
export class MockNotificationService implements NotificationService {
  private items: Notification[] = INITIAL
  private emitter = new SimpleEmitter<Notification[]>()

  async list(): Promise<Notification[]> {
    await delay(180)
    return [...this.items]
  }

  async unreadCount(): Promise<number> {
    return this.items.filter((n) => !n.read).length
  }

  async markRead(id: string): Promise<void> {
    this.items = this.items.map((n) => (n.id === id ? { ...n, read: true } : n))
    this.emitter.emit([...this.items])
  }

  async markAllRead(): Promise<void> {
    this.items = this.items.map((n) => (n.read ? n : { ...n, read: true }))
    this.emitter.emit([...this.items])
  }

  subscribe(listener: (items: Notification[]) => void): Unsubscribe {
    return this.emitter.subscribe(listener)
  }
}