import { useCallback, useEffect, useState } from 'react'
import { services } from '../services'
import type { NotificationService } from '../services/api/notificationService'
import type { Notification } from '../types/notifications'

/**
 * Notifications feed bound to the `NotificationService` interface (mock today,
 * WebSocket/backend push later — zero UI changes).
 */
export function useNotifications(notificationService: NotificationService = services.notifications) {
  const [items, setItems] = useState<Notification[]>([])

  useEffect(() => {
    void notificationService.list().then(setItems)
    return notificationService.subscribe(setItems)
  }, [notificationService])

  const markRead = useCallback(
    (id: string) => {
      void notificationService.markRead(id)
    },
    [notificationService],
  )

  const markAllRead = useCallback(() => {
    void notificationService.markAllRead()
  }, [notificationService])

  const unread = items.filter((item) => !item.read).length

  return { items, unread, markRead, markAllRead }
}