import { useEffect, useRef, useState } from 'react'
import { Bell, CheckCheck, ShieldAlert, Radio, Bot, Wrench } from 'lucide-react'
import { cx } from '../../lib/cx'
import { useNotifications } from '../../hooks/useNotifications'
import type { Notification, NotificationKind } from '../../types/notifications'

const KIND_ICON: Record<NotificationKind, typeof Wrench> = {
  finding: ShieldAlert,
  capture: Radio,
  ai: Bot,
  system: Wrench,
}

const TONE_STYLE: Record<Notification['tone'], string> = {
  info: 'text-info',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
}

function timeAgo(iso: string): string {
  const minutes = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 60_000))
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

export function NotificationBell() {
  const { items, unread, markRead, markAllRead } = useNotifications()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onPointer = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    if (!open) return
    document.addEventListener('mousedown', onPointer)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-label={`Notifications${unread ? ` (${unread} unread)` : ''}`}
        aria-expanded={open}
        onClick={() => setOpen((wasOpen) => !wasOpen)}
        className={cx('btn btn-ghost btn-icon relative', open && 'btn-active')}
      >
        <Bell className="size-4" aria-hidden />
        {unread > 0 ? (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[9px] font-bold text-white">
            {unread}
          </span>
        ) : null}
      </button>

      {open ? (
        <div className="animate-drop-in absolute right-0 top-11 z-50 w-[340px] overflow-hidden rounded-lg border border-edge bg-night-800 shadow-popover">
          <div className="flex items-center justify-between border-b border-edge px-3 py-2.5">
            <span className="label">Notifications</span>
            {unread > 0 ? (
              <button
                type="button"
                onClick={() => markAllRead()}
                className="btn btn-ghost btn-sm text-info"
              >
                <CheckCheck className="size-3.5" aria-hidden />
                Mark all read
              </button>
            ) : null}
          </div>

          <div className="max-h-[360px] overflow-y-auto">
            {items.length === 0 ? (
              <p className="px-4 py-8 text-center text-xs text-mist-faint">No notifications yet.</p>
            ) : (
              items.map((item) => {
                const Icon = KIND_ICON[item.kind]
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => markRead(item.id)}
                    className={cx(
                      'flex w-full items-start gap-3 border-b border-edge/60 px-3 py-2.5 text-left transition-colors hover:bg-night-700',
                      !item.read && 'bg-accent-dim/30',
                    )}
                  >
                    <Icon
                      className={cx(
                        'mt-0.5 size-4 shrink-0',
                        TONE_STYLE[item.tone],
                      )}
                      aria-hidden
                    />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline justify-between gap-2">
                        <span className="truncate text-[13px] font-medium text-mist">
                          {item.title}
                        </span>
                        <span className="shrink-0 text-[10px] text-mist-faint">
                          {timeAgo(item.timestamp)}
                        </span>
                      </span>
                      <span className="mt-0.5 block truncate text-xs text-mist-dim">
                        {item.body}
                      </span>
                    </span>
                    {!item.read ? (
                      <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-accent-400" aria-hidden />
                    ) : null}
                  </button>
                )
              })
            )}
          </div>
        </div>
      ) : null}
    </div>
  )
}