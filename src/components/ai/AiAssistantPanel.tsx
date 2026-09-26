import { useEffect, useRef, useState } from 'react'
import { Bot, RefreshCw, Send, Sparkles, WifiOff, X } from 'lucide-react'
import { cx } from '../../lib/cx'
import { packetIpsecSummary } from '../../lib/ipsecSummary'
import { useAiAssistant } from '../../state/aiAssistant.tsx'
import { usePacketSelection } from '../../state/packetSelection.tsx'
import { SeverityBadge } from '../common/SeverityBadge.tsx'
import { Spinner } from '../common/Spinner.tsx'
import { Skeleton } from '../common/Skeleton.tsx'
import type { AiContextSource } from '../../types/ai'

const SUGGESTIONS = [
  'Explain this packet',
  'Why is this marked medium risk?',
  'What is this SPI?',
  'What encryption is being used?',
  'Suggest a secure configuration',
]

function ContextSummary() {
  const { packet } = usePacketSelection()
  const { context } = useAiAssistant()

  if (!packet) {
    const label = context ? sourceLabel(context.source) : null
    return (
      <div className="border-b border-edge bg-night-800/40 px-4 py-2 text-[11px] text-mist-faint">
        {label ? (
          <>
            <span className="label">Context</span>
            <span className="ml-2">{label}</span>
          </>
        ) : (
          'No packet selected — select one in the Live Analyzer for packet-specific analysis.'
        )}
      </div>
    )
  }

  const summary = packetIpsecSummary(packet)
  const chips = [summary.encryption, summary.integrity, summary.spi ? `SPI ${summary.spi}` : undefined].filter(
    (chip) => chip !== undefined,
  ) as string[]

  return (
    <div className="border-b border-edge bg-night-800/40 px-4 py-2.5">
      <div className="label">Context</div>
      <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-[13px] font-semibold text-mist">Selected packet {packet.number}</span>
          <SeverityBadge severity={packet.risk ?? 'none'} />
        </div>
        <div className="flex min-w-0 flex-wrap items-start gap-x-1.5 gap-y-1">
          {summary.securityProtocols.map((protocol) => (
            <span
              key={protocol}
              className="mono inline-flex rounded border border-accent-500/30 bg-accent-dim px-1.5 py-px text-[10px] font-semibold text-accent-300"
            >
              {protocol}
            </span>
          ))}
          {chips.map((chip) => (
            <span key={chip} className="mono rounded border border-edge bg-night-900 px-1.5 py-px text-[10px] text-mist-dim">
              {chip}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

function sourceLabel(source: AiContextSource): string {
  switch (source) {
    case 'packet':
      return 'Selected packet'
    case 'analyzer':
      return 'Live Analyzer'
    case 'pcap':
      return 'PCAP analysis'
    case 'home':
      return 'Workspace'
  }
}

/**
 * Global AI assistant drawer. Slides in from the right over any page and
 * analyses the packet currently selected in the app (see packetSelection).
 * All replies are mocked locally — no external AI API is contacted.
 */
export function AiAssistantPanel() {
  const { open, closeAssistant, session, openError, retryOpen, isStreaming, sendMessage, sendSuggestion } =
    useAiAssistant()
  const [draft, setDraft] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight })
  }, [session, isStreaming])

  if (!open) return null

  const unavailable = openError !== null
  const opening = !session && !unavailable
  const messages = session?.messages ?? []
  const lastAssistant = [...messages].reverse().find((m) => m.role === 'assistant')
  const accessible = lastAssistant && lastAssistant.suggestions?.length && !isStreaming

  const submit = () => {
    const question = draft.trim()
    if (!question || isStreaming || !session) return
    setDraft('')
    void sendMessage(question)
  }

  return (
    <aside
      aria-label="AI Assistant"
      className="animate-panel-in fixed inset-y-14 right-0 z-40 flex w-full max-w-[400px] flex-col border-l border-edge bg-night-900 shadow-popover"
    >
      {/* Header */}
      <div className="flex items-center justify-between gap-3 border-b border-edge px-4 py-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="flex size-8 items-center justify-center rounded-md border border-accent-500/30 bg-accent-dim text-accent-300">
            <Bot className="size-4" aria-hidden />
          </span>
          <div className="min-w-0">
            <div className="text-[13px] font-semibold text-mist">AI Assistant</div>
            <div className="text-[11px] text-mist-faint">IPsec security copilot</div>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <button
            type="button"
            aria-label="Close AI Assistant"
            title="Close (Esc)"
            onClick={closeAssistant}
            className="btn btn-ghost btn-icon btn-sm"
          >
            <X className="size-4" aria-hidden />
          </button>
        </div>
      </div>

      <ContextSummary />

      {/* Message stream */}
      <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
        {opening ? (
          <OpeningSkeleton />
        ) : unavailable ? (
          <UnavailableState onRetry={retryOpen} />
        ) : messages.length === 0 ? (
          <EmptyThread />
        ) : (
          messages.map((msg) => (
            <MessageBlock
              key={msg.id}
              role={msg.role}
              content={msg.content}
              status={msg.status}
              error={msg.error}
            />
          ))
        )}

        {accessible ? (
          <div className="space-y-1.5 pt-1">
            <div className="label">Suggested</div>
            <div className="flex flex-wrap gap-1.5">
              {(lastAssistant.suggestions ?? []).map((suggestion) => (
                <button
                  key={suggestion}
                  type="button"
                  onClick={() => sendSuggestion(suggestion)}
                  className="btn btn-sm items-center gap-1.5 rounded-full text-accent-300"
                >
                  <Sparkles className="size-3" aria-hidden />
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        ) : null}
      </div>

      {/* Composer */}
      <div className="border-t border-edge px-4 py-3">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') submit()
            }}
            placeholder={isStreaming ? 'Analyzing…' : 'Ask about the selected packet…'}
            disabled={isStreaming || opening || unavailable}
            aria-label="Message the AI assistant"
            className="field"
            spellCheck={false}
          />
          <button
            type="button"
            onClick={submit}
            disabled={isStreaming || opening || unavailable || draft.trim().length === 0}
            className="btn btn-primary shrink-0"
          >
            {isStreaming ? <Spinner className="size-3.5" /> : <Send className="size-3.5" aria-hidden />}
            Send
          </button>
        </div>
      </div>

      {/* Footer */}
      <div className="flex items-center gap-1.5 border-t border-edge bg-night-950/70 px-4 py-2 text-[10px] text-mist-faint">
        <Sparkles className="size-3 shrink-0 text-accent-400/80" aria-hidden />
        AI uses the selected packet as context. Responses are simulated locally.
      </div>
    </aside>
  )
}

function OpeningSkeleton() {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Opening AI assistant">
      <div className="flex justify-end">
        <Skeleton className="h-8 w-24 rounded-lg" />
      </div>
      <div className="flex justify-start">
        <div className="flex max-w-[90%] items-center gap-2 rounded-lg rounded-bl-sm border border-edge bg-night-800 px-3 py-2.5">
          <Spinner className="size-3" />
          <span className="text-[13px] text-mist-dim">Starting session…</span>
        </div>
      </div>
      <div className="space-y-2 pl-8">
        <Skeleton className="h-3 w-2/3" />
        <Skeleton className="h-3 w-5/6" />
        <Skeleton className="h-3 w-3/4" />
      </div>
    </div>
  )
}

function UnavailableState({ onRetry }: { onRetry: () => void }) {
  return (
    <div
      className="flex flex-col items-center gap-3 px-2 py-8 text-center"
      role="alert"
    >
      <div className="flex size-12 items-center justify-center rounded-lg border border-danger/40 bg-danger-dim text-danger">
        <WifiOff className="size-5" aria-hidden />
      </div>
      <div>
        <div className="text-sm font-medium text-mist">Assistant unavailable</div>
        <div className="mx-auto mt-1 max-w-[260px] text-xs text-mist-faint">
          The AI service could not be started. Please try again.
        </div>
      </div>
      <button type="button" className="btn btn-primary" onClick={onRetry}>
        <RefreshCw className="size-4" aria-hidden />
        Retry
      </button>
    </div>
  )
}

function EmptyThread() {
  const { sendSuggestion } = useAiAssistant()
  return (
    <div className="flex flex-col items-center gap-3 py-8 text-center">
      <div className="flex size-12 items-center justify-center rounded-lg border border-edge bg-night-800 text-accent-300">
        <Bot className="size-5" aria-hidden />
      </div>
      <div>
        <div className="text-sm font-medium text-mist">Security analyst copilot</div>
        <div className="mt-1 text-xs text-mist-faint">
          Select a packet in the Live Analyzer, then ask about its crypto, SPI or risk.
        </div>
      </div>
      <div className="flex w-full max-w-[290px] flex-col gap-1.5">
        {SUGGESTIONS.map((suggestion) => (
          <button
            key={suggestion}
            type="button"
            onClick={() => sendSuggestion(suggestion)}
            className="btn justify-start text-left text-[13px]"
          >
            <Sparkles className="size-3.5 shrink-0 text-accent-400" aria-hidden />
            {suggestion}
          </button>
        ))}
      </div>
    </div>
  )
}

function MessageBlock({
  role,
  content,
  status,
  error,
}: {
  role: 'user' | 'assistant' | 'system'
  content: string
  status: 'pending' | 'streaming' | 'complete' | 'error'
  error?: string
}) {
  if (role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-lg rounded-br-sm bg-accent-500 px-3 py-2 text-[13px] text-[#04211a]">
          {content}
        </div>
      </div>
    )
  }

  return (
    <div className="flex justify-start">
      <div
        className={cx(
          'max-w-[90%] rounded-lg rounded-bl-sm border border-edge bg-night-800 px-3 py-2',
          status === 'error' && 'border-danger/50',
        )}
      >
        {status === 'streaming' && content.length === 0 ? (
          <div className="flex items-center gap-2 text-[13px] text-mist-dim">
            <Spinner className="size-3" />
            Analyzing…
          </div>
        ) : (
          <p className="whitespace-pre-wrap text-[13px] leading-relaxed text-mist">{content}</p>
        )}
        {status === 'error' && error ? (
          <p className="mt-1 text-xs text-danger">{error}</p>
        ) : null}
      </div>
    </div>
  )
}