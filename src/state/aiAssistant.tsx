import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { services } from '../services'
import { usePacketSelection } from './packetSelection.tsx'
import type { AiContextRef, AiMessage, AiSession } from '../types/ai'
import type { Timestamped } from '../types/common'

export interface AiAssistantValue {
  open: boolean
  isStreaming: boolean
  session: AiSession | null
  context: AiContextRef | undefined
  /** Set when the assistant service fails to initialize — surfaced as "unavailable". */
  openError: string | null
  openAssistant(context?: AiContextRef): void
  closeAssistant(): void
  toggleAssistant(): void
  attachContext(context?: AiContextRef): void
  retryOpen(): void
  sendMessage(question: string): Promise<void>
  sendSuggestion(suggestion: string): void
}

const AiAssistantContext = createContext<AiAssistantValue | null>(null)

let counter = 0
const uid = (): string => `ai-${(++counter).toString(36)}-${Date.now().toString(36)}`

function nowStamp(createdAt: number): Timestamped {
  return {
    timestamp: new Date(Date.now()).toISOString(),
    relativeTimeMs: Date.now() - createdAt,
  }
}

export function AiAssistantProvider({ children }: { children: ReactNode }) {
  const { packet: selectedPacket } = usePacketSelection()
  const [open, setOpen] = useState(false)
  const [isStreaming, setIsStreaming] = useState(false)
  const [session, setSession] = useState<AiSession | null>(null)
  const [context, setContext] = useState<AiContextRef | undefined>(undefined)
  const [openError, setOpenError] = useState<string | null>(null)

  const sessionRef = useRef<AiSession | null>(null)
  const contextRef = useRef<AiContextRef | undefined>(undefined)
  const sessionCreatedAt = useRef(Date.now())

  /** The packet context follows whatever the user has selected, live. */
  const selectedCtx: AiContextRef | undefined = selectedPacket
    ? { source: 'packet', packetId: selectedPacket.id }
    : undefined

  /** Effective context for messages: an explicit packet attachment tracks the
   * current selection; otherwise an explicit context wins; otherwise fall back
   * to the selected packet so the copilot always speaks about the click. */
  const effectiveContext: AiContextRef | undefined =
    context?.source === 'packet' ? selectedCtx : (context ?? selectedCtx)

  const ensureSession = useCallback(async (ctx?: AiContextRef) => {
    if (sessionRef.current) return
    sessionCreatedAt.current = Date.now()
    try {
      const created = await services.ai.startSession(ctx)
      sessionRef.current = created
      setSession(created)
      setOpenError(null)
    } catch {
      setOpenError('The AI assistant service is unavailable.')
    }
  }, [])

  const openAssistant = useCallback(
    (ctx?: AiContextRef) => {
      contextRef.current = ctx
      setContext(ctx)
      setOpenError(null)
      setOpen(true)
      void ensureSession(ctx)
    },
    [ensureSession],
  )

  const closeAssistant = useCallback(() => setOpen(false), [])

  const toggleAssistant = useCallback(() => {
    setOpen((wasOpen) => {
      if (!wasOpen) {
        setOpenError(null)
        void ensureSession(contextRef.current)
      }
      return !wasOpen
    })
  }, [ensureSession])

  const retryOpen = useCallback(() => {
    contextRef.current = undefined
    setContext(undefined)
    setOpenError(null)
    void ensureSession()
  }, [ensureSession])

  const attachContext = useCallback((ctx?: AiContextRef) => {
    contextRef.current = ctx
    setContext(ctx)
  }, [])

  const sendMessage = useCallback(
    async (question: string) => {
      if (isStreaming) return
      const base = sessionRef.current
      if (!base) return

      const createdAt = sessionCreatedAt.current
      const userMsg: AiMessage = {
        id: uid(),
        role: 'user',
        content: question,
        status: 'complete',
        ...nowStamp(createdAt),
      }
      const assistantMsg: AiMessage = {
        id: uid(),
        role: 'assistant',
        content: '',
        status: 'streaming',
        ...nowStamp(createdAt),
        context: effectiveContext,
      }

      sessionRef.current = {
        ...base,
        updatedAt: new Date().toISOString(),
        messages: [...base.messages, userMsg, assistantMsg],
      }
      setSession(sessionRef.current)
      setIsStreaming(true)
      try {
        const response = await services.ai.ask({
          sessionId: base.id,
          question,
          context: effectiveContext,
        })
        if (!sessionRef.current) return
        sessionRef.current = {
          ...sessionRef.current,
          updatedAt: new Date().toISOString(),
          messages: sessionRef.current.messages.map((m) =>
            m.id === assistantMsg.id
              ? { ...m, content: response.content, status: 'complete' as const, suggestions: response.suggestions }
              : m,
          ),
        }
        setSession(sessionRef.current)
      } catch {
        if (!sessionRef.current) return
        sessionRef.current = {
          ...sessionRef.current,
          messages: sessionRef.current.messages.map((m) =>
            m.id === assistantMsg.id
              ? { ...m, status: 'error' as const, error: 'The assistant service is unavailable.' }
              : m,
          ),
        }
        setSession(sessionRef.current)
      } finally {
        setIsStreaming(false)
      }
    },
    [isStreaming, effectiveContext],
  )

  const sendSuggestion = useCallback(
    (suggestion: string) => {
      void sendMessage(suggestion)
    },
    [sendMessage],
  )

  const value = useMemo<AiAssistantValue>(
    () => ({
      open,
      isStreaming,
      session,
      context,
      openError,
      openAssistant,
      closeAssistant,
      toggleAssistant,
      attachContext,
      retryOpen,
      sendMessage,
      sendSuggestion,
    }),
    [
      open,
      isStreaming,
      session,
      context,
      openError,
      openAssistant,
      closeAssistant,
      toggleAssistant,
      attachContext,
      retryOpen,
      sendMessage,
      sendSuggestion,
    ],
  )

  return <AiAssistantContext.Provider value={value}>{children}</AiAssistantContext.Provider>
}

export function useAiAssistant(): AiAssistantValue {
  const value = useContext(AiAssistantContext)
  if (!value) {
    throw new Error('useAiAssistant must be used within an AiAssistantProvider')
  }
  return value
}