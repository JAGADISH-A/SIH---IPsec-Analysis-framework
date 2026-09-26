import type { Timestamped } from './common'

export type AiRole = 'user' | 'assistant' | 'system'

export type AiMessageStatus = 'pending' | 'streaming' | 'complete' | 'error'

/** Where the assistant was opened from, so it can reference context. */
export type AiContextSource = 'home' | 'analyzer' | 'pcap' | 'packet'

/** Context snapshot attached to a message / session. */
export interface AiContextRef {
  source: AiContextSource
  packetId?: string
  captureId?: string
  pcapName?: string
}

export interface AiMessage extends Timestamped {
  id: string
  role: AiRole
  content: string
  status: AiMessageStatus
  context?: AiContextRef
  /** Optional structured suggestions rendered by the UI. */
  suggestions?: string[]
  error?: string
}

export interface AiSession {
  id: string
  title: string
  createdAt: string
  updatedAt: string
  messages: AiMessage[]
  context?: AiContextRef
}

/** Request contract between the assistant UI and any backend provider. */
export interface AiAskRequest {
  sessionId: string
  question: string
  context?: AiContextRef
}

export type AiAskResponse = Pick<AiMessage, 'content' | 'suggestions'>

/** A question/answer pair that mock data can replay deterministically. */
export interface AiCannedResponse {
  match: RegExp
  answer: string
  suggestions: string[]
}