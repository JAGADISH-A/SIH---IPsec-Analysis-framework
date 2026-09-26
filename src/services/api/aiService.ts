import type { AiSession, AiAskRequest, AiAskResponse, AiContextRef } from '../../types/ai'

/** AI assistant provider contract (mock today, LLM/backend proxy later). */
export interface AiService {
  startSession(context?: AiContextRef): Promise<AiSession>
  ask(request: AiAskRequest): Promise<AiAskResponse>
  session(id: string): Promise<AiSession | null>
}