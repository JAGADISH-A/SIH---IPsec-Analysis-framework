import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import './index.css'
import App from './App.tsx'
import { ServiceError } from './services/api/apiClient'
import { SearchFilterProvider } from './state/searchFilter.tsx'
import { PacketSelectionProvider } from './state/packetSelection.tsx'
import { CaptureProvider } from './state/capture.tsx'
import { AiAssistantProvider } from './state/aiAssistant.tsx'
import { SettingsProvider } from './state/settings.tsx'

/**
 * Query client defaults.
 *
 * Retries are skipped for errors the backend will not fix on a second attempt
 * (404, validation) so a missing record renders its empty state immediately
 * instead of flashing three loading states.
 */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 15_000,
      retry: (failureCount, error) => {
        if (error instanceof ServiceError && !error.retryable) return false
        return failureCount < 2
      },
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <SettingsProvider>
        <BrowserRouter>
          <SearchFilterProvider>
            <PacketSelectionProvider>
              <CaptureProvider>
                <AiAssistantProvider>
                  <App />
                </AiAssistantProvider>
              </CaptureProvider>
            </PacketSelectionProvider>
          </SearchFilterProvider>
        </BrowserRouter>
      </SettingsProvider>
    </QueryClientProvider>
  </StrictMode>,
)
