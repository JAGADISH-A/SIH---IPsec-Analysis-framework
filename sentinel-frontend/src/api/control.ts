import { CONTROL_API_URL } from '@/config'
import { request } from './client'
import type {
  ControlHealth,
  ExperimentConfigurations,
  ExperimentJob,
  ExperimentRequest,
} from '@/types'

/**
 * Server B — the mutating control plane (127.0.0.1:8000).
 *
 * Only experiment orchestration lives here. Every path is taken from the
 * existing FastAPI app in `controller/api.py`; nothing is invented.
 */

const BASE = CONTROL_API_URL

export function getControlHealth(signal?: AbortSignal): Promise<ControlHealth> {
  return request<ControlHealth>('control', BASE, '/health', {
    signal,
    title: 'Unable to reach the control API',
    fallback: 'The control service did not answer the health check.',
  })
}

export function getExperimentConfigurations(
  signal?: AbortSignal,
): Promise<ExperimentConfigurations> {
  return request<ExperimentConfigurations>(
    'control',
    BASE,
    '/experiments/configurations',
    {
      signal,
      title: 'Unable to load configurations',
      fallback: 'The control service did not return the available configurations.',
    },
  )
}

export function createExperiment(
  config: ExperimentRequest,
  signal?: AbortSignal,
): Promise<{ job_id: string; status: string }> {
  return request<{ job_id: string; status: string }>('control', BASE, '/experiments', {
    method: 'POST',
    body: config,
    signal,
    title: 'Unable to start the experiment',
    fallback: 'The control service did not accept the experiment request.',
  })
}

export function getExperiment(jobId: string, signal?: AbortSignal): Promise<ExperimentJob> {
  return request<ExperimentJob>('control', BASE, `/experiments/${encodeURIComponent(jobId)}`, {
    signal,
    title: 'Unable to read experiment status',
    fallback: 'The control service did not return a status for this job.',
  })
}
