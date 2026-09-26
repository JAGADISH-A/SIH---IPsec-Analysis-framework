import type { HealthService } from '../api/healthService'
import type { SystemHealth } from '../../types/health'
import { mockDataset } from './mockData'
import { latency } from './mockSupport'

export class MockHealthService implements HealthService {
  async getHealth(): Promise<SystemHealth> {
    const health = mockDataset.systemHealth()
    return latency(
      {
        ...health,
        // The frontend knows it is talking to mocks; the page must say so.
        mockMode: true,
        checkedAt: new Date().toISOString(),
      },
      130,
    )
  }
}
