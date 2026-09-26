import { Link } from 'react-router-dom'
import { ArrowRight, Play, Radio, Upload } from 'lucide-react'
import { AnalyzerMock } from './AnalyzerMock.tsx'
import { Section } from './Section.tsx'

const FACTS: [string, string][] = [
  ['Protocols dissected', 'IKEv2 · ESP · AH'],
  ['Standards', 'RFC 7296 · 4303 · 4302'],
  ['Rule set', 'SENTINEL-2026.09'],
  ['Transport', 'Browser only — no backend'],
]

const PILLARS = ['Capture', 'Analyze', 'Understand', 'Secure'] as const

/**
 * Landing hero.
 *
 * Deliberately not a giant centred splash: the copy sits in a left column with
 * a technical fact table on the right, and the product itself — a real preview
 * of the analyzer workspace — runs full-bleed underneath so the first screen
 * shows software rather than a promise.
 */
export function Hero() {
  return (
    <Section grid innerClassName="pb-12 pt-12 lg:pb-16 lg:pt-16">
      <div className="grid items-start gap-x-12 gap-y-8 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full border border-edge-strong bg-night-850 px-3 py-1">
            <Radio className="size-3 text-accent-400" aria-hidden />
            <span className="label !text-mist-dim">IPsec traffic analysis</span>
          </span>

          <h1 className="mt-5 text-[42px] font-bold leading-[1.02] tracking-tight text-mist lg:text-[60px]">
            IPsec Sentinel
          </h1>

          <p className="mt-4 max-w-2xl text-[19px] font-medium leading-snug text-mist lg:text-[22px]">
            Intelligent IPsec Traffic Analysis
            <span className="text-mist-dim"> and Security Assessment</span>
          </p>

          <p className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-[14px] tracking-wide text-mist-faint">
            {PILLARS.map((pillar, index) => (
              <span key={pillar} className="flex items-center gap-2">
                <span className={index % 2 === 1 ? 'font-medium text-accent-400' : 'font-medium text-mist-dim'}>
                  {pillar}.
                </span>
              </span>
            ))}
          </p>

          <div className="mt-7 flex flex-wrap items-center gap-2.5">
            <Link to="/live-monitor" className="btn btn-primary h-10 px-5 text-[13px]">
              <Play className="size-4" aria-hidden />
              Start Live Capture
              <ArrowRight className="size-4" aria-hidden />
            </Link>
            <Link to="/dataset" className="btn h-10 px-5 text-[13px]">
              <Upload className="size-4" aria-hidden />
              Analyze PCAP
            </Link>
          </div>
        </div>

        {/* Technical fact table — reads like a spec sheet, not a stat card row. */}
        <dl className="self-stretch rounded-md border border-edge bg-night-900/70">
          {FACTS.map(([label, value], index) => (
            <div
              key={label}
              className={`flex flex-wrap items-baseline gap-x-4 gap-y-0.5 px-4 py-2.5 ${
                index > 0 ? 'border-t border-edge' : ''
              }`}
            >
              <dt className="w-full text-[10px] font-semibold uppercase tracking-[0.07em] text-mist-faint sm:w-[150px] sm:shrink-0">
                {label}
              </dt>
              <dd className="mono-tab text-[12.5px] text-mist-dim">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="mt-12">
        <AnalyzerMock />
      </div>
    </Section>
  )
}
