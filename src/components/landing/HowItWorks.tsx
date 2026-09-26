import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import { Section, SectionHeading } from './Section.tsx'

interface Step {
  stage: string
  title: string
  body: string
  output: string
  to: string
  cta: string
}

const STEPS: Step[] = [
  {
    stage: 'Stage 01',
    title: 'Capture',
    body: 'Start a live capture on an interface, or load a PCAP/PCAPNG file for offline analysis. Frames stream into a ring buffer as they are observed.',
    output: 'packet stream',
    to: '/live',
    cta: 'Start capture',
  },
  {
    stage: 'Stage 02',
    title: 'Parse',
    body: 'Every frame is dissected layer by layer — Ethernet, IPv4, UDP, and the IPsec header itself — into a readable tree of named fields.',
    output: 'dissection tree',
    to: '/live',
    cta: 'View a packet',
  },
  {
    stage: 'Stage 03',
    title: 'Analyze',
    body: 'A rule engine scores each packet against IPsec hardening guidance: cipher strength, integrity, DH group, PFS, replay and SA lifetime.',
    output: 'risk score',
    to: '/findings',
    cta: 'Review findings',
  },
  {
    stage: 'Stage 04',
    title: 'Explain',
    body: 'Select any packet and ask the assistant what a field means, why a risk was raised, or which configuration to migrate towards.',
    output: 'contextual answer',
    to: '/live',
    cta: 'Open assistant',
  },
  {
    stage: 'Stage 05',
    title: 'Report',
    body: 'Findings are aggregated across the capture into a graded assessment you can hand to whoever owns the tunnel.',
    output: 'assessment report',
    to: '/reports',
    cta: 'Generate report',
  },
]

/** How it works — a five-stage pipeline rendered as a technical strip. */
export function HowItWorks() {
  return (
    <Section>
      <div className="py-14 lg:py-16">
        <SectionHeading
          index="02"
          eyebrow="Workflow"
          title="From capture to report in five stages"
          subtitle="The same pipeline whether the traffic is arriving live or coming out of a file — each stage hands a concrete artefact to the next."
        />

        <ol className="mt-10 grid gap-px overflow-hidden rounded-md border border-edge bg-edge md:grid-cols-2 xl:grid-cols-5">
          {STEPS.map((step, index) => (
            <li key={step.title} className="relative flex flex-col bg-night-950 p-4">
              <div className="flex items-baseline justify-between gap-2">
                <span className="mono-tab text-[10.5px] font-bold text-accent-400">{step.stage}</span>
                <span className="mono-tab text-[10px] text-mist-faint">
                  {String(index + 1).padStart(2, '0')}/05
                </span>
              </div>

              <h3 className="mt-2 text-[15px] font-semibold text-mist">{step.title}</h3>
              <p className="mt-1.5 flex-1 text-[12.5px] leading-relaxed text-mist-dim">{step.body}</p>

              <div className="mt-3 border-t border-edge pt-2.5">
                <div className="text-[9.5px] font-semibold uppercase tracking-[0.07em] text-mist-faint">Output</div>
                <div className="mono-tab mt-0.5 text-[11.5px] text-accent-300">{step.output}</div>
                <Link
                  to={step.to}
                  className="mt-2 inline-flex items-center gap-1 text-[11.5px] font-semibold text-mist-dim transition-colors hover:text-accent-400"
                >
                  {step.cta}
                  <ArrowRight className="size-3" aria-hidden />
                </Link>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </Section>
  )
}
