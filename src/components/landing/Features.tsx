import { Bot, FileBarChart, ListFilter, Network } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Section, SectionHeading } from './Section.tsx'

const CAPABILITIES = [
  {
    icon: ListFilter,
    title: 'Live packet capture',
    body: 'Bind an interface and watch frames arrive in a dense, monospaced stream with live counters for volume, IPsec share and risk.',
    to: '/live',
    link: 'Open the analyzer',
  },
  {
    icon: Network,
    title: 'Protocol dissection',
    body: 'IKEv2 exchanges, ESP and AH headers decoded down to SPI, sequence number, transforms and tunnel-mode inner flows.',
    to: '/live',
    link: 'Inspect a packet',
  },
  {
    icon: Bot,
    title: 'AI assistance',
    body: 'A single assistant drawer that reads the packet you have selected and explains its crypto, its SPI and its risk.',
    to: '/live',
    link: 'Ask the assistant',
  },
  {
    icon: FileBarChart,
    title: 'Findings and reporting',
    body: 'Findings are aggregated by rule across the whole capture and rolled into a graded security assessment.',
    to: '/reports',
    link: 'Open the report',
  },
]

/** Product capabilities — a dense two-column listing, not floating cards. */
export function Features() {
  return (
    <Section alt>
      <div className="py-14 lg:py-16">
        <SectionHeading
          index="01"
          eyebrow="Capabilities"
          title="What IPsec Sentinel does"
          subtitle="Four capabilities, one workspace. No configuration sprawl, no separate tools to learn — the capture, the dissection, the assistant and the report all read the same buffer."
        />

        <ul className="mt-10 grid gap-px overflow-hidden rounded-md border border-edge bg-edge md:grid-cols-2">
          {CAPABILITIES.map(({ icon: Icon, title, body, to, link }) => (
            <li key={title} className="group bg-night-950 p-5 transition-colors hover:bg-night-900">
              <div className="flex items-center gap-2.5">
                <span className="flex size-8 items-center justify-center rounded border border-edge bg-night-900 text-accent-300 transition-colors group-hover:border-accent-500/40">
                  <Icon className="size-4" aria-hidden />
                </span>
                <h3 className="text-[15px] font-semibold text-mist">{title}</h3>
              </div>
              <p className="mt-2.5 max-w-lg text-[13.5px] leading-relaxed text-mist-dim">{body}</p>
              <Link
                to={to}
                className="mt-3 inline-flex items-center gap-1.5 text-[12px] font-semibold text-accent-400 transition-colors hover:text-accent-300"
              >
                {link}
                <span aria-hidden>→</span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </Section>
  )
}
