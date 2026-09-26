import { Link } from 'react-router-dom'
import { ArrowRight, ChevronsUpDown, Search, Table2 } from 'lucide-react'
import { AnalyzerMock } from './AnalyzerMock.tsx'
import { Section, SectionHeading } from './Section.tsx'

const DETAILS = [
  {
    icon: Table2,
    title: 'Rows stay dense',
    body: '23px rows, tabular numerals, hairline separators. Hundreds of frames stay scannable without the list feeling like a spreadsheet.',
  },
  {
    icon: ChevronsUpDown,
    title: 'Details expand in place',
    body: 'Selecting a packet opens its dissection directly beneath that row. The previous one collapses — no navigation, no modal, no scrolling away from the stream.',
  },
  {
    icon: Search,
    title: 'Filter like a field tool',
    body: 'The magnifier in the navigation bar reveals a display filter supporting ip.src, ip.dst, ip.addr, esp, ikev2, ah and risk, combined with && and ||.',
  },
]

/** Product preview — the analyzer at full width, with the interaction model called out. */
export function Preview() {
  return (
    <Section alt>
      <div className="py-14 lg:py-16">
        <SectionHeading
          index="03"
          eyebrow="Product preview"
          title="The Live Analyzer workspace"
          subtitle="Capture toolbar, display filter, packet table and inline detail — stacked in one full-height column, exactly as it behaves when you use it."
        />

        <div className="mt-10">
          <AnalyzerMock />
        </div>

        <div className="mt-6 grid gap-px overflow-hidden rounded-md border border-edge bg-edge lg:grid-cols-3">
          {DETAILS.map(({ icon: Icon, title, body }) => (
            <div key={title} className="flex gap-3 bg-night-950 p-4">
              <span className="flex size-8 shrink-0 items-center justify-center rounded border border-edge bg-night-900 text-accent-300">
                <Icon className="size-4" aria-hidden />
              </span>
              <div className="min-w-0">
                <div className="text-[13.5px] font-semibold text-mist">{title}</div>
                <p className="mt-1 text-[12.5px] leading-relaxed text-mist-dim">{body}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6">
          <Link to="/live-monitor?view=analyzer" className="btn btn-primary h-10 px-5 text-[13px]">
            Open the Live Analyzer
            <ArrowRight className="size-4" aria-hidden />
          </Link>
        </div>
      </div>
    </Section>
  )
}
