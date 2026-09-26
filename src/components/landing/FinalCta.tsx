import { Link } from 'react-router-dom'
import { ArrowRight, FileBarChart, Play, Upload } from 'lucide-react'
import { Section } from './Section.tsx'

const ACTIONS = [
  {
    to: '/live',
    icon: Play,
    title: 'Start Live Capture',
    body: 'Bind an interface and watch the stream dissect itself in real time.',
    primary: true,
  },
  {
    to: '/pcap',
    icon: Upload,
    title: 'Analyze a PCAP',
    body: 'Load an existing capture file and run the same analysis offline.',
    primary: false,
  },
  {
    to: '/findings',
    icon: FileBarChart,
    title: 'Read the findings',
    body: 'Start from the rule register instead of the raw packet stream.',
    primary: false,
  },
]

/** Closing call to action — a full-width band with three concrete entry points. */
export function FinalCta() {
  return (
    <Section grid>
      <div className="py-14 lg:py-16">
        <div className="grid gap-x-12 gap-y-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] lg:items-center">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="mono-tab text-[11px] font-bold text-accent-400">06</span>
              <span className="h-px w-6 bg-edge-strong" aria-hidden />
              <span className="label">Get started</span>
            </div>
            <h2 className="mt-3 text-[28px] font-semibold leading-[1.12] tracking-tight text-mist lg:text-[36px]">
              Put an IPsec tunnel under the microscope.
            </h2>
            <p className="mt-3 max-w-lg text-[14px] leading-relaxed text-mist-dim">
              Everything runs in your browser. The capture is simulated, the PCAP parser is stubbed and the assistant
              answers locally — so you can explore the whole workflow without installing anything.
            </p>
          </div>

          <ul className="grid gap-px overflow-hidden rounded-md border border-edge bg-edge">
            {ACTIONS.map(({ to, icon: Icon, title, body, primary }) => (
              <li key={to}>
                <Link
                  to={to}
                  className="flex items-center gap-3.5 bg-night-950 px-4 py-3.5 transition-colors hover:bg-night-900"
                >
                  <span className="flex size-9 shrink-0 items-center justify-center rounded border border-edge bg-night-900 text-accent-300">
                    <Icon className="size-4" aria-hidden />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-[13.5px] font-semibold text-mist">{title}</span>
                    <span className="mt-0.5 block text-[12px] leading-snug text-mist-dim">{body}</span>
                  </span>
                  <span
                    className={`flex shrink-0 items-center gap-1.5 rounded border px-2.5 py-1 text-[11.5px] font-semibold ${
                      primary
                        ? 'border-transparent bg-accent-500 text-night-950'
                        : 'border-edge-strong text-mist-dim'
                    }`}
                    aria-hidden
                  >
                    {primary ? 'Start' : 'Open'}
                    <ArrowRight className="size-3.5" />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Section>
  )
}
