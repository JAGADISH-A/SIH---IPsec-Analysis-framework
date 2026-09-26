import { LogoMark } from '../common/Logo.tsx'

const PRINCIPLES = [
  {
    title: 'Frontend-only today',
    body: 'Every screen runs on typed mock data generated in-browser. No parsing, no captures, no backend calls.',
  },
  {
    title: 'Typed contracts',
    body: 'Packet, ProtocolDetails, SecurityFinding, AiMessage, PCAPUploadState and friends define the data layer in TypeScript — the UI never hardcodes mock shapes.',
  },
  {
    title: 'Swappable services',
    body: 'The mock packet / capture / AI / PCAP services implement the same interfaces a future REST or WebSocket backend will provide. Replacing them requires changing a single composition file.',
  },
]

const PROTOCOLS = ['IKEv2', 'ESP', 'AH', 'ESP-NULL', 'TCP', 'UDP', 'ICMP', 'DNS', 'TLS', 'HTTP']

export function AboutPage() {
  return (
    <div className="mx-auto h-full w-full max-w-4xl overflow-y-auto px-6 py-10 lg:px-8 lg:py-14">
      <div className="flex items-start gap-4">
        <div className="mt-1 flex size-11 shrink-0 items-center justify-center rounded-lg border border-edge bg-night-800">
          <LogoMark size={24} />
        </div>
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-mist">About IPsec Sentinel</h1>
          <p className="mt-1 text-sm text-mist-dim">
            A professional packet capture and IPsec security analysis tool with a
            modern web interaction model.
          </p>
        </div>
      </div>

      <section className="mt-10">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-mist-dim">Why it exists</h2>
        <p className="mt-3 max-w-3xl text-[15px] leading-relaxed text-mist-dim">
          Analysts spend most of their time understanding what an IPsec tunnel is
          really doing: which algorithms were negotiated, whether the SA is
          encrypted end-to-end, and where the posture breaks. IPsec Sentinel
          brings Wireshark-class packet interrogation into the browser — with
          automated security scoring and a context-aware assistant built in for
          the IPsec problem domain.
        </p>
      </section>

      <section className="mt-10">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-mist-dim">
          Architecture principles
        </h2>
        <div className="mt-3 grid gap-4 md:grid-cols-3">
          {PRINCIPLES.map(({ title, body }) => (
            <div key={title} className="panel p-4">
              <h3 className="text-sm font-semibold text-mist">{title}</h3>
              <p className="mt-1.5 text-[13px] leading-relaxed text-mist-dim">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="mt-10">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-mist-dim">
          Protocol coverage
        </h2>
        <div className="mt-3 flex flex-wrap gap-2">
          {PROTOCOLS.map((protocol) => (
            <span key={protocol} className="mono rounded-md border border-edge bg-night-800 px-2.5 py-1 text-xs text-mist-dim">
              {protocol}
            </span>
          ))}
        </div>
      </section>

      <section className="mt-10 border-t border-edge pt-6">
        <div className="flex flex-wrap items-center justify-between gap-2 text-[12px] text-mist-faint">
          <span>IPsec Sentinel — UI preview build</span>
          <span>Security reference: RFC 7296, RFC 8247, RFC 8242</span>
        </div>
      </section>
    </div>
  )
}