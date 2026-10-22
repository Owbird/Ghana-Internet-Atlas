'use client'

import { useEffect, useState } from 'react'
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clock3,
  Database,
  ExternalLink,
  Globe2,
  Menu,
  Network,
  RefreshCw,
  Search,
  ShieldCheck,
  X,
} from 'lucide-react'

import type { Atlas, Measurement, Operator } from '@/lib/atlas'
import { NationalSummary, ExposureBreakdown } from '@/components/atlas-overview'

type Host = { ip: string; hostname: string; ports: number[]; tags: string[]; software: string; prefix: string; fetchedAt: string }
type HostPage = { asn: string; hosts: Host[]; totalHosts: number; page: number; pageSize: number; totalPages: number; hasPrevious: boolean; hasNext: boolean }
const emptyOperator: Operator = { name: 'No operator selected', asn: '', id: '', color: '', prefixes: [], announced: 0, scanned: 0, records: 0, exposed: 0, ports: {}, tags: {} }
const number = (value: number) => value.toLocaleString('en-US')

function StatusPill({ children, tone = 'green' }: { children: React.ReactNode; tone?: 'green' | 'gray' | 'amber' }) {
  return <span className={`status-pill ${tone}`}>{children}</span>
}

export default function AtlasDashboard({ initialData, initialError = '' }: { initialData: Atlas | null; initialError?: string }) {
  const [data, setData] = useState<Atlas | null>(initialData)
  const [operatorId, setOperatorId] = useState('')
  useEffect(() => {
    if (operatorId) document.getElementById('operator-panel')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [operatorId])
  const [search, setSearch] = useState('')
  const [operatorSearch, setOperatorSearch] = useState('')
  const [hostSearch, setHostSearch] = useState('')
  const [selectedHost, setSelectedHost] = useState<Host | null>(null)
  const [page, setPage] = useState(1)
  const [refresh, setRefresh] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(initialError)
  useEffect(() => {
    if (refresh === 0) return
    const controller = new AbortController()
    setLoading(true)
    setError('')
    const timer = setTimeout(async () => {
      try {
        const response = await fetch('/api/atlas', { signal: controller.signal, cache: 'no-store' })
        const result = await response.json()
        if (!response.ok) throw new Error(result.error || 'Unable to load data')
        setData(result)
      } catch (e) { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Unable to load data') }
      finally { if (!controller.signal.aborted) setLoading(false) }
    }, 250)
    return () => { clearTimeout(timer); controller.abort() }
  }, [refresh])
  const operators = data?.operators || []
  const operator = operators.find(o => o.id === operatorId) || emptyOperator
  const [hostData, setHostData] = useState<HostPage | null>(null)
  const [hostsLoading, setHostsLoading] = useState(false)
  const [hostsError, setHostsError] = useState('')
  const query = hostSearch || search
  const [loadedKey, setLoadedKey] = useState('')
  const hostKey = `${operator.id}:${query}:${page}:${refresh}`
  useEffect(() => {
    setHostData(null)
    setSelectedHost(null)
    setHostsError('')
    if (!operator.id) { setHostsLoading(false); return }
    const controller = new AbortController()
    setHostsLoading(true)
    const timer = setTimeout(async () => {
      try {
        const params = new URLSearchParams({ asn: operator.id, search: query, page: String(page) })
        const response = await fetch(`/api/atlas/hosts?${params}`, { signal: controller.signal, cache: 'no-store' })
        const result = await response.json()
        if (!response.ok) throw new Error(result.error || 'Unable to load hosts')
        if (!controller.signal.aborted) { setHostData(result); setLoadedKey(hostKey) }
      } catch (e) { if (!controller.signal.aborted) setHostsError(e instanceof Error ? e.message : 'Unable to load hosts') }
      finally { if (!controller.signal.aborted) setHostsLoading(false) }
    }, 250)
    return () => { clearTimeout(timer); controller.abort() }
  }, [operator.id, query, page, refresh, hostKey])
  const [apnic, setApnic] = useState<{ key: string; measurement: Measurement | null; error: string } | null>(null)
  const apnicKey = `${operator.id}:${refresh}`
  useEffect(() => {
    setApnic(null)
    if (!operator.id) return
    const controller = new AbortController()
    async function loadMeasurement() {
      try {
        const response = await fetch(`/api/atlas/apnic?${new URLSearchParams({ asn: operator.id })}`, { signal: controller.signal, cache: 'no-store' })
        const result = await response.json()
        if (!response.ok) throw new Error(result.error || 'Unable to load APNIC data')
        if (!controller.signal.aborted) setApnic({ key: apnicKey, measurement: result.measurement, error: '' })
      } catch (e) {
        if (!controller.signal.aborted) setApnic({ key: apnicKey, measurement: null, error: e instanceof Error ? e.message : 'Unable to load APNIC data' })
      }
    }
    void loadMeasurement()
    return () => controller.abort()
  }, [operator.id, refresh, apnicKey])
  const currentApnic = apnic?.key === apnicKey ? apnic : null
  const measurement = currentApnic?.measurement
  const apnicStatus = !operator.id ? 'Select an operator' : !currentApnic ? 'Loading…' : currentApnic.error ? 'Unavailable' : measurement?.measured_on || 'Not imported'
  const currentHosts = loadedKey === hostKey ? hostData : null
  const visibleHosts = currentHosts?.hosts || []
  const totalHosts = currentHosts?.totalHosts || 0
  const tableLoading = !!operator.id && (hostsLoading || (!hostsError && !currentHosts))
  const noRecords = !!operator.id && !!currentHosts && totalHosts === 0 && !query && !hostsError


  return <main className="atlas-shell">
    <header className="topbar">
      <div className="brand"><div className="brand-mark"><Globe2 /></div><div><b>Ghana Internet Atlas</b><span>Network observatory</span></div></div>
      <div className="top-actions"><div className="global-search"><Search /><input aria-label="Global search" placeholder="Search IP, hostname, tag" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1) }} />{search && <X onClick={() => { setSearch(''); setPage(1) }} />}</div><button className="icon-button mobile-menu" aria-label="Open menu"><Menu /></button><div className="live-dot"><span />{loading ? 'Loading' : error ? 'Unavailable' : 'Connected'}</div></div>
    </header>

    <section className="content">
      <div className="page-heading"><div><p className="eyebrow">OPERATIONS</p><h1>Internet visibility</h1><p className="subheading">A measured view of Ghana&apos;s public internet surface.</p></div><button className="refresh-button" disabled={loading} onClick={() => setRefresh(v => v + 1)}><RefreshCw /> Refresh data</button></div>
      
      {error && <p role="alert">{error}</p>}
      {!loading && !error && !operators.length && <p>No active collection run or IPv4 operators found.</p>}
      <NationalSummary data={data} />
        <div className="workspace" id="operator-panel">
          <aside className="operator-sidebar"><div className="section-label"><span>Operators</span><span className="count">{operators.length}</span></div><div className="operator-search"><Search /><input aria-label="Search operators" placeholder="Filter operators" value={operatorSearch} onChange={e => setOperatorSearch(e.target.value)} /></div><div className="operator-list">{operators.filter(o => `${o.name} ${o.asn}`.toLowerCase().includes(operatorSearch.toLowerCase())).map((item) => <button key={item.id} className={`operator-row ${operator.id === item.id ? 'selected' : ''}`} onClick={() => { setOperatorId(item.id); setSelectedHost(null); setPage(1) }}><span className={`operator-logo ${item.color}`}>{item.name.slice(0, 1)}</span><span className="operator-copy"><b>{item.name}</b><small>{item.asn}</small></span></button>)}</div><div className="sidebar-note"><CircleHelp /><span>Host records describe addresses, not distinct devices or subscribers.</span></div></aside>
          <section className="operator-main"><div className="operator-header"><div><p className="eyebrow">SELECTED OPERATOR</p><h2>{operator.name} <span>{operator.asn}</span></h2></div><StatusPill><span className="tiny-dot" /> {loading ? 'Loading' : error ? 'Unavailable' : 'Database snapshot'}</StatusPill></div>
            {currentApnic?.error && <p role="alert">{currentApnic.error}</p>}{operator.id && currentApnic && !currentApnic.error && !measurement ? <section className="no-records" aria-labelledby="no-measurement-title"><Activity aria-hidden="true" /><h3 id="no-measurement-title">No measurement yet</h3><p>No APNIC measurement has been imported for {operator.asn} yet.</p></section> : <div className="insight-grid"><div className="insight-card"><div className="card-heading"><span>APNIC user reach</span><ExternalLink /></div><div className="insight-values"><div><strong>{measurement ? number(Number(measurement.estimated_users)) : '—'}</strong><small>estimated Ghana users</small></div><div><strong>{measurement ? `${measurement.country_percent}%` : '—'}</strong><small>estimated share of users</small></div></div><div className="card-foot"><Clock3 /> Measurement: {apnicStatus}</div></div></div>}
            <ExposureBreakdown operator={operator} />
            {hostsError && <p role="alert">{hostsError}</p>}
            {noRecords ? <section className="no-records" aria-labelledby="no-records-title"><Database aria-hidden="true" /><h3 id="no-records-title">No record yet</h3><p>No host records have been collected for {operator.asn} yet.</p><button className="refresh-button" onClick={() => setRefresh(v => v + 1)}><RefreshCw /> Refresh data</button></section> : <div className="table-card" aria-busy={tableLoading}><div className="table-toolbar"><div className="tabs"><span className="tab-active">Hosts</span></div><div className="table-tools"><div className="table-search"><Search /><input aria-label="Filter hosts" disabled={!operator.id} placeholder="Filter hosts" value={hostSearch} onChange={(e) => { setHostSearch(e.target.value); setPage(1) }} /></div></div></div><div className="table-caption"><span>{totalHosts} hosts with records</span><span className="redaction-note"><ShieldCheck /> Vulnerability identifiers redacted</span></div><div className="table-wrap"><table><thead><tr><th>IP address</th><th>Hostname</th><th>Reported ports</th><th>Tags</th><th aria-label="Actions" /></tr></thead><tbody>{!visibleHosts.length && <tr><td colSpan={5}>{!operator.id ? 'Select an operator to load hosts' : tableLoading ? 'Loading records…' : hostsError ? 'Unable to load records' : 'No matching records'}</td></tr>}{visibleHosts.map((host) => <tr key={host.ip} onClick={() => setSelectedHost(host)}><td><b className="mono">{host.ip}</b><StatusPill tone="gray">record</StatusPill></td><td>{host.hostname}</td><td><div className="port-list">{host.ports.map((port) => <span key={port}>{port}</span>)}</div></td><td><div className="tag-list">{host.tags.map((tag) => <span key={tag}>{tag}</span>)}</div></td><td><ChevronRight className="row-arrow" /></td></tr>)}</tbody></table></div><div className="pagination"><span>Showing {currentHosts && totalHosts ? (currentHosts.page - 1) * currentHosts.pageSize + 1 : 0}–{currentHosts ? Math.min(currentHosts.page * currentHosts.pageSize, totalHosts) : 0} of {totalHosts}</span><div><button aria-label="Previous page" disabled={tableLoading || !currentHosts?.hasPrevious} onClick={() => setPage((currentHosts?.page || 1) - 1)}><ChevronLeft /></button><button aria-label="Next page" disabled={tableLoading || !currentHosts?.hasNext} onClick={() => setPage((currentHosts?.page || 1) + 1)}><ChevronRight /></button></div></div></div>}
          </section>
        </div>
    </section>
    {selectedHost && <div className="detail-overlay" onClick={() => setSelectedHost(null)}><aside className="detail-panel" onClick={(e) => e.stopPropagation()}><div className="detail-header"><div><p className="eyebrow">HOST RECORD</p><h2 className="mono">{selectedHost.ip}</h2></div><button className="icon-button" aria-label="Close details" onClick={() => setSelectedHost(null)}><X /></button></div><StatusPill>Successful record</StatusPill><dl className="detail-list"><div><dt>Hostname</dt><dd>{selectedHost.hostname}</dd></div><div><dt>ASN / prefix</dt><dd>{operator.asn}<br /><span className="muted">{selectedHost.prefix}</span></dd></div><div><dt>Software fingerprint</dt><dd>{selectedHost.software}</dd></div><div><dt>Reported ports</dt><dd><div className="port-list">{selectedHost.ports.map((port) => <span key={port}>{port}</span>)}</div></dd></div><div><dt>Tags</dt><dd><div className="tag-list">{selectedHost.tags.map((tag) => <span key={tag}>{tag}</span>)}</div></dd></div><div><dt>Last lookup</dt><dd>{new Date(selectedHost.fetchedAt).toLocaleString()}</dd></div></dl><div className="detail-callout"><ShieldCheck /><span>Source-reported vulnerability associations are aggregated and redacted. They do not establish exploitability.</span></div></aside></div>}
  </main>
}

