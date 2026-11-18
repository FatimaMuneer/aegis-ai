import { useCallback, useEffect, useMemo, useState } from 'react'
import ReactECharts from 'echarts-for-react'
import {
  Activity, AlertOctagon, AlertTriangle,
  Bot, Check, CheckCircle2, ChevronDown, ChevronRight, CircleHelp,
  Clock3, FileCheck2, Fingerprint, Gauge, LayoutDashboard,
  LockKeyhole, Menu, RefreshCw, Search, Send,
  Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles,
  Terminal, X, Zap
} from 'lucide-react'
import './App.css'

type AnyRecord = Record<string, any>

type Stats = {
  total?: number
  verdicts?: Record<string, number>
  kinds?: Record<string, number>
  risks?: Record<string, number>
  agents?: Record<string, number>
  log_intact?: boolean
  integrity_message?: string
}

type ApiList = {
  count?: number
  entries?: AnyRecord[]
}

type AgentStatusResponse = {
  agents?: AnyRecord[]
  connected_count?: number
  total_agents?: number
  updated_at?: string
}

type ChatMessage = {
  role: 'user' | 'assistant'
  text: string
}

const API = '/api'

const number = (value: unknown) =>
  typeof value === 'number' && Number.isFinite(value) ? value : 0

const pretty = (value: unknown) =>
  String(value ?? 'Unknown').replaceAll('_', ' ').toLowerCase()
    .replace(/\b\w/g, (letter) => letter.toUpperCase())

const getValue = (item: AnyRecord, keys: string[], fallback = '—') => {
  for (const key of keys) {
    if (item?.[key] !== undefined && item?.[key] !== null && item[key] !== '') {
      return String(item[key])
    }
  }
  return fallback
}

const verdictColor = (verdict: string) => {
  const value = verdict.toUpperCase()
  if (value === 'ALLOW' || value === 'APPROVED' || value === 'CORRECT') return 'green'
  if (value === 'BLOCK' || value === 'REJECTED') return 'red'
  if (value === 'REVIEW' || value === 'PENDING') return 'amber'
  return 'muted'
}

function App() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [pending, setPending] = useState<AnyRecord[]>([])
  const [audit, setAudit] = useState<AnyRecord[]>([])
  const [agentStatus, setAgentStatus] = useState<AgentStatusResponse | null>(null)
  const [eventFilter, setEventFilter] = useState('ALL')
  const [health, setHealth] = useState<'checking' | 'online' | 'offline'>('checking')
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [activeTab, setActiveTab] = useState('Overview')
  const [auditFilter, setAuditFilter] = useState('ALL')
  const [search, setSearch] = useState('')
  const [assistantOpen, setAssistantOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [chatInput, setChatInput] = useState('')
  const [chatLoading, setChatLoading] = useState(false)
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { role: 'assistant', text: 'AEGIS assistant is ready. Ask me about governance decisions, pending reviews, or audit activity.' }
  ])

  const loadDashboard = useCallback(async () => {
    try {
      const [healthRes, statsRes, pendingRes, auditRes, agentsRes] = await Promise.all([
        fetch(`${API}/health`),
        fetch(`${API}/stats`),
        fetch(`${API}/pending`),
        fetch(`${API}/audit?limit=100`),
        fetch(`${API}/agents/status`)
      ])

      setHealth(healthRes.ok ? 'online' : 'offline')

      if (statsRes.ok) setStats(await statsRes.json())
      if (pendingRes.ok) {
        const data: ApiList = await pendingRes.json()
        setPending(Array.isArray(data.entries) ? data.entries : [])
      }
      if (auditRes.ok) {
        const data: ApiList = await auditRes.json()
        setAudit(Array.isArray(data.entries) ? data.entries : [])
      }
      if (agentsRes.ok) {
        const data: AgentStatusResponse = await agentsRes.json()
        setAgentStatus(data)
      }

      setLastUpdated(new Date())
    } catch {
      setHealth('offline')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadDashboard()
    const interval = window.setInterval(() => void loadDashboard(), 10000)
    return () => window.clearInterval(interval)
  }, [loadDashboard])

  const verdicts = stats?.verdicts ?? {}
  const allowCount = number(verdicts.ALLOW)
  const blockCount = number(verdicts.BLOCK)
  const reviewCount = number(verdicts.REVIEW)
  const total = number(stats?.total) || allowCount + blockCount + reviewCount
  const integrity = stats?.log_intact

  const filteredAudit = useMemo(() => {
    return audit.filter((entry) => {
      const verdict = getValue(entry, ['verdict'], '').toUpperCase()
      const matchesFilter = auditFilter === 'ALL' || verdict === auditFilter
      const searchable = [
        getValue(entry, ['agent', 'actor']),
        getValue(entry, ['kind', 'type']),
        getValue(entry, ['verdict']),
        getValue(entry, ['reason', 'message']),
        getValue(entry, ['risk'])
      ].join(' ').toLowerCase()
      return matchesFilter && searchable.includes(search.toLowerCase())
    })
  }, [audit, auditFilter, search])


  const liveAgents = agentStatus?.agents ?? []
  const connectedAgents = liveAgents.filter((agent) => agent.status === 'running').length

  const networkOption = useMemo(() => {
    const centerX = 460
    const centerY = 190
    const radius = 142
    const statusColor = (status: string) => {
      if (status === 'running') return '#39d6a2'
      if (status === 'error' || status === 'disconnected') return '#ff667b'
      if (status === 'stale') return '#f1b95e'
      return '#71849a'
    }

    const nodes = [
      {
        id: 'aegis-core',
        name: 'AEGIS',
        x: centerX,
        y: centerY,
        symbolSize: 76,
        itemStyle: { color: '#173b50', borderColor: '#36cbd2', borderWidth: 3, shadowBlur: 22, shadowColor: 'rgba(54,203,210,0.35)' },
        label: { show: true, color: '#e8eff7', fontSize: 15, fontWeight: 700, position: 'inside' }
      },
      ...liveAgents.map((agent, index) => {
        const angle = (Math.PI * 2 * index / Math.max(liveAgents.length, 1)) - Math.PI / 2
        const status = String(agent.status ?? 'unknown')
        return {
          id: String(agent.agent_id ?? `agent-${index}`),
          name: String(agent.name ?? agent.agent_id ?? `Agent ${index + 1}`),
          x: centerX + Math.cos(angle) * radius,
          y: centerY + Math.sin(angle) * radius,
          symbolSize: 48,
          itemStyle: {
            color: '#132638',
            borderColor: statusColor(status),
            borderWidth: 2,
            shadowBlur: status === 'running' ? 16 : 0,
            shadowColor: statusColor(status)
          },
          label: { show: true, color: '#dce7f1', fontSize: 11, position: 'bottom', distance: 9 },
          status
        }
      })
    ]

    const links = liveAgents.map((agent) => ({
      source: 'aegis-core',
      target: String(agent.agent_id),
      lineStyle: {
        color: statusColor(String(agent.status ?? 'unknown')),
        width: agent.status === 'running' ? 2.5 : 1.3,
        opacity: agent.status === 'running' ? 0.9 : 0.45,
        curveness: 0.04
      },
      effect: { show: agent.status === 'running', period: 3.5, trailLength: 0.25, symbolSize: 5 }
    }))

    return {
      backgroundColor: 'transparent',
      animationDuration: 500,
      tooltip: {
        trigger: 'item',
        backgroundColor: '#101c2b',
        borderColor: '#26394d',
        textStyle: { color: '#e6f1fa' },
        formatter: (params: AnyRecord) => {
          const data = params.data ?? {}
          if (data.id === 'aegis-core') return '<strong>AEGIS Governance Core</strong>'
          return `<strong>${data.name ?? 'Agent'}</strong><br/>Status: ${pretty(data.status ?? 'unknown')}`
        }
      },
      series: [{
        type: 'graph',
        layout: 'none',
        coordinateSystem: null,
        roam: true,
        draggable: true,
        data: nodes,
        links,
        edgeSymbol: ['none', 'none'],
        lineStyle: { color: '#36cbd2', opacity: 0.5, width: 1.5 },
        emphasis: { focus: 'adjacency', lineStyle: { width: 3 } }
      }]
    }
  }, [liveAgents])

  const liveEvents = useMemo(() => {
    const runtimeEvents: AnyRecord[] = liveAgents.flatMap((agent) =>
      (Array.isArray(agent.recent_events) ? agent.recent_events : []).map((event: AnyRecord) => ({
        ...event,
        agent_id: event.agent_id ?? agent.agent_id ?? agent.name,
        source: 'agent'
      }))
    )

    const auditEvents: AnyRecord[] = audit.map((entry) => ({
      ...entry,
      event: entry.event ?? entry.verdict ?? 'governance_decision',
      timestamp: entry.timestamp ?? entry.created_at ?? entry.time,
      agent_id: entry.agent_id ?? entry.agent ?? entry.actor ?? 'AEGIS',
      source: 'audit'
    }))

    return [...runtimeEvents, ...auditEvents]
      .filter((event) => event.timestamp)
      .sort((a, b) => Date.parse(String(b.timestamp)) - Date.parse(String(a.timestamp)))
  }, [liveAgents, audit])

  const filteredLiveEvents = useMemo(() => {
    return liveEvents.filter((event) => {
      const eventName = String(event.event ?? '').toLowerCase()
      if (eventFilter === 'ERROR') return eventName.includes('error') || eventName.includes('failed')
      if (eventFilter === 'DECISION') return event.source === 'audit' || Boolean(event.verdict)
      if (eventFilter === 'AGENT') return event.source === 'agent'
      return true
    })
  }, [liveEvents, eventFilter])

  const chartOption = useMemo(() => ({
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: '#101c2b',
      borderColor: '#26394d',
      textStyle: { color: '#e6f1fa' }
    },
    legend: {
      bottom: 0,
      icon: 'circle',
      itemWidth: 7,
      itemHeight: 7,
      textStyle: { color: '#8295a9', fontSize: 11 },
      data: ['Allowed', 'Blocked', 'Review']
    },
    series: [{
      type: 'pie',
      radius: ['62%', '82%'],
      center: ['50%', '43%'],
      avoidLabelOverlap: true,
      itemStyle: { borderColor: '#101b29', borderWidth: 4, borderRadius: 5 },
      label: { show: false },
      emphasis: {
        scale: true,
        scaleSize: 7,
        label: { show: true, color: '#e6f1fa', fontSize: 13, fontWeight: 600, formatter: '{b}\n{c}' }
      },
      data: [
        { name: 'Allowed', value: allowCount, itemStyle: { color: '#35d6a0' } },
        { name: 'Blocked', value: blockCount, itemStyle: { color: '#ff6378' } },
        { name: 'Review', value: reviewCount, itemStyle: { color: '#f3b957' } }
      ]
    }]
  }), [allowCount, blockCount, reviewCount])

  const riskOption = useMemo(() => {
    const risks = stats?.risks ?? {}
    const entries = Object.entries(risks).filter(([, value]) => number(value) > 0)
    const labels = entries.length ? entries.map(([key]) => pretty(key)) : ['No risk data']
    const values = entries.length ? entries.map(([, value]) => number(value)) : [0]
    return {
      backgroundColor: 'transparent',
      grid: { left: 8, right: 18, top: 15, bottom: 30, containLabel: true },
      tooltip: {
        trigger: 'axis',
        backgroundColor: '#101c2b',
        borderColor: '#26394d',
        textStyle: { color: '#e6f1fa' }
      },
      xAxis: {
        type: 'category',
        data: labels,
        axisLabel: { color: '#8295a9', fontSize: 10, rotate: labels.length > 4 ? 20 : 0 },
        axisLine: { lineStyle: { color: '#26394d' } },
        axisTick: { show: false }
      },
      yAxis: {
        type: 'value',
        minInterval: 1,
        axisLabel: { color: '#8295a9', fontSize: 10 },
        splitLine: { lineStyle: { color: '#1e2d3d', type: 'dashed' } }
      },
      series: [{
        type: 'bar',
        data: values,
        barMaxWidth: 34,
        itemStyle: {
          color: '#32c9d0',
          borderRadius: [5, 5, 0, 0]
        }
      }]
    }
  }, [stats?.risks])

  const handleDecision = async (action: 'approve' | 'reject', entry: AnyRecord) => {
    const reviewSeq = Number(entry.review_seq ?? entry.seq)
    if (!Number.isInteger(reviewSeq) || reviewSeq < 1) {
      window.alert('This review item does not contain a valid review sequence number.')
      return
    }

    const token = window.prompt('Enter your AEGIS reviewer token. It will not be saved in the browser.')
    if (!token) return

    try {
      const response = await fetch(`${API}/${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ review_seq: reviewSeq })
      })
      const result = await response.json().catch(() => ({}))
      if (!response.ok) {
        window.alert(result.detail || `Could not ${action} this request.`)
        return
      }
      window.alert(action === 'approve'
        ? 'Approval recorded. This does not execute the requested action.'
        : 'Rejection recorded. No action was executed.')
      await loadDashboard()
    } catch {
      window.alert('Could not reach the AEGIS API. Check that the backend is running.')
    }
  }

  const sendChat = async () => {
    const message = chatInput.trim()
    if (!message || chatLoading) return
    setChatMessages((current) => [...current, { role: 'user', text: message }])
    setChatInput('')
    setChatLoading(true)

    try {
      const response = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, agent: 'chat', session_id: 'dashboard' })
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(data.detail || 'The assistant request failed.')
      const reply = data.reply ?? data.response ?? data.message ?? JSON.stringify(data, null, 2)
      setChatMessages((current) => [...current, { role: 'assistant', text: String(reply) }])
    } catch (error) {
      setChatMessages((current) => [...current, {
        role: 'assistant',
        text: error instanceof Error ? error.message : 'Could not connect to the AEGIS assistant.'
      }])
    } finally {
      setChatLoading(false)
    }
  }

  const navItems = [
    { name: 'Overview', icon: LayoutDashboard },
    { name: 'Governance', icon: ShieldCheck },
    { name: 'Audit trail', icon: FileCheck2 },
    { name: 'Human reviews', icon: Fingerprint }
  ]

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={22} strokeWidth={1.8} /></div>
          <div>
            <div className="brand-name">AEGIS<span>.AI</span></div>
            <div className="brand-caption">AI GOVERNANCE PLATFORM</div>
          </div>
          <button className="mobile-close icon-button" onClick={() => setMobileNavOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <div className="workspace-switch">
          <div className="workspace-avatar">A</div>
          <div className="workspace-copy"><strong>AEGIS Control</strong><span>Governance environment</span></div>
          <ChevronDown size={15} />
        </div>

        <div className="nav-label">PLATFORM</div>
        <nav className="main-nav">
          {navItems.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${activeTab === name ? 'active' : ''}`}
              onClick={() => { setActiveTab(name); setMobileNavOpen(false) }}
            >
              <Icon size={17} />
              <span>{name}</span>
              {name === 'Human reviews' && pending.length > 0 && <span className="nav-count">{pending.length}</span>}
            </button>
          ))}
        </nav>

        <div className="nav-label nav-label-lower">SYSTEM</div>
        <div className="system-links">
          <div className="system-link"><Terminal size={16} /><span>Agent runtime</span></div>
          <div className="system-link"><LockKeyhole size={16} /><span>Policy controls</span></div>
          <div className="system-link"><SlidersHorizontal size={16} /><span>Configuration</span></div>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span className={`status-dot ${health}`} />
            <div><strong>API connection</strong><small>{health === 'online' ? 'Backend connected' : health === 'offline' ? 'Backend unavailable' : 'Checking connection'}</small></div>
          </div>
          <div className="user-profile">
            <div className="user-avatar">OP</div>
            <div><strong>Operator</strong><small>Control workspace</small></div>
            <ChevronDown size={15} />
          </div>
        </div>
      </aside>

      {mobileNavOpen && <button className="mobile-backdrop" onClick={() => setMobileNavOpen(false)} aria-label="Close menu" />}

      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu size={19} /></button>
            <div className="breadcrumb">Workspace <ChevronRight size={13} /> <strong>{activeTab}</strong></div>
          </div>
          <div className="topbar-right">
            <div className={`connection-pill ${health}`}>
              <span className="status-dot" />
              {health === 'online' ? 'SYSTEM ONLINE' : health === 'offline' ? 'API OFFLINE' : 'CONNECTING'}
            </div>
            <button className="icon-button refresh-button" onClick={() => void loadDashboard()} title="Refresh dashboard"><RefreshCw size={16} /></button>
            <button className="assistant-trigger" onClick={() => setAssistantOpen(true)}><Sparkles size={15} /> Ask AEGIS</button>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> AUTONOMOUS SYSTEM OVERSIGHT</div>
              <h1>{activeTab === 'Overview' ? 'Governance overview' : activeTab}</h1>
              <p>Monitor decisions, review high-impact actions, and maintain control over agent activity.</p>
            </div>
            <div className="heading-meta">
              <div className="live-indicator"><span className="pulse-dot" /> LIVE DATA</div>
              <span className="updated-time">{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Waiting for data'}</span>
            </div>
          </section>

          <section className="live-monitor-grid">
            <div className="panel network-panel">
              <div className="panel-header">
                <div>
                  <div className="panel-kicker">LIVE AGENT TOPOLOGY</div>
                  <h2>AEGIS agent network</h2>
                </div>
                <div className="network-summary">
                  <span className="network-count">{connectedAgents}/{agentStatus?.total_agents ?? liveAgents.length}</span>
                  <span>agents online</span>
                </div>
              </div>
              <div className="network-legend">
                <span><i className="legend-dot running" /> Running</span>
                <span><i className="legend-dot stopped" /> Stopped</span>
                <span><i className="legend-dot disconnected" /> Disconnected / error</span>
              </div>
              {liveAgents.length === 0 ? (
                <div className="network-empty">
                  <Bot size={25} />
                  <strong>No agents reported yet</strong>
                  <span>Start your simulated agents to see them connected to the AEGIS core.</span>
                </div>
              ) : (
                <ReactECharts option={networkOption} style={{ height: 360, width: '100%' }} notMerge />
              )}
              <div className="network-agent-strip">
                {liveAgents.map((agent, index) => (
                  <div className="network-agent-chip" key={String(agent.agent_id ?? index)}>
                    <span className={`status-dot ${agent.status === 'running' ? 'online' : agent.status === 'error' || agent.status === 'disconnected' ? 'error' : 'idle'}`} />
                    <span>{pretty(agent.name ?? agent.agent_id)}</span>
                    <strong>{pretty(agent.status ?? 'unknown')}</strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel live-events-panel">
              <div className="panel-header">
                <div>
                  <div className="panel-kicker">LIVE PROCESS + GOVERNANCE FEED</div>
                  <h2>Event stream <span className="inline-count">{liveEvents.length}</span></h2>
                </div>
                <Activity size={18} className="muted-icon" />
              </div>
              <div className="event-filter-row">
                <span>Showing latest events</span>
                <select value={eventFilter} onChange={(e) => setEventFilter(e.target.value)} aria-label="Filter live events">
                  <option value="ALL">All events</option>
                  <option value="DECISION">Governance decisions</option>
                  <option value="AGENT">Agent process events</option>
                  <option value="ERROR">Errors and failures</option>
                </select>
              </div>
              <div className="live-event-list">
                {filteredLiveEvents.length === 0 ? (
                  <div className="empty-state compact">
                    <Activity size={22} />
                    <span>No events match this filter yet.</span>
                  </div>
                ) : filteredLiveEvents.slice(0, 18).map((event, index) => {
                  const eventName = String(event.event ?? 'event')
                  const verdict = String(event.verdict ?? event.last_verdict ?? '')
                  const failed = eventName.toLowerCase().includes('error') || eventName.toLowerCase().includes('failed')
                  return (
                    <details className="live-event-item" key={`${event.source}-${event.seq ?? event.timestamp}-${index}`}>
                      <summary>
                        <span className={`event-mark ${failed ? 'failed' : verdict ? verdictColor(verdict) : 'neutral'}`}>
                          {failed ? <AlertTriangle size={14} /> : verdict ? <ShieldCheck size={14} /> : <Zap size={14} />}
                        </span>
                        <span className="event-main">
                          <strong>{pretty(eventName)}</strong>
                          <small>{pretty(event.agent_id ?? 'AEGIS')} · {event.source === 'audit' ? 'Governance' : 'Agent process'}</small>
                        </span>
                        {verdict && <span className={`verdict-pill ${verdictColor(verdict)}`}>{verdict}</span>}
                        <time>{new Date(event.timestamp).toLocaleTimeString()}</time>
                        <ChevronDown size={14} className="event-chevron" />
                      </summary>
                      <div className="live-event-detail">
                        <div><span>Timestamp</span><strong>{new Date(event.timestamp).toLocaleString()}</strong></div>
                        {event.kind && <div><span>Action type</span><strong>{String(event.kind)}</strong></div>}
                        {event.rule_id && <div><span>Policy rule</span><strong>{String(event.rule_id)}</strong></div>}
                        {event.reason && <div><span>Reason</span><strong>{String(event.reason)}</strong></div>}
                        {event.error && <div><span>Error</span><strong className="text-red">{String(event.error)}</strong></div>}
                        <pre>{JSON.stringify(event, null, 2)}</pre>
                      </div>
                    </details>
                  )
                })}
              </div>
            </div>
          </section>

          <section className="metric-grid">
            <MetricCard label="Total decisions" value={total} icon={<Activity />} detail="Recorded governance events" tone="cyan" />
            <MetricCard label="Allowed" value={allowCount} icon={<ShieldCheck />} detail="Permitted by policy" tone="green" />
            <MetricCard label="Blocked" value={blockCount} icon={<ShieldAlert />} detail="Denied by policy" tone="red" />
            <MetricCard label="Awaiting review" value={pending.length} icon={<Clock3 />} detail="Human decision required" tone="amber" />
          </section>

          <section className="dashboard-grid">
            <div className="panel decision-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">DECISION DISTRIBUTION</div><h2>Governance activity</h2></div>
                <span className="panel-icon"><Gauge size={17} /></span>
              </div>
              <div className="donut-wrap">
                <ReactECharts option={chartOption} style={{ height: 238, width: '100%' }} notMerge />
                <div className="donut-center"><strong>{total}</strong><span>DECISIONS</span></div>
              </div>
              <div className="chart-footnote"><span className="footnote-dot" /> Distribution from recorded API decisions</div>
            </div>

            <div className="panel risk-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">RISK CLASSIFICATION</div><h2>Recorded risk levels</h2></div>
                <span className="panel-icon"><AlertTriangle size={17} /></span>
              </div>
              <ReactECharts option={riskOption} style={{ height: 250, width: '100%' }} notMerge />
              <div className="chart-footnote"><span className="footnote-dot teal" /> Counts supplied by the AEGIS statistics API</div>
            </div>

            <div className="panel integrity-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">AUDIT PROTECTION</div><h2>Log integrity</h2></div>
                <Fingerprint size={18} className="muted-icon" />
              </div>
              <div className="integrity-visual">
                <div className={`integrity-icon ${integrity === true ? 'good' : integrity === false ? 'bad' : 'unknown'}`}>
                  {integrity === true ? <ShieldCheck size={29} /> : integrity === false ? <AlertOctagon size={29} /> : <CircleHelp size={29} />}
                </div>
                <div className="integrity-copy">
                  <strong>{integrity === true ? 'Integrity verified' : integrity === false ? 'Integrity check failed' : 'Status unavailable'}</strong>
                  <span>{stats?.integrity_message || 'Audit integrity status from the backend'}</span>
                </div>
              </div>
              <div className="integrity-divider" />
              <div className="integrity-row"><span>Audit records</span><strong>{total.toLocaleString()}</strong></div>
              <div className="integrity-row"><span>Pending decisions</span><strong>{pending.length}</strong></div>
              <div className="integrity-row"><span>API status</span><strong className={health === 'online' ? 'text-green' : 'text-red'}>{health === 'online' ? 'Connected' : 'Unavailable'}</strong></div>
            </div>
          </section>

          <section className="lower-grid">
            <div className="panel reviews-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">HUMAN-IN-THE-LOOP</div><h2>Review queue <span className="inline-count">{pending.length}</span></h2></div>
                <button className="text-action" onClick={() => setActiveTab('Human reviews')}>View queue <ChevronRight size={14} /></button>
              </div>
              {pending.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon"><CheckCircle2 size={22} /></div>
                  <strong>You're all caught up</strong>
                  <span>No pending review items were returned by the API.</span>
                </div>
              ) : (
                <div className="review-list">
                  {pending.slice(0, 5).map((entry, index) => (
                    <ReviewItem key={entry.review_seq ?? entry.seq ?? index} entry={entry} onDecision={handleDecision} />
                  ))}
                </div>
              )}
            </div>

            <div className="panel activity-panel">
              <div className="panel-header">
                <div><div className="panel-kicker">AGENT GOVERNANCE</div><h2>Agent activity</h2></div>
                <Bot size={18} className="muted-icon" />
              </div>
              {Object.keys(stats?.agents ?? {}).length === 0 ? (
                <div className="empty-state compact"><Bot size={23} /><span>No agent activity data available.</span></div>
              ) : (
                <div className="agent-list">
                  {Object.entries(stats?.agents ?? {}).map(([agent, count]) => (
                    <div className="agent-row" key={agent}>
                      <div className="agent-avatar"><Bot size={16} /></div>
                      <div className="agent-info"><strong>{pretty(agent)}</strong><span>Recorded decisions</span></div>
                      <strong className="agent-count">{number(count)}</strong>
                    </div>
                  ))}
                </div>
              )}
              <div className="activity-footer"><span className="status-dot online" /> Based on recorded agent events</div>
            </div>
          </section>

          <section className="panel audit-panel">
            <div className="panel-header audit-heading">
              <div><div className="panel-kicker">IMMUTABLE EVENT HISTORY</div><h2>Recent audit activity</h2></div>
              <div className="audit-tools">
                <div className="search-box"><Search size={14} /><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search events..." /></div>
                <select value={auditFilter} onChange={(e) => setAuditFilter(e.target.value)} aria-label="Filter audit verdict">
                  <option value="ALL">All verdicts</option><option value="ALLOW">Allowed</option><option value="BLOCK">Blocked</option><option value="REVIEW">Review</option>
                </select>
              </div>
            </div>
            <div className="audit-table-wrap">
              <table className="audit-table">
                <thead><tr><th>EVENT</th><th>AGENT</th><th>TYPE</th><th>RISK</th><th>VERDICT</th><th>REASON</th></tr></thead>
                <tbody>
                  {filteredAudit.slice(0, 12).map((entry, index) => {
                    const verdict = getValue(entry, ['verdict'], 'UNKNOWN')
                    return (
                      <tr key={entry.seq ?? entry.audit_seq ?? index}>
                        <td className="event-id">#{getValue(entry, ['seq', 'audit_seq'], String(index + 1))}</td>
                        <td>{getValue(entry, ['agent', 'actor'])}</td>
                        <td>{pretty(getValue(entry, ['kind', 'type']))}</td>
                        <td>{pretty(getValue(entry, ['risk']))}</td>
                        <td><span className={`verdict-badge ${verdictColor(verdict)}`}><span />{verdict}</span></td>
                        <td className="reason-cell" title={getValue(entry, ['reason', 'message'])}>{getValue(entry, ['reason', 'message'])}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {filteredAudit.length === 0 && <div className="table-empty">{loading ? 'Loading audit records...' : 'No matching audit records.'}</div>}
            </div>
            <div className="audit-footer"><span>Showing {Math.min(filteredAudit.length, 12)} of {filteredAudit.length} matching records</span><span>Source: AEGIS audit API</span></div>
          </section>

          <footer className="page-footer">
            <span><span className="footer-mark">A</span> AEGIS.AI <span className="footer-separator">/</span> Accountability layer for autonomous agents</span>
            <span>Governance interface <span className="footer-separator">·</span> API-backed data</span>
          </footer>
        </div>
      </main>

      <button className={`assistant-fab ${assistantOpen ? 'fab-hidden' : ''}`} onClick={() => setAssistantOpen(true)} aria-label="Open AEGIS assistant">
        <Sparkles size={20} /><span>AEGIS</span>
      </button>

      <div className={`assistant-backdrop ${assistantOpen ? 'visible' : ''}`} onClick={() => setAssistantOpen(false)} />
      <aside className={`assistant-drawer ${assistantOpen ? 'drawer-open' : ''}`}>
        <div className="assistant-header">
          <div className="assistant-brand">
            <div className="assistant-orb"><Sparkles size={19} /></div>
            <div><strong>AEGIS Assistant</strong><span>Governance intelligence</span></div>
          </div>
          <button className="icon-button" onClick={() => setAssistantOpen(false)} aria-label="Close assistant"><X size={18} /></button>
        </div>
        <div className="assistant-context"><span className="pulse-dot" /> CONNECTED TO AEGIS API</div>
        <div className="chat-messages">
          {chatMessages.map((message, index) => (
            <div className={`chat-message ${message.role}`} key={index}>
              {message.role === 'assistant' && <div className="chat-avatar"><Sparkles size={13} /></div>}
              <div className="chat-bubble">{message.text}</div>
            </div>
          ))}
          {chatLoading && <div className="chat-loading"><span /><span /><span /> AEGIS is responding</div>}
        </div>
        <div className="assistant-suggestions">
          <button onClick={() => setChatInput('Summarize the current governance activity.')}>Governance summary</button>
          <button onClick={() => setChatInput('Explain the pending review queue.')}>Pending reviews</button>
        </div>
        <form className="chat-composer" onSubmit={(e) => { e.preventDefault(); void sendChat() }}>
          <input value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Ask AEGIS something..." />
          <button type="submit" disabled={!chatInput.trim() || chatLoading} aria-label="Send message"><Send size={17} /></button>
        </form>
        <div className="assistant-disclaimer">Responses are generated by the configured AEGIS assistant.</div>
      </aside>
    </div>
  )
}

function MetricCard({ label, value, icon, detail, tone }: {
  label: string; value: number; icon: React.ReactNode; detail: string; tone: string
}) {
  return (
    <div className="metric-card">
      <div className="metric-top"><span>{label}</span><div className={`metric-icon ${tone}`}>{icon}</div></div>
      <div className="metric-value">{value.toLocaleString()}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  )
}

function ReviewItem({ entry, onDecision }: {
  entry: AnyRecord
  onDecision: (action: 'approve' | 'reject', entry: AnyRecord) => void
}) {
  const description = getValue(entry, ['reason', 'description', 'action', 'original'], 'Review required')
  return (
    <div className="review-item">
      <div className="review-symbol"><AlertTriangle size={16} /></div>
      <div className="review-copy">
        <strong>{getValue(entry, ['agent'], 'Agent')} <span>·</span> {pretty(getValue(entry, ['kind', 'type'], 'Action'))}</strong>
        <p>{description.length > 115 ? `${description.slice(0, 115)}…` : description}</p>
        <div className="review-meta">Review #{getValue(entry, ['review_seq', 'seq'])} <span>·</span> {pretty(getValue(entry, ['risk'], 'Unspecified risk'))}</div>
      </div>
      <div className="review-actions">
        <button className="approve-button" onClick={() => onDecision('approve', entry)} title="Record approval"><Check size={14} /> Approve</button>
        <button className="reject-button" onClick={() => onDecision('reject', entry)} title="Record rejection"><X size={14} /></button>
      </div>
    </div>
  )
}

export default App
