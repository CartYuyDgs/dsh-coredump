/**
 * dsh-coredump — Web GUI half.
 *
 * A central panel (`main` key `coredump`, opened from its sidebar icon) that
 * drives the same host engine the agent tools use, through three loopback-only
 * routes: find → parse → frame.
 *
 * Plain browser module: no Harness Client package is imported. React comes from
 * the host module table, styling uses `--dsw-alias-*` theme tokens only, and all
 * visible text goes through the Client locale service.
 */

window.__ModuleLoader__.load({
  id: 'dsh-coredump',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const { useState, useEffect, useRef, useCallback, useMemo } = React

    const NS = 'dsh-coredump'
    const PANEL_ID = 'coredump'
    const PANEL_ORDER = 47
    const API = {
      find: '/api/dsh-coredump/find',
      parse: '/api/dsh-coredump/parse',
      frame: '/api/dsh-coredump/frame',
    }
    const RECENT_KEY = 'dsh-coredump.recent.v1'
    const FORM_KEY = 'dsh-coredump.form.v1'
    const MAX_RECENT = 8

    // -----------------------------------------------------------------------
    // Text
    // -----------------------------------------------------------------------

    const ZH = {
      'meta.title': 'Coredump 解析',
      'meta.description': '通过 SSH 在远端 Linux 设备上找 core、看崩溃栈、深挖单帧。',
      'panel.title': 'Coredump 解析',
      'panel.subtitle': '远端 Linux 设备的 core：找文件 → 出崩溃栈 → 深挖单帧。走系统 OpenSSH，支持多跳。',
      'form.host': 'SSH 主机',
      'form.host.placeholder': '别名或 user@host，例如 172.24.80.249',
      'form.core': 'Core 路径',
      'form.core.placeholder': '/tmp/cdtest/core.4360',
      'form.exe': '可执行文件（可选）',
      'form.exe.placeholder': '/tmp/cdtest/crash',
      'form.key': '私钥文件路径（可选，不是密码）',
      'form.key.placeholder': '~/.ssh/id_ed25519 或 C:\\Users\\you\\.ssh\\id_ed25519',
      'form.hint': '纯密码登录：先 ssh-copy-id 装一把公钥；私钥有口令时用 ssh-agent（ssh-add）后这里留空。',
      'action.parse': '解析',
      'action.find': '扫描 core',
      'action.refresh': '重新解析',
      'action.open': '解析这个',
      'recent.title': '最近',
      'recent.clear': '清空',
      'state.busy.find': '正在扫描远端…',
      'state.busy.parse': '解析中（大 core 可能要几十秒）…',
      'state.busy.frame': '读取帧详情…',
      'empty.title': '还没有结果',
      'empty.hint': '填好主机和 core 路径，点「解析」；不知道 core 在哪就先点「扫描 core」。',
      'result.threads': '线程',
      'result.crash': '崩溃',
      'result.frames': '调用栈',
      'result.noFrames': '这个线程没有解析出栈帧。',
      'result.detail': '帧详情',
      'result.closeDetail': '收起',
      'result.registers': '寄存器',
      'result.args': '参数',
      'result.locals': '局部变量',
      'result.disasm': '反汇编',
      'result.source': '源码',
      'result.diagnostics': '诊断',
      'result.modules': '模块',
      'result.signal': '信号',
      'result.instruction': '崩溃指令',
      'result.threadsCount': '线程数',
      'result.arch': '架构',
      'result.untrusted': 'core 与可执行文件不匹配：下面的栈不可信，只当线索。',
      'result.generatedBy': '生成命令',
      'find.pattern': 'core_pattern',
      'find.ulimit': 'ulimit -c',
      'find.rows': '找到的 core',
      'find.none': '这些目录里没有 core。',
      'find.ctl': 'coredumpctl',
      'error.title': '出错了',
      'hint.loopbackOnly': '面板仅接受本机请求。',
    }

    const EN = {
      'meta.title': 'Coredump Inspector',
      'meta.description': 'Find cores, read crash stacks and inspect single frames on remote Linux hosts over SSH.',
      'panel.title': 'Coredump Inspector',
      'panel.subtitle': 'Remote Linux cores: find → stack → single frame. Uses the system OpenSSH client, jump hosts included.',
      'form.host': 'SSH host',
      'form.host.placeholder': 'alias or user@host, e.g. 172.24.80.249',
      'form.core': 'Core path',
      'form.core.placeholder': '/tmp/cdtest/core.4360',
      'form.exe': 'Executable (optional)',
      'form.exe.placeholder': '/tmp/cdtest/crash',
      'form.key': 'Key file path (optional, not a password)',
      'form.key.placeholder': '~/.ssh/id_ed25519 or C:\\Users\\you\\.ssh\\id_ed25519',
      'form.hint': 'Password-only host? Run ssh-copy-id once. Passphrase-protected key? Load it into ssh-agent (ssh-add) and leave this empty.',
      'action.parse': 'Parse',
      'action.find': 'Find cores',
      'action.refresh': 'Parse again',
      'action.open': 'Parse this',
      'recent.title': 'Recent',
      'recent.clear': 'Clear',
      'state.busy.find': 'Scanning the host…',
      'state.busy.parse': 'Parsing (a big core can take tens of seconds)…',
      'state.busy.frame': 'Loading frame detail…',
      'empty.title': 'Nothing parsed yet',
      'empty.hint': 'Fill in the host and core path, then Parse. Not sure where the core is? Find cores first.',
      'result.threads': 'Threads',
      'result.crash': 'crash',
      'result.frames': 'Stack',
      'result.noFrames': 'No frames parsed for this thread.',
      'result.detail': 'Frame detail',
      'result.closeDetail': 'Close',
      'result.registers': 'Registers',
      'result.args': 'Arguments',
      'result.locals': 'Locals',
      'result.disasm': 'Disassembly',
      'result.source': 'Source',
      'result.diagnostics': 'Diagnostics',
      'result.modules': 'Modules',
      'result.signal': 'Signal',
      'result.instruction': 'Faulting instruction',
      'result.threadsCount': 'Threads',
      'result.arch': 'Arch',
      'result.untrusted': 'The core does not match this executable: the stack is not trustworthy.',
      'result.generatedBy': 'Generated by',
      'find.pattern': 'core_pattern',
      'find.ulimit': 'ulimit -c',
      'find.rows': 'Cores found',
      'find.none': 'No core in these directories.',
      'find.ctl': 'coredumpctl',
      'error.title': 'Failed',
      'hint.loopbackOnly': 'This panel only accepts local requests.',
    }

    /** Replace `{name}` placeholders. */
    function applyParams(template, params) {
      if (!params) return template
      return String(template).replace(/\{(\w+)\}/g, (whole, key) =>
        (params[key] === undefined ? whole : String(params[key])))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /** POST JSON; resolves to the parsed payload, throws on transport errors. */
    async function postJson(url, body) {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
      let payload
      try {
        payload = await response.json()
      } catch {
        throw new Error(`HTTP ${response.status}`)
      }
      if (payload && payload.ok === false && payload.error) return payload
      if (!response.ok) {
        throw new Error((payload && payload.error && payload.error.message) || `HTTP ${response.status}`)
      }
      return payload
    }

    function clip(value, limit) {
      const text = String(value ?? '')
      return text.length <= limit ? text : text.slice(0, limit - 1) + '…'
    }

    function humanSize(bytes) {
      if (!Number.isFinite(bytes)) return '?'
      const units = ['B', 'KB', 'MB', 'GB']
      let value = bytes
      let unit = 0
      while (value >= 1024 && unit < units.length - 1) {
        value /= 1024
        unit += 1
      }
      return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)}${units[unit]}`
    }

    function readStored(key, fallback) {
      try {
        const raw = window.localStorage.getItem(key)
        return raw ? JSON.parse(raw) : fallback
      } catch {
        return fallback
      }
    }

    function writeStored(key, value) {
      try {
        if (value === undefined) window.localStorage.removeItem(key)
        else window.localStorage.setItem(key, JSON.stringify(value))
      } catch {
        /* storage can be unavailable; the panel still works */
      }
    }

    /** Frame position inside one thread, stable across re-renders. */
    function frameKey(threadId, index) {
      return `${threadId}:${index}`
    }

    // -----------------------------------------------------------------------
    // Icons
    // -----------------------------------------------------------------------

    /** Sidebar mark: a stack trace with a faulting row. */
    function CoredumpIcon({ size = 16, ...props }) {
      return h('svg', {
        viewBox: '0 0 16 16',
        width: size,
        height: size,
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: 1.4,
        strokeLinecap: 'round',
        strokeLinejoin: 'round',
        'aria-hidden': 'true',
        ...props,
      },
        h('rect', { x: 2, y: 1.8, width: 12, height: 12.4, rx: 2 }),
        h('path', { d: 'M4.5 5.2h4.2M4.5 7.6h6M4.5 10h2.6' }),
        h('circle', { cx: 11.2, cy: 10.3, r: 1.45, stroke: 'none', fill: 'currentColor' }),
      )
    }

    function ChevronIcon({ open }) {
      return h('svg', {
        viewBox: '0 0 12 12',
        width: 10,
        height: 10,
        fill: 'none',
        stroke: 'currentColor',
        strokeWidth: 1.6,
        strokeLinecap: 'round',
        'aria-hidden': 'true',
        style: { transform: open ? 'rotate(90deg)' : 'none', transition: 'transform .12s ease' },
      }, h('path', { d: 'M4 2.5 7.5 6 4 9.5' }))
    }

    // -----------------------------------------------------------------------
    // Styles (component-local; unmount removes them with the element)
    // -----------------------------------------------------------------------

    const CSS = `
.dcd-root { height: 100%; overflow: auto; box-sizing: border-box; padding: 24px 28px 40px;
  color: var(--dsw-alias-label-primary); background: var(--dsw-alias-bg-base);
  font-size: 13px; line-height: 1.55; }
.dcd-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.dcd-title { margin: 0; font-size: 19px; font-weight: 600; letter-spacing: .01em; }
.dcd-sub { margin: 4px 0 18px; color: var(--dsw-alias-label-secondary); max-width: 720px; }
.dcd-card { border: 1px solid var(--dsw-alias-border-l1); border-radius: 10px;
  background: var(--dsw-alias-bg-layer-1); padding: 14px 16px; }
.dcd-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 14px; }
.dcd-field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.dcd-label { font-size: 11px; letter-spacing: .02em; color: var(--dsw-alias-label-secondary); }
.dcd-input { height: 30px; padding: 0 9px; box-sizing: border-box; width: 100%;
  border: 1px solid var(--dsw-alias-border-l1); border-radius: 6px;
  background: var(--dsw-alias-bg-base); color: inherit; font: inherit; }
.dcd-input:focus { outline: none; border-color: var(--dsw-alias-brand-primary); }
.dcd-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dcd-row.end { justify-content: flex-end; }
.dcd-btn { height: 30px; padding: 0 13px; border-radius: 6px; cursor: pointer; font: inherit;
  border: 1px solid var(--dsw-alias-border-l1); background: var(--dsw-alias-bg-layer-2); color: inherit; }
.dcd-btn:hover:not(:disabled) { border-color: var(--dsw-alias-border-l2); }
.dcd-btn:disabled { opacity: .45; cursor: default; }
.dcd-btn.primary { border-color: transparent; background: var(--dsw-alias-brand-primary); color: #fff; }
.dcd-btn.ghost { border-color: transparent; background: transparent; color: var(--dsw-alias-label-secondary); }
.dcd-btn.ghost:hover:not(:disabled) { color: var(--dsw-alias-label-primary); background: var(--dsw-alias-bg-layer-2); }
.dcd-chips { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 10px 0 0; }
.dcd-chip { display: inline-flex; align-items: center; gap: 6px; max-width: 340px;
  padding: 3px 9px; border-radius: 999px; cursor: pointer; font-size: 12px;
  border: 1px solid var(--dsw-alias-border-l1); background: var(--dsw-alias-bg-layer-2); color: inherit; }
.dcd-chip:hover { border-color: var(--dsw-alias-brand-primary); }
.dcd-chip span.path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dcd-muted { color: var(--dsw-alias-label-secondary); }
.dcd-error { margin-top: 14px; border: 1px solid var(--dsw-alias-state-error-primary);
  border-radius: 10px; padding: 12px 14px; background: var(--dsw-alias-bg-layer-1); }
.dcd-error .code { color: var(--dsw-alias-state-error-primary); font-weight: 600; }
.dcd-status { margin-top: 14px; color: var(--dsw-alias-label-secondary); }
.dcd-empty { margin-top: 22px; padding: 26px 18px; text-align: center; border-radius: 10px;
  border: 1px dashed var(--dsw-alias-border-l1); color: var(--dsw-alias-label-secondary); }
.dcd-summary { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 18px 0 10px; }
.dcd-badge { display: inline-flex; align-items: center; gap: 6px; padding: 2px 9px; border-radius: 999px;
  font-size: 12px; border: 1px solid var(--dsw-alias-border-l1); background: var(--dsw-alias-bg-layer-2); }
.dcd-badge.signal { border-color: transparent; background: var(--dsw-alias-state-error-primary); color: #fff; }
.dcd-badge.ok { color: var(--dsw-alias-state-success-primary); }
.dcd-warn { margin: 0 0 12px; padding: 9px 12px; border-radius: 8px; font-size: 12.5px;
  border: 1px solid var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary);
  background: var(--dsw-alias-bg-layer-1); }
.dcd-split { display: grid; grid-template-columns: 216px minmax(0, 1fr); gap: 14px; align-items: start; }
.dcd-panel { border: 1px solid var(--dsw-alias-border-l1); border-radius: 10px;
  background: var(--dsw-alias-bg-layer-1); min-width: 0; }
.dcd-panel > header { display: flex; align-items: center; justify-content: space-between;
  padding: 9px 12px; border-bottom: 1px solid var(--dsw-alias-border-l1);
  font-size: 12px; color: var(--dsw-alias-label-secondary); }
.dcd-threads { padding: 6px; max-height: 260px; overflow: auto; }
.dcd-thread { display: flex; align-items: center; gap: 8px; width: 100%; text-align: left;
  padding: 5px 8px; border-radius: 6px; border: 1px solid transparent;
  background: transparent; color: inherit; cursor: pointer; font: inherit; }
.dcd-thread:hover { background: var(--dsw-alias-bg-layer-2); }
.dcd-thread[data-active='true'] { background: var(--dsw-alias-bg-layer-2); border-color: var(--dsw-alias-border-l2); }
.dcd-dot { width: 6px; height: 6px; border-radius: 50%; flex: none;
  background: var(--dsw-alias-state-idle-primary); }
.dcd-dot.crash { background: var(--dsw-alias-state-error-primary); }
.dcd-frames { max-height: 340px; overflow: auto; padding: 6px; }
.dcd-frame { display: block; width: 100%; text-align: left; border: 0; border-left: 2px solid transparent;
  background: transparent; color: inherit; cursor: pointer; padding: 3px 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.dcd-frame:hover { background: var(--dsw-alias-bg-layer-2); }
.dcd-frame[data-active='true'] { background: var(--dsw-alias-bg-layer-2); border-left-color: var(--dsw-alias-brand-primary); }
.dcd-frame .idx { display: inline-block; min-width: 26px; color: var(--dsw-alias-label-secondary); }
.dcd-frame .src { color: var(--dsw-alias-label-secondary); }
.dcd-detail { margin-top: 14px; }
.dcd-section { padding: 10px 12px; border-top: 1px solid var(--dsw-alias-border-l1); }
.dcd-section:first-of-type { border-top: 0; }
.dcd-section h4 { margin: 0 0 6px; font-size: 11px; font-weight: 600; letter-spacing: .04em;
  text-transform: uppercase; color: var(--dsw-alias-label-secondary); }
.dcd-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.dcd-regs { display: flex; flex-wrap: wrap; gap: 4px 12px; }
.dcd-source { margin: 0; padding-left: 0; list-style: none; overflow: auto; max-height: 300px; }
.dcd-source li { display: flex; gap: 10px; white-space: pre; }
.dcd-source li .ln { color: var(--dsw-alias-label-secondary); min-width: 42px; text-align: right; }
.dcd-source li[data-current='true'] { background: var(--dsw-alias-bg-layer-2); }
.dcd-kv { display: grid; grid-template-columns: minmax(90px, max-content) minmax(0, 1fr); gap: 4px 12px; }
.dcd-kv .k { color: var(--dsw-alias-label-secondary); }
.dcd-kv .v { overflow-wrap: anywhere; }
.dcd-diag { display: flex; gap: 8px; padding: 4px 0; }
.dcd-diag .sev { flex: none; width: 54px; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
.dcd-diag[data-sev='error'] .sev { color: var(--dsw-alias-state-error-primary); }
.dcd-diag[data-sev='warn'] .sev { color: var(--dsw-alias-state-warn-primary); }
.dcd-diag[data-sev='info'] .sev { color: var(--dsw-alias-label-secondary); }
.dcd-rows { padding: 4px 6px 8px; }
.dcd-rowitem { display: flex; align-items: center; gap: 10px; padding: 5px 6px; border-radius: 6px; }
.dcd-rowitem:hover { background: var(--dsw-alias-bg-layer-2); }
.dcd-rowitem .grow { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dcd-collapse { margin-top: 12px; }
`

    // -----------------------------------------------------------------------
    // Small views
    // -----------------------------------------------------------------------

    function Field({ label, value, placeholder, onChange, onEnter }) {
      return h('div', { className: 'dcd-field' },
        h('span', { className: 'dcd-label' }, label),
        h('input', {
          className: 'dcd-input',
          value,
          placeholder,
          spellCheck: false,
          onChange: event => onChange(event.target.value),
          onKeyDown: event => {
            if (event.key === 'Enter' && onEnter) onEnter()
          },
        }),
      )
    }

    function Section({ title, children }) {
      return h('div', { className: 'dcd-section' },
        title ? h('h4', null, title) : null,
        children,
      )
    }

    function KeyValues({ pairs }) {
      return h('div', { className: 'dcd-kv' },
        pairs.flatMap(([key, value]) => [
          h('span', { className: 'k', key: `k-${key}` }, key),
          h('span', { className: 'v dcd-mono', key: `v-${key}` }, value),
        ]))
    }

    function SourceWindow({ source }) {
      if (!source || !Array.isArray(source.lines) || source.lines.length === 0) return null
      return h('ul', { className: 'dcd-source dcd-mono' },
        source.lines.map(line => h('li', {
          key: line.number,
          'data-current': line.current ? 'true' : 'false',
        },
          h('span', { className: 'ln' }, line.number),
          h('span', null, line.text),
        )))
    }

    function Disassembly({ items }) {
      if (!Array.isArray(items) || items.length === 0) return null
      return h('div', { className: 'dcd-mono' },
        items.map(item => h('div', {
          key: item.address,
          style: item.current ? { color: 'var(--dsw-alias-brand-primary)' } : undefined,
        }, `${item.current ? '>' : ' '} ${item.address}${item.symbol ? ` <${item.symbol}>` : ''}  ${item.text}`)))
    }

    // -----------------------------------------------------------------------
    // Panel
    // -----------------------------------------------------------------------

    function CoredumpPanel({ t }) {
      const [host, setHost] = useState(() => readStored(FORM_KEY, {}).host || '')
      const [core, setCore] = useState(() => readStored(FORM_KEY, {}).core || '')
      const [exe, setExe] = useState(() => readStored(FORM_KEY, {}).exe || '')
      const [key, setKey] = useState(() => readStored(FORM_KEY, {}).key || '')
      const [busy, setBusy] = useState(null)
      const [error, setError] = useState(null)
      const [report, setReport] = useState(null)
      const [found, setFound] = useState(null)
      const [threadId, setThreadId] = useState(null)
      const [frameIndex, setFrameIndex] = useState(null)
      const [detail, setDetail] = useState(null)
      const [recent, setRecent] = useState(() => readStored(RECENT_KEY, []))
      const [showModules, setShowModules] = useState(false)
      const requestId = useRef(0)

      useEffect(() => {
        writeStored(FORM_KEY, { host, core, exe, key })
      }, [host, core, exe, key])

      const crashThread = report ? report.crashThread : null
      const threads = report && Array.isArray(report.threads) ? report.threads : []
      const activeThread = useMemo(
        () => threads.find(thread => thread.id === threadId) || threads.find(thread => thread.id === crashThread) || threads[0] || null,
        [threads, threadId, crashThread],
      )
      const frames = activeThread ? activeThread.frames || [] : []

      const connection = useMemo(
        () => ({ host: host.trim(), exe: exe.trim(), identityFile: key.trim() || undefined }),
        [host, exe, key],
      )

      const remember = useCallback((entry) => {
        setRecent(previous => {
          const next = [entry, ...previous.filter(item =>
            !(item.host === entry.host && item.core === entry.core))].slice(0, MAX_RECENT)
          writeStored(RECENT_KEY, next)
          return next
        })
      }, [])

      const runParse = useCallback(async (overrides) => {
        const target = overrides || {}
        const hostValue = (target.host !== undefined ? target.host : host).trim()
        const coreValue = (target.core !== undefined ? target.core : core).trim()
        const exeValue = (target.exe !== undefined ? target.exe : exe).trim()
        if (hostValue === '' || coreValue === '') {
          setError({ code: 'BAD_ARGS', message: t('error.title') + ': host / core' })
          return
        }
        const ticket = ++requestId.current
        setBusy('parse')
        setError(null)
        setDetail(null)
        setFrameIndex(null)
        try {
          const payload = await postJson(API.parse, {
            host: hostValue,
            core: coreValue,
            exe: exeValue || undefined,
            identityFile: (target.key !== undefined ? target.key : key).trim() || undefined,
          })
          if (ticket !== requestId.current) return
          if (payload.ok === false) {
            setError(payload.error)
            setReport(null)
            return
          }
          const nextReport = payload.report
          setReport(nextReport)
          setThreadId(nextReport.crashThread ?? (nextReport.threads?.[0]?.id ?? null))
          remember({ host: hostValue, core: coreValue, exe: exeValue, key: key.trim(), at: Date.now() })
        } catch (failure) {
          if (ticket !== requestId.current) return
          setError({ code: 'NETWORK', message: String(failure && failure.message ? failure.message : failure) })
        } finally {
          if (ticket === requestId.current) setBusy(null)
        }
      }, [host, core, exe, key, remember, t])

      const runFind = useCallback(async () => {
        if (host.trim() === '') {
          setError({ code: 'BAD_ARGS', message: t('error.title') + ': host' })
          return
        }
        const ticket = ++requestId.current
        setBusy('find')
        setError(null)
        setFound(null)
        try {
          const payload = await postJson(API.find, {
            host: host.trim(),
            identityFile: key.trim() || undefined,
          })
          if (ticket !== requestId.current) return
          if (payload.ok === false) {
            setError(payload.error)
            return
          }
          setFound(payload)
        } catch (failure) {
          if (ticket !== requestId.current) return
          setError({ code: 'NETWORK', message: String(failure && failure.message ? failure.message : failure) })
        } finally {
          if (ticket === requestId.current) setBusy(null)
        }
      }, [host, key, t])

      const openFrame = useCallback(async (thread, index) => {
        if (!report || !activeThread) return
        setThreadId(thread)
        setFrameIndex(index)
        setDetail(null)
        const ticket = ++requestId.current
        setBusy('frame')
        setError(null)
        try {
          const payload = await postJson(API.frame, {
            host: connection.host,
            core: report.target?.core || core.trim(),
            exe: connection.exe || report.target?.exe || undefined,
            identityFile: connection.identityFile,
            thread,
            frame: index,
          })
          if (ticket !== requestId.current) return
          if (payload.ok === false) {
            setError(payload.error)
            return
          }
          setDetail(payload.detail)
        } catch (failure) {
          if (ticket !== requestId.current) return
          setError({ code: 'NETWORK', message: String(failure && failure.message ? failure.message : failure) })
        } finally {
          if (ticket === requestId.current) setBusy(null)
        }
      }, [report, activeThread, connection, core, t])

      const chooseRecent = useCallback((entry) => {
        setHost(entry.host || '')
        setCore(entry.core || '')
        setExe(entry.exe || '')
        if (entry.key) setKey(entry.key)
        runParse({ host: entry.host, core: entry.core, exe: entry.exe, key: entry.key || key })
      }, [runParse, key])

      const clearRecent = useCallback(() => {
        setRecent([])
        writeStored(RECENT_KEY, [])
      }, [])

      const signal = report && report.signal
      const crash = report && report.crash
      const instruction = crash && crash.instruction
      const diagnostics = report && Array.isArray(report.diagnostics) ? report.diagnostics : []
      const modules = report && Array.isArray(report.modules) ? report.modules : []

      return h('div', { className: 'dcd-root', 'data-dsh-plugin': PANEL_ID },
        h('style', null, CSS),

        h('div', { className: 'dcd-head' },
          h('div', null,
            h('h2', { className: 'dcd-title' }, t('panel.title')),
            h('p', { className: 'dcd-sub' }, t('panel.subtitle')),
          ),
        ),

        h('div', { className: 'dcd-card' },
          h('div', { className: 'dcd-grid' },
            h(Field, {
              label: t('form.host'),
              value: host,
              placeholder: t('form.host.placeholder'),
              onChange: setHost,
              onEnter: () => runParse(),
            }),
            h(Field, {
              label: t('form.core'),
              value: core,
              placeholder: t('form.core.placeholder'),
              onChange: setCore,
              onEnter: () => runParse(),
            }),
            h(Field, {
              label: t('form.exe'),
              value: exe,
              placeholder: t('form.exe.placeholder'),
              onChange: setExe,
              onEnter: () => runParse(),
            }),
            h(Field, {
              label: t('form.key'),
              value: key,
              placeholder: t('form.key.placeholder'),
              onChange: setKey,
            }),
          ),
          h('div', { className: 'dcd-muted', style: { marginTop: 8, fontSize: 12 } }, t('form.hint')),
          h('div', { className: 'dcd-row end', style: { marginTop: 12 } },
            h('button', {
              className: 'dcd-btn',
              type: 'button',
              disabled: busy !== null,
              onClick: runFind,
            }, busy === 'find' ? t('state.busy.find') : t('action.find')),
            h('button', {
              className: 'dcd-btn primary',
              type: 'button',
              disabled: busy !== null,
              'aria-busy': busy === 'parse' ? 'true' : 'false',
              onClick: () => runParse(),
            }, busy === 'parse' ? t('state.busy.parse') : t('action.parse')),
          ),
          recent.length > 0
            ? h('div', { className: 'dcd-chips' },
              h('span', { className: 'dcd-muted' }, t('recent.title')),
              recent.map(entry => h('button', {
                key: `${entry.host}|${entry.core}`,
                type: 'button',
                className: 'dcd-chip',
                title: `${entry.host}:${entry.core}`,
                onClick: () => chooseRecent(entry),
              },
                h('span', { className: 'path' }, `${entry.host}:${entry.core}`),
              )),
              h('button', { type: 'button', className: 'dcd-btn ghost', onClick: clearRecent }, t('recent.clear')),
            )
            : null,
        ),

        error
          ? h('div', { className: 'dcd-error' },
            h('div', null, h('span', { className: 'code' }, `${error.code || 'ERROR'}：`), error.message),
            error.hint ? h('div', { className: 'dcd-muted', style: { marginTop: 4 } }, error.hint) : null,
          )
          : null,

        busy === 'parse' || busy === 'frame'
          ? h('div', { className: 'dcd-status' }, busy === 'parse' ? t('state.busy.parse') : t('state.busy.frame'))
          : null,

        found
          ? h('div', { className: 'dcd-card dcd-collapse' },
            h('div', { className: 'dcd-summary' },
              found.pattern ? h('span', { className: 'dcd-badge' }, `${t('find.pattern')}: ${found.pattern}`) : null,
              found.ulimit ? h('span', { className: 'dcd-badge' }, `${t('find.ulimit')}: ${found.ulimit}`) : null,
            ),
            found.coredumpctl
              ? h(Section, { title: t('find.ctl') },
                h('pre', { className: 'dcd-mono', style: { margin: 0, overflow: 'auto', maxHeight: 160 } }, found.coredumpctl))
              : null,
            h(Section, { title: `${t('find.rows')} (${found.rows ? found.rows.length : 0})` },
              found.rows && found.rows.length > 0
                ? h('div', { className: 'dcd-rows' }, found.rows.map(row => h('div', {
                  key: row.path,
                  className: 'dcd-rowitem',
                },
                  h('span', { className: 'dcd-muted dcd-mono' }, humanSize(row.sizeBytes)),
                  h('span', { className: 'dcd-muted dcd-mono' }, row.mtime),
                  h('span', { className: 'grow dcd-mono', title: row.path }, row.path),
                  h('button', {
                    type: 'button',
                    className: 'dcd-btn',
                    disabled: busy !== null,
                    onClick: () => {
                      setCore(row.path)
                      runParse({ core: row.path })
                    },
                  }, t('action.open')),
                )))
                : h('div', { className: 'dcd-muted' }, t('find.none')),
            ),
          )
          : null,

        !report && !found && !error
          ? h('div', { className: 'dcd-empty' },
            h('div', { style: { fontWeight: 600, marginBottom: 4 } }, t('empty.title')),
            h('div', null, t('empty.hint')),
          )
          : null,

        report
          ? h('div', null,
            h('div', { className: 'dcd-summary' },
              signal
                ? h('span', { className: 'dcd-badge signal' }, `${signal.name}`)
                : h('span', { className: 'dcd-badge' }, t('result.signal')),
              instruction
                ? h('span', { className: 'dcd-badge dcd-mono' }, `${instruction.address} ${instruction.text}`)
                : null,
              h('span', { className: 'dcd-badge' }, `${t('result.threadsCount')}: ${threads.length}`),
              report.target && report.target.arch
                ? h('span', { className: 'dcd-badge' }, `${t('result.arch')}: ${report.target.arch}`)
                : null,
              report.target && report.target.generatedBy
                ? h('span', { className: 'dcd-badge dcd-mono', title: report.target.generatedBy },
                  `${t('result.generatedBy')}: ${clip(report.target.generatedBy, 42)}`)
                : null,
              h('button', {
                type: 'button',
                className: 'dcd-btn ghost',
                disabled: busy !== null,
                onClick: () => runParse(),
              }, t('action.refresh')),
            ),

            report.trusted === false ? h('p', { className: 'dcd-warn' }, t('result.untrusted')) : null,

            h('div', { className: 'dcd-split' },
              h('div', { className: 'dcd-panel' },
                h('header', null,
                  h('span', null, t('result.threads')),
                  h('span', null, String(threads.length)),
                ),
                h('div', { className: 'dcd-threads' },
                  threads.map(thread => h('button', {
                    key: thread.id,
                    type: 'button',
                    className: 'dcd-thread',
                    'data-active': activeThread && thread.id === activeThread.id ? 'true' : 'false',
                    onClick: () => {
                      setThreadId(thread.id)
                      setFrameIndex(null)
                      setDetail(null)
                    },
                  },
                    h('span', { className: `dcd-dot${thread.id === crashThread ? ' crash' : ''}` }),
                    h('span', null, `#${thread.id}`),
                    thread.lwp ? h('span', { className: 'dcd-muted dcd-mono' }, `LWP ${thread.lwp}`) : null,
                    thread.id === crashThread
                      ? h('span', { className: 'dcd-badge', style: { marginLeft: 'auto' } }, t('result.crash'))
                      : null,
                  )),
                ),
              ),
              h('div', { className: 'dcd-panel' },
                h('header', null,
                  h('span', null, activeThread ? `${t('result.frames')} · #${activeThread.id}` : t('result.frames')),
                  h('span', null, String(frames.length)),
                ),
                h('div', { className: 'dcd-frames' },
                  frames.length > 0
                    ? frames.map(frame => h('button', {
                      key: frameKey(activeThread.id, frame.index),
                      type: 'button',
                      className: 'dcd-frame',
                      title: `${frame.address || ''} ${frame.symbol || ''} ${frame.source ? `${frame.source.file}:${frame.source.line}` : ''}`,
                      'data-active': activeThread.id === threadId && frame.index === frameIndex ? 'true' : 'false',
                      onClick: () => openFrame(activeThread.id, frame.index),
                    },
                      h('span', { className: 'idx' }, `#${frame.index}`),
                      h('span', null, frame.unresolved ? '??' : frame.symbol || '??'),
                      frame.source && frame.source.file
                        ? h('span', { className: 'src' }, `  ${frame.source.file}:${frame.source.line ?? '?'}`)
                        : frame.module
                          ? h('span', { className: 'src' }, `  ${frame.module}`)
                          : null,
                    ))
                    : h('div', { className: 'dcd-muted', style: { padding: '8px 10px' } }, t('result.noFrames')),
                ),
              ),
            ),

            detail
              ? h('div', { className: 'dcd-panel dcd-detail' },
                h('header', null,
                  h('span', null,
                    `${t('result.detail')} · #${detail.thread} #${detail.currentFrame?.index ?? detail.frame} ${detail.currentFrame?.symbol || ''}`),
                  h('button', {
                    type: 'button',
                    className: 'dcd-btn ghost',
                    onClick: () => {
                      setDetail(null)
                      setFrameIndex(null)
                    },
                  }, t('result.closeDetail')),
                ),
                Object.keys(detail.registers || {}).length > 0
                  ? h(Section, { title: t('result.registers') },
                    h('div', { className: 'dcd-regs dcd-mono' },
                      Object.entries(detail.registers).map(([name, value]) =>
                        h('span', { key: name }, `${name}=${value}`))))
                  : null,
                Array.isArray(detail.args) && detail.args.length > 0
                  ? h(Section, { title: t('result.args') },
                    h(KeyValues, {
                      pairs: detail.args.map(item => [item.name, clip(item.value, 160)]),
                    }))
                  : null,
                Array.isArray(detail.locals) && detail.locals.length > 0
                  ? h(Section, { title: t('result.locals') },
                    h(KeyValues, {
                      pairs: detail.locals.map(item => [item.name, clip(item.value, 160)]),
                    }))
                  : null,
                Array.isArray(detail.disassembly) && detail.disassembly.length > 0
                  ? h(Section, { title: t('result.disasm') }, h(Disassembly, { items: detail.disassembly }))
                  : null,
                detail.source && detail.source.lines && detail.source.lines.length > 0
                  ? h(Section, { title: `${t('result.source')}${detail.source.file ? ` · ${detail.source.file}` : ''}` },
                    h(SourceWindow, { source: detail.source }))
                  : null,
                Array.isArray(detail.diagnostics) && detail.diagnostics.length > 0
                  ? h(Section, { title: t('result.diagnostics') },
                    detail.diagnostics.map((item, index) => h('div', {
                      key: `${item.code}-${index}`,
                      className: 'dcd-diag',
                      'data-sev': item.severity || 'info',
                    },
                      h('span', { className: 'sev' }, item.severity || 'info'),
                      h('span', null, `${item.code}：${item.message}`),
                    )))
                  : null,
              )
              : null,

            diagnostics.length > 0
              ? h('div', { className: 'dcd-card dcd-collapse' },
                h(Section, { title: t('result.diagnostics') },
                  diagnostics.map((item, index) => h('div', {
                    key: `${item.code}-${index}`,
                    className: 'dcd-diag',
                    'data-sev': item.severity || 'info',
                  },
                    h('span', { className: 'sev' }, item.severity || 'info'),
                    h('span', null, `${item.code}：${item.message}`,
                      item.hint ? h('div', { className: 'dcd-muted' }, item.hint) : null),
                  ))),
              )
              : null,

            modules.length > 0
              ? h('div', { className: 'dcd-card dcd-collapse' },
                h('button', {
                  type: 'button',
                  className: 'dcd-btn ghost',
                  onClick: () => setShowModules(value => !value),
                }, h(ChevronIcon, { open: showModules }), ` ${t('result.modules')} (${modules.length})`),
                showModules
                  ? h(Section, null,
                    h('div', null, modules.map(module => h('div', {
                      key: module.path,
                      className: 'dcd-rowitem',
                    },
                      h('span', {
                        className: 'dcd-badge',
                        style: module.symbolsLoaded === false
                          ? { color: 'var(--dsw-alias-state-warn-primary)' }
                          : { color: 'var(--dsw-alias-state-success-primary)' },
                      }, module.symbolsLoaded === false ? '✗' : '✓'),
                      h('span', { className: 'grow dcd-mono', title: module.path }, module.path),
                      module.buildId ? h('span', { className: 'dcd-muted dcd-mono' }, clip(module.buildId, 16)) : null,
                    ))))
                  : null,
              )
              : null,
          )
          : null,
      )
    }

    /** Wrapper the slot mounts; inject supplies the translate seat. */
    function CoredumpPage({ t }) {
      return h(CoredumpPanel, { t })
    }

    // -----------------------------------------------------------------------
    // Plugin entry
    // -----------------------------------------------------------------------

    const inject = ['slots', 'locale']

    function apply(ctx) {
      const ns = NS

      // Dictionaries first: slots read `t` the moment they render.
      const registerDict = (locale, dict) => {
        try {
          const dispose = ctx.locale && ctx.locale.register
            ? ctx.locale.register(ns, locale, dict)
            : undefined
          return dispose || (() => {})
        } catch {
          return () => {}
        }
      }
      if (typeof ctx.effect === 'function') {
        ctx.effect(() => {
          const disposers = [registerDict('zh', ZH), registerDict('en', EN)]
          return () => {
            for (const dispose of disposers) dispose()
          }
        }, 'dsh-coredump: locale')
      } else {
        registerDict('zh', ZH)
        registerDict('en', EN)
      }

      let bound
      try {
        bound = ctx.locale && ctx.locale.bind ? ctx.locale.bind(ns) : undefined
      } catch {
        bound = undefined
      }
      const t = (key, params) => {
        let value
        try {
          value = bound ? bound(key, params) : undefined
        } catch {
          value = undefined
        }
        if (value === undefined || value === null || value === key) {
          // Locale registration can be refused on an older host; fall back to
          // the dictionary that matches the active language, then to zh.
          let active = ''
          try {
            active = (ctx.locale && ctx.locale.getLocale ? ctx.locale.getLocale().active : '') || ''
          } catch {
            active = ''
          }
          const dict = active.toLowerCase().startsWith('zh') ? ZH : EN
          value = dict[key] ?? ZH[key] ?? key
        }
        return applyParams(value, params)
      }

      const slots = ctx.slots
      const disposers = []

      // Panel row: the owner renders the icon and switches the main panel; the
      // list id and the main key must be the same string.
      disposers.push(slots.inject('sidebar.panellist', () => slots.register({
        name: 'sidebar.panellist',
        id: PANEL_ID,
        order: PANEL_ORDER,
        label: () => t('meta.title'),
      }, CoredumpIcon)))

      disposers.push(slots.inject('main', () => slots.register({
        name: 'main',
        key: PANEL_ID,
        inject: () => ({ t }),
      }, CoredumpPage)))

      return () => {
        for (const dispose of disposers) {
          try {
            dispose()
          } catch {
            /* already released */
          }
        }
      }
    }

    return { inject, apply }
  },
})
