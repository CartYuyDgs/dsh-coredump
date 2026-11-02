/**
 * Browser routes for the coredump panel: `/api/dsh-coredump/*`.
 *
 * The panel is a plain browser page, so it cannot call the agent tools. These
 * three routes are the panel's only data path; they reuse the exact same engine
 * runner as the tools, so a stack shown in the panel and a stack returned to
 * the model cannot drift apart.
 *
 * Trust fence: loopback socket + loopback Host header + same-origin markers.
 * The panel talks to local machines and can read a coredump's memory, so it is
 * deliberately not exposed to a LAN browser.
 */

import { runEngine } from './engine-run.js'
import { buildScanCommand, parseCoreRows } from './find-tool.js'
import { splitSections } from './output.js'
import { buildSshArgs, runSshCommand } from './ssh.js'

/** Route family registered on the host web server. */
export const ROUTE_PATHS = {
  find: '/api/dsh-coredump/find',
  parse: '/api/dsh-coredump/parse',
  frame: '/api/dsh-coredump/frame',
}

/** Maximum JSON request body; the panel only sends short parameter objects. */
const MAX_BODY_BYTES = 1024 * 1024

/** IPv4 127/8 predicate. */
function isIPv4Loopback(value) {
  const parts = value.split('.')
  return parts.length === 4
    && parts[0] === '127'
    && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

/** Whether a socket remote address names the loopback range. */
function isLoopbackAddress(address) {
  if (address === undefined) return false
  const normalized = address.toLowerCase()
  if (normalized === '::1') return true
  if (normalized.startsWith('::ffff:')) return isIPv4Loopback(normalized.slice(7))
  return isIPv4Loopback(normalized)
}

/** Whether a URL hostname names the loopback authority. */
function isLoopbackHostname(hostname) {
  if (hostname === 'localhost' || hostname === '[::1]') return true
  return isIPv4Loopback(hostname)
}

/**
 * Request-level trust fence: loopback socket AND loopback Host header AND no
 * cross-site browser marker. The socket address is authoritative.
 * @param {import('node:http').IncomingMessage} request
 * @returns {boolean}
 */
export function isLoopbackRequest(request) {
  if (!isLoopbackAddress(request.socket?.remoteAddress)) return false
  const host = request.headers.host
  if (typeof host !== 'string') return false
  let hostUrl
  try {
    hostUrl = new URL('http://' + host)
  } catch {
    return false
  }
  if (!isLoopbackHostname(hostUrl.hostname)) return false
  if (request.headers['sec-fetch-site'] === 'cross-site') return false
  const origin = request.headers.origin
  if (origin === undefined) return true
  try {
    return new URL(origin).host === hostUrl.host
  } catch {
    return false
  }
}

/** Write one JSON response. */
function writeJson(res, status, value) {
  const payload = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  })
  res.end(payload)
}

/** Read a bounded JSON body; `undefined` means "not valid JSON". */
function readJsonBody(request) {
  return new Promise((resolve) => {
    let size = 0
    const chunks = []
    request.on('data', (chunk) => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        resolve(undefined)
        request.destroy()
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      if (chunks.length === 0) {
        resolve({})
        return
      }
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        resolve(parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : undefined)
      } catch {
        resolve(undefined)
      }
    })
    request.on('error', () => resolve(undefined))
  })
}

/** Small helpers shared by the handlers. */
function text(value) {
  return String(value ?? '').trim()
}

function int(value, fallback, min, max) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return fallback
  const integer = Math.trunc(parsed)
  if (min !== undefined && integer < min) return min
  if (max !== undefined && integer > max) return max
  return integer
}

function list(value) {
  if (value === undefined || value === null || value === '') return []
  const items = Array.isArray(value) ? value : String(value).split(',')
  return items.map(item => String(item ?? '').trim()).filter(item => item !== '')
}

/** SSH options from a request body. */
function sshOptions(body) {
  return {
    host: text(body.host),
    user: text(body.user) || undefined,
    port: body.port === undefined || body.port === '' ? undefined : int(body.port, 22, 1, 65535),
    jumps: list(body.jumps),
    identityFile: text(body.identityFile) || undefined,
    strictHostKeyChecking: text(body.strictHostKeyChecking) || undefined,
  }
}

/** Shared guard: loopback fence + POST + JSON content type. */
function guard(request, res) {
  if (!isLoopbackRequest(request)) {
    writeJson(res, 403, { ok: false, error: { code: 'FORBIDDEN', message: '只接受本机（loopback）请求。' } })
    return false
  }
  if ((request.method ?? 'GET') !== 'POST') {
    writeJson(res, 405, { ok: false, error: { code: 'METHOD_NOT_ALLOWED', message: `method not allowed: ${request.method}` } })
    return false
  }
  return true
}

/** Map an engine/ssh failure onto the response shape the panel renders. */
function failure(res, outcome) {
  writeJson(res, 200, {
    ok: false,
    error: { code: outcome.code, message: outcome.message, hint: outcome.hint },
  })
}

/** `POST /api/dsh-coredump/find` */
async function handleFind(request, res) {
  const body = await readJsonBody(request)
  if (body === undefined) {
    writeJson(res, 400, { ok: false, error: { code: 'BAD_BODY', message: '请求体不是合法 JSON。' } })
    return
  }
  if (text(body.host) === '') {
    writeJson(res, 400, { ok: false, error: { code: 'BAD_ARGS', message: 'host 必填。' } })
    return
  }
  const timeoutMs = int(body.timeoutMs, 20000, 5000, 120000)
  let result
  try {
    result = await runSshCommand({
      args: buildSshArgs(sshOptions(body)),
      remoteCommand: buildScanCommand(list(body.dirs)),
      timeoutMs,
    })
  } catch (error) {
    failure(res, { code: 'SSH_SPAWN_FAILED', message: `无法启动 ssh 客户端：${error?.message ?? error}` })
    return
  }
  if (result.timedOut) {
    failure(res, { code: 'SSH_TIMEOUT', message: `扫描超时（${Math.round(timeoutMs / 1000)} 秒）。`, hint: '缩小扫描目录或调大超时。' })
    return
  }
  if (!result.stdout.trim()) {
    const stderr = result.stderr.trim()
    failure(res, {
      code: 'SSH_FAILED',
      message: stderr ? `ssh: ${stderr.slice(0, 500)}` : '远端没有返回任何内容。',
      hint: '确认密钥 / 主机可达；插件不支持密码登录。',
    })
    return
  }
  const sections = splitSections(result.stdout)
  const rows = parseCoreRows(sections.files).slice(0, 40)
  writeJson(res, 200, {
    ok: true,
    pattern: (sections.pattern || '').trim(),
    ulimit: (sections.limits || '').trim(),
    coredumpctl: (sections.coredumpctl || '').trim(),
    rows,
  })
}

/** `POST /api/dsh-coredump/parse` */
async function handleParse(request, res) {
  const body = await readJsonBody(request)
  if (body === undefined) {
    writeJson(res, 400, { ok: false, error: { code: 'BAD_BODY', message: '请求体不是合法 JSON。' } })
    return
  }
  if (text(body.host) === '' || text(body.core) === '') {
    writeJson(res, 400, { ok: false, error: { code: 'BAD_ARGS', message: 'host 与 core 必填。' } })
    return
  }
  const outcome = await runEngine({
    ssh: sshOptions(body),
    core: text(body.core),
    exe: text(body.exe) || undefined,
    symbolDirs: list(body.symbolDirs),
    maxFrames: int(body.maxFrames, 40, 1, 500),
    timeoutMs: int(body.timeoutMs, 180000, 10000, 900000),
  })
  if (!outcome.ok) {
    failure(res, outcome)
    return
  }
  writeJson(res, 200, { ok: true, report: outcome.report })
}

/** `POST /api/dsh-coredump/frame` */
async function handleFrame(request, res) {
  const body = await readJsonBody(request)
  if (body === undefined) {
    writeJson(res, 400, { ok: false, error: { code: 'BAD_BODY', message: '请求体不是合法 JSON。' } })
    return
  }
  if (text(body.host) === '' || text(body.core) === '') {
    writeJson(res, 400, { ok: false, error: { code: 'BAD_ARGS', message: 'host 与 core 必填。' } })
    return
  }
  const thread = int(body.thread, 0, 0, 1e6)
  const frame = int(body.frame, 0, 0, 10000)
  const outcome = await runEngine({
    ssh: sshOptions(body),
    core: text(body.core),
    exe: text(body.exe) || undefined,
    symbolDirs: list(body.symbolDirs),
    maxFrames: 5,
    thread,
    frame,
    timeoutMs: int(body.timeoutMs, 180000, 10000, 900000),
  })
  if (!outcome.ok) {
    failure(res, outcome)
    return
  }
  writeJson(res, 200, { ok: true, detail: outcome.report })
}

/**
 * Build the route list for `webServer.register`.
 * @returns {Array<{kind: 'exact', path: string, handler: Function}>}
 */
export function makeRoutes() {
  return [
    { kind: 'exact', path: ROUTE_PATHS.find, handler: (req, res) => guard(req, res) && handleFind(req, res) },
    { kind: 'exact', path: ROUTE_PATHS.parse, handler: (req, res) => guard(req, res) && handleParse(req, res) },
    { kind: 'exact', path: ROUTE_PATHS.frame, handler: (req, res) => guard(req, res) && handleFrame(req, res) },
  ]
}
