/**
 * SSH transport for the coredump plugin.
 *
 * Deliberate design choice: we drive the system `ssh` client instead of
 * re-implementing SSH. That reuses ~/.ssh/config (aliases, IdentityFile,
 * ProxyJump, ssh-agent, known_hosts) for free and keeps the plugin completely
 * free of credential handling — it never reads a key, a password, or ssh.json.
 *
 * Multi-hop: `jumps` becomes a single `-J a,b,c` argument, i.e. OpenSSH's own
 * jump-host semantics (including per-hop user/port). An alias that ALREADY has
 * ProxyJump in ~/.ssh/config keeps working untouched.
 */

import { spawn } from 'node:child_process'
import os from 'node:os'
import path from 'node:path'

/** Cap on stdout held in memory; a huge core can produce a huge gdb transcript. */
const MAX_STDOUT = 64 * 1024 * 1024
/** stderr is diagnostic only; keep it short. */
const MAX_STDERR = 16 * 1024

const SSH_BIN = process.env.DSH_COREDUMP_SSH || 'ssh'

/**
 * Expand a leading `~` in a LOCAL path. `ssh -i` does not expand it on Windows,
 * and the panel accepts what people naturally type (`~/.ssh/id_ed25519`).
 * Remote paths are never passed through this.
 * @param {string} value - local path.
 * @returns {string} absolute-ish path.
 */
export function expandHome(value) {
  const text = String(value ?? '')
  if (text === '~') return os.homedir()
  if (text.startsWith('~/') || text.startsWith('~\\')) return path.join(os.homedir(), text.slice(2))
  return text
}

/** POSIX single-quote a value for the remote shell. */
export function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'"
}

/**
 * Build the local `ssh` argv (everything before the remote command).
 * @param {object} options
 * @param {string} options.host - alias or destination (`user@host`).
 * @param {string} [options.user] - explicit user, merged into the destination.
 * @param {number} [options.port] - ssh -p.
 * @param {string[]} [options.jumps] - jump hosts, ssh -J.
 * @param {string} [options.identityFile] - explicit key.
 * @param {string} [options.strictHostKeyChecking] - default `accept-new`.
 * @returns {string[]} helper ssh arguments.
 */
export function buildSshArgs(options) {
  const args = [
    '-T',
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=30',
    '-o', `StrictHostKeyChecking=${options.strictHostKeyChecking || 'accept-new'}`,
  ]
  if (options.port) args.push('-p', String(options.port))
  if (options.identityFile) args.push('-i', expandHome(options.identityFile))
  if (Array.isArray(options.jumps) && options.jumps.length > 0) {
    args.push('-J', options.jumps.join(','))
  }
  const host = String(options.host)
  const destination = options.user && !host.includes('@') ? `${options.user}@${host}` : host
  args.push(destination)
  return args
}

/**
 * Build the remote command line: `python3 - --core '...' ...`.
 * The engine script is fed on stdin, so arguments must come after the `-`.
 * @param {object} options
 * @returns {string} the remote command.
 */
export function buildRemoteCommand(options) {
  const parts = [options.python || 'python3', '-']
  parts.push('--core', shellQuote(options.core))
  if (options.exe) parts.push('--exe', shellQuote(options.exe))
  if (Array.isArray(options.symbolDirs) && options.symbolDirs.length > 0) {
    parts.push('--symbol-dirs', shellQuote(options.symbolDirs.join(':')))
  }
  parts.push('--max-frames', String(options.maxFrames))
  parts.push('--timeout', String(options.remoteTimeout))
  if (options.thread !== undefined && options.thread !== null) {
    parts.push('--thread', String(options.thread))
    if (options.frame !== undefined && options.frame !== null) {
      parts.push('--frame', String(options.frame))
    }
  }
  return parts.join(' ')
}

/**
 * Run ssh with optional stdin payload (the engine script, or nothing for a
 * plain remote command such as the core-file scan).
 * @param {object} options
 * @param {string[]} options.args - ssh argv from {@link buildSshArgs}.
 * @param {string} options.remoteCommand - remote command string.
 * @param {string} [options.script] - engine source, piped to the remote interpreter.
 * @param {number} options.timeoutMs - local wall-clock limit.
 * @param {AbortSignal} [options.signal] - caller cancellation.
 * @returns {Promise<{code:number|null, stdout:string, stderr:string, timedOut:boolean}>}
 */
export function runSsh(options) {
  return new Promise((resolve, reject) => {
    let child
    try {
      child = spawn(SSH_BIN, [...options.args, options.remoteCommand], {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch (error) {
      reject(error)
      return
    }

    let stdout = ''
    let stderr = ''
    let settled = false
    let timedOut = false
    let timer

    const cleanup = () => {
      if (timer) clearTimeout(timer)
      if (options.signal) options.signal.removeEventListener('abort', onAbort)
    }
    const settle = (payload) => {
      if (settled) return
      settled = true
      cleanup()
      resolve(payload)
    }
    const fail = (error) => {
      if (settled) return
      settled = true
      cleanup()
      reject(error)
    }
    const onAbort = () => {
      child.kill()
    }

    child.on('error', fail)
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      if (stdout.length < MAX_STDOUT) stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      if (stderr.length < MAX_STDERR) stderr += chunk
    })
    child.stdin.on('error', () => {
      // ssh may exit before consuming the script; the close handler reports it.
    })
    child.stdin.end(options.script === undefined ? '' : options.script)

    timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, options.timeoutMs)
    if (options.signal) {
      if (options.signal.aborted) child.kill()
      else options.signal.addEventListener('abort', onAbort)
    }

    child.on('close', (code) => {
      settle({ code, stdout, stderr, timedOut })
    })
  })
}

/**
 * Run a plain remote shell command (no stdin payload).
 * @param {object} options - {@link runSsh} options; `script` is unused.
 * @returns {Promise<{code:number|null, stdout:string, stderr:string, timedOut:boolean}>}
 */
export function runSshCommand(options) {
  return runSsh({ ...options, script: '' })
}

/**
 * Turn ssh's stderr into an actionable error code + hint.
 * @param {string} stderr - ssh diagnostics.
 * @returns {{code: string, hint: string}}
 */
export function classifySshError(stderr) {
  const text = String(stderr || '').toLowerCase()
  if (text.includes('permission denied')) {
    return {
      code: 'SSH_AUTH_FAILED',
      hint: '插件不使用密码登录。确认 ~/.ssh/config 的 IdentityFile / ProxyJump 正确，或先手工 `ssh 主机 true` 连通；「私钥」参数要填私钥文件路径（不是密码），纯密码主机先用 ssh-copy-id 装公钥。',
    }
  }
  if (text.includes('host key verification failed')) {
    return {
      code: 'SSH_HOSTKEY',
      hint: '先手工 ssh 一次确认并记录主机指纹（known_hosts），再重试。',
    }
  }
  if (text.includes('could not resolve hostname') || text.includes('name or service not known')) {
    return { code: 'SSH_UNREACHABLE', hint: '检查 host / jumps 的主机名与 DNS/网络可达性。' }
  }
  if (text.includes('connection refused') || text.includes('no route to host')) {
    return { code: 'SSH_UNREACHABLE', hint: '目标端口不可达：检查跳板机链路和 sshd 状态。' }
  }
  if (text.includes('timed out')) {
    return { code: 'SSH_TIMEOUT', hint: '连接超时：确认跳板机可达，或把 timeoutMs 调大。' }
  }
  return {
    code: 'SSH_FAILED',
    hint: '先手工验证链路：ssh [-J 跳板] 主机 "python3 --version"。',
  }
}
