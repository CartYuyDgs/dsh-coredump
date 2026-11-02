/**
 * One ssh round-trip that runs the bundled engine on the remote host.
 *
 * The engine script travels on stdin (`python3 - --core ...`), so the remote
 * side needs no installation and always runs the version this plugin shipped.
 * Every tool goes through this module: connection handling, timeout headroom,
 * JSON extraction and ssh-error classification live here exactly once.
 */

import { readFile } from 'node:fs/promises'
import { DEFAULT_PYTHON, engineScriptPath } from './config.js'
import { buildRemoteCommand, buildSshArgs, classifySshError, runSsh } from './ssh.js'
import { parseEngineOutput } from './output.js'

/** Local wall clock must outlast the remote gdb timeout so we get a report. */
const REMOTE_HEADROOM_SECONDS = 25

/**
 * Run the engine against one remote core.
 * @param {object} options
 * @param {object} options.ssh - {@link import('./tool-kit.js').sshOptions} result.
 * @param {string} options.core - remote core path.
 * @param {string} [options.exe] - remote binary path.
 * @param {string[]} [options.symbolDirs] - extra remote symbol directories.
 * @param {number} [options.maxFrames] - frames per thread.
 * @param {number} [options.thread] - frame-detail mode: thread id.
 * @param {number} [options.frame] - frame-detail mode: frame index.
 * @param {number} options.timeoutMs - local limit.
 * @param {AbortSignal} [options.signal] - caller cancellation.
 * @returns {Promise<{ok: true, report: object} | {ok: false, code: string, message: string, hint?: string}>}
 */
export async function runEngine(options) {
  let script
  try {
    script = await readFile(engineScriptPath(), 'utf8')
  } catch (error) {
    return {
      ok: false,
      code: 'ENGINE_MISSING',
      message: `插件自带引擎读取失败：${error.message}`,
      hint: '重新安装插件包。',
    }
  }

  const sshArgs = buildSshArgs(options.ssh)
  const remoteCommand = buildRemoteCommand({
    python: DEFAULT_PYTHON,
    core: options.core,
    exe: options.exe,
    symbolDirs: options.symbolDirs,
    maxFrames: options.maxFrames,
    thread: options.thread,
    frame: options.frame,
    remoteTimeout: remoteTimeoutFor(options.timeoutMs),
  })

  let result
  try {
    result = await runSsh({
      args: sshArgs,
      remoteCommand,
      script,
      timeoutMs: options.timeoutMs,
      signal: options.signal,
    })
  } catch (error) {
    return {
      ok: false,
      code: 'SSH_SPAWN_FAILED',
      message: `无法启动 ssh 客户端：${error?.message ?? error}`,
      hint: '确认本机 OpenSSH 客户端可执行（ssh -V）。',
    }
  }

  if (result.timedOut) {
    return {
      ok: false,
      code: 'SSH_TIMEOUT',
      message: `等待超时（${Math.round(options.timeoutMs / 1000)} 秒）`,
      hint: 'core 很大时调大 timeoutMs；或先手工在远端跑一次 gdb 确认不是符号路径问题。',
    }
  }

  const stderr = result.stderr.trim()
  if (!result.stdout.trim()) {
    const classified = classifySshError(stderr)
    return {
      ok: false,
      code: classified.code,
      message: stderr ? `ssh: ${stderr.slice(0, 800)}` : '远端没有返回任何报告',
      hint: classified.hint,
    }
  }

  const report = parseEngineOutput(result.stdout)
  if (report === undefined) {
    return {
      ok: false,
      code: 'ENGINE_BAD_OUTPUT',
      message: '无法解析远端引擎输出（不是 JSON）',
      hint: stderr ? `远端 stderr：${stderr.slice(0, 600)}` : '远端输出被日志污染。',
    }
  }

  if (report.ok === false) {
    const error = report.error || {}
    return {
      ok: false,
      code: String(error.code || 'ENGINE_ERROR'),
      message: String(error.message || '解析失败'),
      hint: error.hint ? String(error.hint) : undefined,
    }
  }
  return { ok: true, report }
}

/** Seconds the remote gdb may run before the local ssh timeout fires. */
export function remoteTimeoutFor(timeoutMs) {
  return Math.max(20, Math.floor(timeoutMs / 1000) - REMOTE_HEADROOM_SECONDS)
}
