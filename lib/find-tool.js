/**
 * The `coredump_find` agent tool.
 *
 * Answers the question that comes before every analysis: "which cores exist on
 * that box, and where does the kernel drop new ones?" One ssh round-trip, no
 * gdb, no engine — a listing must stay cheap even when the host is in pain.
 */

import { buildSshArgs, classifySshError, runSshCommand, shellQuote } from './ssh.js'
import { splitSections } from './output.js'
import { renderFailure } from './report.js'
import {
  SSH_PARAMETERS,
  objectSchema,
  optionalInteger,
  optionalStringArray,
  requiredString,
  sshOptions,
  textContent,
  toArray,
  toInt,
  toText,
  finish,
} from './tool-kit.js'

/** Directories that hold cores on systemd / abrt / debian-ish hosts. */
const DEFAULT_DIRS = ['/var/crash', '/var/lib/systemd/coredump', '/var/spool/abrt', '/root', '/tmp']

/** Cap on rendered rows; the model does not need 200 cores. */
const MAX_ROWS = 20

/**
 * Build the remote POSIX shell line. Sections are marked so one ssh call can
 * return the pattern, coredumpctl and the file list without guessing.
 * @param {string[]} dirs - directories to scan.
 * @returns {string} remote command.
 */
export function buildScanCommand(dirs) {
  const targets = dirs.length > 0 ? dirs : DEFAULT_DIRS
  // `do` must be followed by a command, not by `;` — so the loop body is one
  // string with the keyword inline (`for d in X; do <body>; done`).
  const loopBody = [
    '[ -d "$d" ] || continue',
    'find "$d" -maxdepth 4 -type f \\( -name core -o -name "core.*" -o -name "*.core" -o -name "vmcore*" -o -name "*.zst" \\) -printf "%s %TY-%Tm-%TdT%TH:%TM %p\\n" 2>/dev/null | head -n 40',
  ].join('; ')
  const scan = `for d in ${targets.map(shellQuote).join(' ')}; do ${loopBody}; done`
  return [
    'printf "@@cdparse:pattern@@\\n"',
    'cat /proc/sys/kernel/core_pattern 2>/dev/null',
    'printf "@@cdparse:limits@@\\n"',
    'ulimit -c 2>/dev/null',
    'printf "@@cdparse:coredumpctl@@\\n"',
    'if command -v coredumpctl >/dev/null 2>&1; then coredumpctl --no-pager list 2>/dev/null | tail -n 25; fi',
    'printf "@@cdparse:files@@\\n"',
    scan,
    'printf "@@cdparse:end@@\\n"',
  ].join('; ')
}

/** Parse the `<size> <time> <path>` rows produced by find. */
export function parseCoreRows(text) {
  const rows = []
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.match(/^(\d+)\s+(\S+)\s+(.+)$/)
    if (!match) continue
    rows.push({
      sizeBytes: Number(match[1]),
      mtime: match[2],
      path: match[3].trim(),
    })
  }
  rows.sort((left, right) => (right.mtime > left.mtime ? 1 : right.mtime < left.mtime ? -1 : 0))
  return rows
}

/** Human-readable size. */
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

/** Render the scan result. */
export function renderScan(host, sections) {
  const rows = parseCoreRows(sections.files).slice(0, MAX_ROWS)
  const lines = [`## 远端 core 文件：${host}`, '']
  const pattern = (sections.pattern || '').trim()
  lines.push(`- core_pattern：${pattern ? `\`${pattern}\`` : '（读不到）'}`)
  const limit = (sections.limits || '').trim()
  if (limit) lines.push(`- 当前 shell 的 ulimit -c：\`${limit}\``)

  const coredumpctl = (sections.coredumpctl || '').trim()
  if (coredumpctl) {
    lines.push('')
    lines.push('### coredumpctl list（最近 25 条）')
    lines.push('```')
    lines.push(coredumpctl)
    lines.push('```')
  }

  lines.push('')
  lines.push(`### 找到的 core（${rows.length} 个${rows.length >= MAX_ROWS ? '，已截断' : ''}）`)
  if (rows.length === 0) {
    lines.push('_默认扫描目录里没有 core 文件；可用 dirs 参数指定目录。_')
  } else {
    for (const row of rows) {
      lines.push(`- ${humanSize(row.sizeBytes)}  ${row.mtime}  \`${row.path}\``)
    }
  }
  lines.push('')
  lines.push('下一步：把要分析的路径交给 coredump_parse。')
  return lines.join('\n')
}

/** Create the tool definition. */
export function createFindTool() {
  return {
    name: 'coredump_find',
    description: '通过 SSH 在远端 Linux 主机上列出 coredump 文件：core_pattern、当前 ulimit -c、coredumpctl list、以及默认目录（/var/crash、/var/lib/systemd/coredump、/var/spool/abrt、/root、/tmp）里的 core。不跑 gdb，很快。用户不知道 core 在哪、或问“这台机器上有没有 core”时先用它，再拿路径给 coredump_parse。',
    parameters: objectSchema(
      {
        host: requiredString('SSH 别名（~/.ssh/config 里的 Host）或 user@host。'),
        dirs: optionalStringArray('要扫描的远端目录（额外/替换默认目录）；传了就只扫这些。'),
        timeoutMs: optionalInteger('ssh 超时毫秒（默认 20000）。'),
        ...SSH_PARAMETERS,
      },
      ['host'],
    ),
    output: {
      schema: objectSchema(
        {
          ok: { type: 'boolean' },
          host: { type: 'string' },
          corePattern: { type: 'string' },
          found: { type: 'integer' },
          markdown: { type: 'string' },
          error: { type: 'string' },
        },
        ['ok', 'markdown'],
      ),
      render: (_args, value) => textContent(value.markdown),
    },
    isConcurrencySafe: () => true,
    async execute(args) {
      const host = toText(args.host)
      if (host === '') {
        return {
          ok: false,
          host: '-',
          found: 0,
          markdown: renderFailure({ title: '扫描失败' }, { code: 'BAD_ARGS', message: '参数错误：host 必填。' }),
          error: 'BAD_ARGS：host 必填。',
        }
      }
      const options = sshOptions(args)
      const timeoutMs = toInt(args.timeoutMs, 20000, 5000, 120000)
      const directories = toArray(args.dirs)

      let result
      try {
        result = await runSshCommand({
          args: buildSshArgs(options),
          remoteCommand: buildScanCommand(directories),
          timeoutMs,
        })
      } catch (error) {
        const failure = {
          code: 'SSH_SPAWN_FAILED',
          message: `无法启动 ssh 客户端：${error?.message ?? error}`,
          hint: '确认本机 OpenSSH 客户端可执行（ssh -V）。',
        }
        return {
          ok: false,
          host,
          found: 0,
          markdown: renderFailure({ title: '扫描失败', host }, failure),
          error: `${failure.code}：${failure.message}`,
        }
      }

      if (result.timedOut) {
        const failure = {
          code: 'SSH_TIMEOUT',
          message: `扫描超时（${Math.round(timeoutMs / 1000)} 秒）`,
          hint: '指定更小的 dirs（例如只扫 /var/crash），或调大 timeoutMs。',
        }
        return {
          ok: false,
          host,
          found: 0,
          markdown: renderFailure({ title: '扫描失败', host }, failure),
          error: `${failure.code}：${failure.message}`,
        }
      }

      if (!result.stdout.trim()) {
        const classified = classifySshError(result.stderr)
        const failure = {
          code: classified.code,
          message: result.stderr.trim() ? `ssh: ${result.stderr.trim().slice(0, 600)}` : '远端没有返回任何内容',
          hint: classified.hint,
        }
        return {
          ok: false,
          host,
          found: 0,
          markdown: renderFailure({ title: '扫描失败', host }, failure),
          error: `${failure.code}：${failure.message}`,
        }
      }

      const sections = splitSections(result.stdout)
      const rows = parseCoreRows(sections.files).slice(0, MAX_ROWS)
      return finish({
        ok: true,
        host,
        corePattern: (sections.pattern || '').trim() || undefined,
        found: rows.length,
        markdown: renderScan(host, sections),
      })
    },
  }
}
