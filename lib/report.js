/**
 * Report rendering and persistence.
 *
 * The engine's JSON is the contract; this module only decides how much of it a
 * model needs to see (a 30-thread core must not flood the context) and where
 * the full copy is kept on the local machine.
 */

import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { dshHome } from './config.js'

const MAX_OTHER_THREADS = 8
const MAX_MODULES_SHOWN = 10
const MAX_FRAME_ARGS = 70
const MAX_FRAMES_PER_OTHER_THREAD = 3

/** Truncate one display value. */
function clip(value, limit) {
  const text = String(value ?? '')
  return text.length <= limit ? text : text.slice(0, limit - 1) + '…'
}

/** One frame line: `#0  0x...  symbol (args) at file:line`. */
export function frameLine(frame) {
  const address = frame.address ? `${frame.address}  ` : ''
  const symbol = frame.unresolved ? '??（无符号）' : frame.symbol
  const args = frame.args === null || frame.args === undefined
    ? ''
    : frame.args === ''
      ? ' ()'
      : ` (${clip(frame.args, MAX_FRAME_ARGS)})`
  const where = frame.source?.file
    ? `  at ${frame.source.file}:${frame.source.line ?? '?'}`
    : frame.module
      ? `  from ${frame.module}`
      : ''
  return `#${frame.index}  ${address}${symbol}${args}${where}`
}

/** Registers worth showing when the instruction itself names none. */
const FALLBACK_REGISTERS = {
  x86_64: ['rip', 'rsp', 'rbp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi'],
  aarch64: ['pc', 'sp', 'x0', 'x1', 'x2', 'x3', 'x29', 'x30'],
}

/** Normalize one register name so instruction text and gdb output agree. */
function registerKey(name) {
  return String(name || '').replace(/^\$/, '').replace(/^%/, '').toLowerCase()
}

/**
 * Pick the registers that explain the faulting instruction: every register the
 * instruction mentions, then a small architecture default.
 * @param {object} registers - gdb `info registers` map.
 * @param {object} [instruction] - crash instruction from the engine.
 * @param {string} [arch] - `x86_64` / `aarch64` / ...
 * @returns {Array<{name: string, value: string}>}
 */
export function crashRegisters(registers, instruction, arch) {
  const values = new Map()
  if (registers && typeof registers === 'object') {
    for (const [name, value] of Object.entries(registers)) {
      values.set(registerKey(name), value)
    }
  }
  const picked = []
  const seen = new Set()
  const push = (name) => {
    const key = registerKey(name)
    if (seen.has(key) || !values.has(key)) return
    seen.add(key)
    picked.push({ name: key, value: values.get(key) })
  }
  const text = instruction?.text || ''
  for (const match of text.matchAll(/(?:\$|%)?(?<![a-z0-9])(r[a-z0-9]{1,3}|e[a-z]{2}|[xyzw]\d{1,2}|[wsp]p|pc|lr)\b/gi)) {
    push(match[1])
  }
  for (const name of FALLBACK_REGISTERS[arch] || FALLBACK_REGISTERS.x86_64) push(name)
  return picked.slice(0, 12)
}

/**
 * Summarize another thread's stack in one line.
 * Application frames (those with source) are far more useful than the libc
 * frames above them: a thread waiting on a lock should show `waiter`, not
 * `clock_nanosleep`.
 * @param {object} thread - engine thread record.
 * @returns {string} `waiter at crash.c:11 ← ...`
 */
export function threadTrace(thread) {
  const frames = thread.frames || []
  const app = frames.filter(frame => frame.source?.file)
  const chosen = app.length > 0 ? app.slice(0, MAX_FRAMES_PER_OTHER_THREAD) : frames.slice(0, MAX_FRAMES_PER_OTHER_THREAD)
  if (chosen.length === 0) return '无栈帧'
  return chosen
    .map((frame) => {
      if (frame.source?.file) {
        return `${clip(frame.unresolved ? '??' : frame.symbol || '??', 60)} at ${frame.source.file}:${frame.source.line ?? '?'}`
      }
      return clip(frame.unresolved ? '??' : frame.symbol || '??', 60)
    })
    .join(' ← ')
}

/** Human label for a thread. */
function threadLabel(thread) {
  const name = thread.name ? ` "${thread.name}"` : ''
  const lwp = thread.lwp ? ` (LWP ${thread.lwp})` : ''
  return `#${thread.id}${name}${lwp}`
}

/** Top-level suggestion list, derived from the report itself. */
export function suggestionsFor(report) {
  const codes = new Set((report.diagnostics || []).map(item => item.code))
  const signal = report.signal?.name || ''
  const crash = (report.threads || []).find(thread => thread.id === report.crashThread)
  const top = crash?.frames?.[0]
  const out = []

  if (codes.has('EXE_MISMATCH')) {
    out.push('栈不可信：core 与可执行文件不匹配，先拿到产生这个 core 的那次构建产物，再重跑。')
  }
  if (codes.has('SYMBOL_MISSING') || codes.has('NO_DEBUG_SYMBOLS')) {
    out.push('先补符号：按模块 build-id 安装 debuginfo（/usr/lib/debug/.build-id/xx/yyyy.debug），否则只有地址没有函数名。')
  }
  if (codes.has('CORE_TRUNCATED')) {
    out.push('core 不完整：线程栈可能被截断，检查生成 core 时的 ulimit -c / core_pattern 配置。')
  }
  if (signal === 'SIGABRT') {
    out.push('SIGABRT 通常来自 assert / 未捕获异常 / std::terminate：看崩溃线程 #1、#2 帧，再对照业务日志。')
  } else if (signal === 'SIGSEGV') {
    out.push('SIGSEGV：先看栈顶帧的参数里有没有 0x0 / 异常指针（this、对象指针），再追溯初始化路径。')
  } else if (signal === 'SIGBUS') {
    out.push('SIGBUS：常见于 mmap 的文件被截断或对齐问题，检查映射文件与页大小。')
  } else if (signal === 'SIGFPE') {
    out.push('SIGFPE：除零或整数溢出指令，检查栈顶帧的参数值。')
  }
  if (!signal && (report.threads || []).length > 1) {
    const waitFrames = (report.threads || []).some(thread =>
      (thread.frames || []).some(frame => /__(lll_)?(lock|futex|pthread_cond)/.test(frame.symbol || '')))
    if (waitFrames) {
      out.push('没有崩溃信号、多个线程卡在锁/条件变量上：很像死锁或卡死。用 gcore 抓活进程 + 全线程栈对比锁持有关系。')
    }
  }
  if (top && top.unresolved) {
    out.push('栈顶没有符号：先装 debuginfo，再判断是空指针还是栈破坏。')
  }
  if (out.length === 0) {
    out.push('把完整 report.json 里的线程栈与模块表发我看，我再往下定位。')
  }
  return out
}

/**
 * Render the model-facing markdown report.
 * @param {object} report - engine report (schemaVersion 1).
 * @param {{host?: string, reportPath?: string}} [meta]
 * @returns {string} markdown text.
 */
export function renderMarkdown(report, meta = {}) {
  const lines = []
  const signal = report.signal
  const title = signal ? `${signal.name}${signal.description ? `（${signal.description}）` : ''}` : '无信号（可能是 gcore 抓的活进程）'

  lines.push(`## coredump 解析结果：${title}`)
  lines.push('')
  if (report.trusted === false) {
    lines.push('> ⚠ **core 与可执行文件不匹配（EXE_MISMATCH）：下面的栈不可信，只当线索。**')
    lines.push('')
  }

  const target = report.target || {}
  lines.push(`- core：\`${target.core || '-'}\``)
  if (target.exe) lines.push(`- exe：\`${target.exe}\``)
  if (target.generatedBy) lines.push(`- 生成命令：\`${clip(target.generatedBy, 160)}\``)
  if (target.arch || target.coreArch) {
    const arch = target.arch || target.coreArch
    const mismatch = target.arch && target.coreArch && target.arch !== target.coreArch
    lines.push(`- 架构：${arch}${mismatch ? `（core 是 ${target.coreArch}，与 exe 不一致）` : ''}`)
  }
  if (meta.host) lines.push(`- 主机：${meta.host}`)
  lines.push(`- 线程：${(report.threads || []).length} 个，崩溃线程 ${report.crashThread ?? '未知'}`)
  lines.push(`- gdb 输出：${report.limits?.gdbOutputBytes ?? '?'} 字节`)

  const crashThread = (report.threads || []).find(thread => thread.id === report.crashThread)
  lines.push('')
  lines.push(`### 崩溃线程调用栈 ${crashThread ? threadLabel(crashThread) : ''}`)
  if (crashThread && (crashThread.frames || []).length > 0) {
    for (const frame of crashThread.frames) lines.push(frameLine(frame))
    if (crashThread.truncated) lines.push('…（超过 maxFrames 上限，更深的帧未展开）')
  } else {
    lines.push('_没有解析到栈帧。_')
  }

  const crash = report.crash || {}
  const instruction = crash.instruction
  const registers = crashRegisters(report.registers, instruction, target.arch || target.coreArch)
  if (instruction || registers.length > 0) {
    lines.push('')
    lines.push('### 崩溃现场')
    if (instruction) {
      lines.push(`- 崩溃指令：\`${instruction.address}\`${instruction.symbol ? ` <${instruction.symbol}>` : ''}  ${clip(instruction.text, 120)}`)
    }
    if (registers.length > 0) {
      lines.push(`- 相关寄存器：${registers.map(item => `${item.name}=${item.value}`).join('  ')}`)
    }
    if (crash.disassembly?.length > 1) {
      lines.push('- 指令上下文：')
      for (const item of crash.disassembly) {
        const pointer = item.current ? '>' : ' '
        const symbol = item.symbol ? ` <${item.symbol}>` : ''
        lines.push(`  ${pointer} ${item.address}${symbol}  ${clip(item.text, 100)}`)
      }
    }
  }

  const others = (report.threads || []).filter(thread => thread.id !== report.crashThread)
  if (others.length > 0) {
    lines.push('')
    lines.push(`### 其他线程（${others.length} 个）`)
    for (const thread of others.slice(0, MAX_OTHER_THREADS)) {
      const trace = threadTrace(thread)
      lines.push(`- ${threadLabel(thread)}（${(thread.frames || []).length} 帧）：${trace}`)
    }
    if (others.length > MAX_OTHER_THREADS) {
      lines.push(`- …另有 ${others.length - MAX_OTHER_THREADS} 个线程，见完整报告`)
    }
  }

  const modules = report.modules || []
  if (modules.length > 0) {
    lines.push('')
    lines.push(`### 模块与符号（${modules.length} 个）`)
    for (const module of modules.slice(0, MAX_MODULES_SHOWN)) {
      const symbols = module.symbolsLoaded === false ? '✗ 无符号' : module.symbolsLoaded === true ? '✓' : '?'
      const buildId = module.buildId ? `  build-id \`${module.buildId}\`` : '  无 build-id'
      const debug = module.debugFile ? `  debug: ${module.debugFile}` : ''
      lines.push(`- \`${module.path}\`  ${symbols}${buildId}${debug}`)
    }
    if (modules.length > MAX_MODULES_SHOWN) {
      lines.push(`- …另有 ${modules.length - MAX_MODULES_SHOWN} 个模块，见完整报告`)
    }
  }

  const diagnostics = report.diagnostics || []
  if (diagnostics.length > 0) {
    lines.push('')
    lines.push('### 诊断')
    for (const item of diagnostics) {
      const hint = item.hint ? `（${item.hint}）` : ''
      lines.push(`- [${item.severity}] ${item.code}：${item.message}${hint}`)
    }
  }

  const suggestions = suggestionsFor(report)
  if (suggestions.length > 0) {
    lines.push('')
    lines.push('### 建议下一步')
    for (const item of suggestions) lines.push(`- ${item}`)
  }

  if (meta.reportPath) {
    lines.push('')
    lines.push(`完整 JSON：\`${meta.reportPath}\``)
  }
  return lines.join('\n')
}

/** Turn a free-form host string into a filename-safe slug. */
function slugify(value) {
  return String(value || 'host').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60)
}

/**
 * Render a failure card. Every tool returns one instead of throwing: a failed
 * parse is still a finding (missing gdb, wrong binary, unreadable core).
 * @param {object} context - `{ title?, host?, core?, subject? }`.
 * @param {{code?: string, message: string, hint?: string}} failure
 * @returns {string} markdown text.
 */
export function renderFailure(context, failure) {
  const lines = [`## ${context.title || 'coredump 解析失败'}`, '']
  if (context.host) lines.push(`- 主机：${context.host}`)
  if (context.core) lines.push(`- core：\`${context.core}\``)
  if (context.subject) lines.push(`- 对象：${context.subject}`)
  if (failure.code) lines.push(`- 错误码：${failure.code}`)
  lines.push('', `**${failure.message}**`)
  if (failure.hint) lines.push('', failure.hint)
  return lines.join('\n')
}

/** One disassembly row: `> 0x4011c9 <main+20>  mov (%rax),%eax`. */
function disassemblyLine(item) {
  const pointer = item.current ? '>' : ' '
  const symbol = item.symbol ? ` <${item.symbol}>` : ''
  return `${pointer} ${item.address}${symbol}  ${clip(item.text, 120)}`
}

/**
 * Render the single-frame detail card (registers / args / locals / disassembly /
 * source window). Empty sections are omitted, not printed as "无".
 * @param {object} detail - engine frame report (`mode: 'frame'`).
 * @param {{core?: string, host?: string, reportPath?: string}} [meta]
 * @returns {string} markdown text.
 */
export function renderFrameDetail(detail, meta = {}) {
  const frame = detail.currentFrame || {}
  const target = detail.target || {}
  const where = frame.source?.file ? `  ${frame.source.file}:${frame.source.line ?? '?'}` : ''
  const actual = frame.index ?? detail.frame
  const note = actual !== detail.frame ? `（请求的 #${detail.frame} 不存在，显示 #${actual}）` : ''
  const lines = [`## 帧详情：线程 ${detail.thread} #${actual}  ${frame.symbol || '??'}${where}${note}`]
  lines.push('')
  lines.push(`- core：\`${target.core || meta.core || '-'}\``)
  if (target.exe) lines.push(`- exe：\`${target.exe}\``)
  if (meta.host) lines.push(`- 主机：${meta.host}`)
  if (frame.address) lines.push(`- 帧地址：${frame.address}`)
  if (frame.module) lines.push(`- 模块：\`${frame.module}\``)
  if (detail.frameInfo?.pc) lines.push(`- pc：${detail.frameInfo.pc}`)

  const registers = crashRegisters(detail.registers, detail.disassembly?.find(item => item.current), target.arch)
  if (registers.length > 0) {
    lines.push('')
    lines.push('### 寄存器')
    lines.push(registers.map(item => `${item.name}=${item.value}`).join('  '))
  }

  if (detail.args?.length > 0) {
    lines.push('')
    lines.push('### 参数')
    for (const item of detail.args) {
      lines.push(`- ${item.name} = ${clip(item.value, 200)}${item.truncated ? ' …（结构体已截断）' : ''}`)
    }
  }

  if (detail.locals?.length > 0) {
    lines.push('')
    lines.push('### 局部变量')
    for (const item of detail.locals) {
      lines.push(`- ${item.name} = ${clip(item.value, 200)}${item.truncated ? ' …（结构体已截断）' : ''}`)
    }
  }

  if (detail.disassembly?.length > 0) {
    lines.push('')
    lines.push('### 反汇编（pc 附近）')
    for (const item of detail.disassembly) lines.push(disassemblyLine(item))
  }

  if (detail.source?.lines?.length > 0) {
    lines.push('')
    lines.push(`### 源码${detail.source.file ? `（${detail.source.file}）` : ''}`)
    lines.push('```')
    for (const item of detail.source.lines) {
      lines.push(`${item.current ? '>' : ' '}${String(item.number).padStart(5)}  ${item.text}`)
    }
    lines.push('```')
  }

  const diagnostics = detail.diagnostics || []
  if (diagnostics.length > 0) {
    lines.push('')
    lines.push('### 诊断')
    for (const item of diagnostics) {
      const hint = item.hint ? `（${item.hint}）` : ''
      lines.push(`- [${item.severity}] ${item.code}：${item.message}${hint}`)
    }
  }

  if (meta.reportPath) {
    lines.push('')
    lines.push(`完整 JSON：\`${meta.reportPath}\``)
  }
  return lines.join('\n')
}

/**
 * Persist the full report under $DSH_HOME/coredump/.
 * @param {object} report - engine report.
 * @param {{host?: string, core?: string, suffix?: string}} [meta]
 * @returns {Promise<string>} absolute path of the written JSON.
 */
export async function saveReport(report, meta = {}) {
  const directory = path.join(dshHome(), 'coredump')
  await mkdir(directory, { recursive: true })
  const base = slugify(path.basename(meta.core || report.target?.core || 'core'))
  const suffix = meta.suffix ? `-${slugify(meta.suffix)}` : ''
  const name = `${Date.now()}-${slugify(meta.host)}-${base}${suffix}.json`
  const destination = path.join(directory, name)
  await writeFile(destination, JSON.stringify(report, null, 2), 'utf8')
  return destination
}
