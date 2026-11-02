/**
 * The `coredump_frame` agent tool.
 *
 * One frame, on demand: registers, arguments, locals, disassembly and the
 * source window. `coredump_parse` already returns every thread's stack, so this
 * tool exists to answer "what was in this frame" without flooding the model
 * with a full `thread apply all bt full` transcript.
 *
 * Cost: gdb loads the core again. That is the honest tradeoff — the alternative
 * is caching gigabytes of gdb state on a machine that may be someone's
 * production box.
 */

import { renderFailure, renderFrameDetail, saveReport } from './report.js'
import { runEngine } from './engine-run.js'
import {
  SSH_PARAMETERS,
  objectSchema,
  optionalBoolean,
  optionalInteger,
  optionalString,
  optionalStringArray,
  requiredString,
  sshOptions,
  textContent,
  toInt,
  toText,
  finish,
} from './tool-kit.js'

/** Create the tool definition. */
export function createFrameTool() {
  return {
    name: 'coredump_frame',
    description: '深挖 coredump 里的某一帧：寄存器、函数参数、局部变量、pc 附近反汇编、源码窗口。先用 coredump_parse 拿到线程号和帧号，再对关键帧用本工具。返回内容可能较长（局部变量/源码），默认只给核心信息。远端需 gdb 7.6+ 与 python3 3.6+。',
    parameters: objectSchema(
      {
        host: requiredString('SSH 别名（~/.ssh/config 里的 Host）或 user@host。'),
        core: requiredString('远端 core 文件的绝对路径。'),
        thread: optionalInteger('线程号，取 coredump_parse 输出里的 #id（gdb 的 thread 编号）。'),
        frame: optionalInteger('帧号，取调用栈里的 #n；默认 0（栈顶）。'),
        exe: optionalString('产生这个 core 的可执行文件远端绝对路径；省略时从 core 推断。'),
        symbolDirs: optionalStringArray('额外的远端符号搜索目录。'),
        timeoutMs: optionalInteger('整体超时毫秒（默认 180000）。'),
        saveReport: optionalBoolean('是否把完整 JSON 落到本机 $DSH_HOME/coredump（默认 false）。'),
        ...SSH_PARAMETERS,
      },
      ['host', 'core', 'thread'],
    ),
    output: {
      schema: objectSchema(
        {
          ok: { type: 'boolean' },
          host: { type: 'string' },
          core: { type: 'string' },
          thread: { type: 'integer' },
          frame: { type: 'integer' },
          markdown: { type: 'string' },
          error: { type: 'string' },
        },
        ['ok', 'markdown'],
      ),
      render: (_args, value) => textContent(value.markdown),
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const context = {
        host: toText(args.host),
        core: toText(args.core),
      }
      if (context.host === '' || context.core === '') {
        return {
          ok: false,
          host: context.host || '-',
          core: context.core || '-',
          markdown: renderFailure(
            { title: '帧详情失败', host: context.host, core: context.core },
            { code: 'BAD_ARGS', message: '参数错误：host 与 core 必填。' },
          ),
          error: 'BAD_ARGS：host 与 core 必填。',
        }
      }
      if (args.thread === undefined || args.thread === null || args.thread === '') {
        return {
          ok: false,
          host: context.host,
          core: context.core,
          markdown: renderFailure(
            { title: '帧详情失败', host: context.host, core: context.core },
            { code: 'BAD_ARGS', message: '参数错误：thread 必填（先用 coredump_parse 看线程表）。' },
          ),
          error: 'BAD_ARGS：thread 必填。',
        }
      }

      const thread = toInt(args.thread, 0, 0, 1e6)
      const frame = toInt(args.frame, 0, 0, 10000)
      const timeoutMs = toInt(args.timeoutMs, 180000, 10000, 900000)

      const outcome = await runEngine({
        ssh: sshOptions(args),
        core: context.core,
        exe: toText(args.exe) || undefined,
        symbolDirs: args.symbolDirs,
        maxFrames: 5,
        thread,
        frame,
        timeoutMs,
        signal: exec?.signal,
      })
      const failureContext = {
        title: '帧详情失败',
        host: context.host,
        core: context.core,
        subject: `线程 ${thread} #${frame}`,
      }
      if (!outcome.ok) {
        return {
          ok: false,
          host: context.host,
          core: context.core,
          thread,
          frame,
          markdown: renderFailure(failureContext, outcome),
          error: `${outcome.code}：${outcome.message}`,
        }
      }

      const detail = outcome.report
      let reportPath
      if (args.saveReport === true) {
        try {
          reportPath = await saveReport(detail, {
            host: context.host,
            core: context.core,
            suffix: `t${thread}-f${frame}`,
          })
        } catch {
          reportPath = undefined
        }
      }

      return finish({
        ok: true,
        host: context.host,
        core: context.core,
        thread,
        frame,
        markdown: renderFrameDetail(detail, { host: context.host, core: context.core, reportPath }),
      })
    },
  }
}
