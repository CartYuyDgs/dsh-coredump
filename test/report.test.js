import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { renderMarkdown, suggestionsFor, saveReport } from '../lib/report.js'

const report = {
  schemaVersion: 1,
  ok: true,
  target: {
    core: '/data/core.18422',
    exe: '/opt/app/bin/order-server',
    generatedBy: '/opt/app/bin/order-server --config /etc/order/config.yaml',
    arch: 'x86_64',
    coreArch: 'x86_64',
  },
  signal: { name: 'SIGSEGV', description: 'Segmentation fault' },
  crashThread: 2,
  threads: [
    {
      id: 2,
      name: 'worker-1',
      lwp: 18423,
      current: true,
      truncated: false,
      frames: [
        {
          index: 0,
          address: '0x00000000004012ab',
          symbol: 'OrderService::submit',
          args: 'this=0x0, order=...',
          source: { file: '/src/order/service.cpp', line: 218 },
          module: '/opt/app/bin/order-server',
          unresolved: false,
        },
        {
          index: 1,
          address: '0x00000000004017c2',
          symbol: 'worker_loop',
          args: 'ctx=0x60e010',
          source: { file: '/src/worker.cpp', line: 88 },
          module: '/opt/app/bin/order-server',
          unresolved: false,
        },
      ],
    },
    {
      id: 1,
      name: 'worker-2',
      lwp: 18424,
      current: false,
      truncated: false,
      frames: [
        {
          index: 0,
          address: '0x00007f8d4a8b3a86',
          symbol: '__lll_lock_wait',
          args: '',
          source: null,
          module: '/lib64/libpthread.so.0',
          unresolved: false,
        },
      ],
    },
  ],
  registers: { rip: '0x4012ab' },
  modules: [
    { path: '/opt/app/bin/order-server', symbolsLoaded: true, buildId: 'a1b2c3d4e5f6', debugFile: null },
    { path: '/lib64/libc.so.6', symbolsLoaded: false, buildId: null, debugFile: null },
  ],
  diagnostics: [
    { code: 'SYMBOL_MISSING', severity: 'warn', message: '模块没有加载符号：/lib64/libc.so.6', hint: '装 debuginfo' },
  ],
  limits: { maxFramesPerThread: 40, gdbOutputBytes: 2048 },
}

test('renderMarkdown: header, crash stack, other threads, modules, diagnostics', () => {
  const text = renderMarkdown(report, { host: 'prod-1', reportPath: 'C:/dsh/coredump/x.json' })
  assert.match(text, /## coredump 解析结果：SIGSEGV/)
  assert.match(text, /core：`\/data\/core\.18422`/)
  assert.match(text, /#0 {2}0x00000000004012ab {2}OrderService::submit \(this=0x0, order=\.\.\.\) {2}at \/src\/order\/service\.cpp:218/)
  assert.match(text, /### 其他线程（1 个）/)
  assert.match(text, /__lll_lock_wait/)
  assert.match(text, /### 模块与符号（2 个）/)
  assert.match(text, /SYMBOL_MISSING/)
  assert.match(text, /完整 JSON：`C:\/dsh\/coredump\/x\.json`/)
})

test('renderMarkdown: unresolved frame is spelled out instead of a bare ??', () => {
  const broken = {
    ...report,
    threads: [
      {
        ...report.threads[0],
        frames: [{ index: 0, address: '0x0', symbol: '??', args: '', source: null, module: null, unresolved: true }],
      },
    ],
    signal: { name: 'SIGSEGV', description: 'Segmentation fault' },
  }
  const text = renderMarkdown(broken)
  assert.match(text, /\?\?（无符号）/)
})

test('suggestionsFor: build-id mismatch is called out first', () => {
  const suggestions = suggestionsFor({
    ...report,
    diagnostics: [{ code: 'EXE_MISMATCH', severity: 'error', message: 'mismatch' }],
  })
  assert.match(suggestions[0], /栈不可信/)
})

test('suggestionsFor: deadlock hint for a signalless gcore', () => {
  const suggestions = suggestionsFor({ ...report, signal: null })
  assert.ok(suggestions.some(item => /死锁|卡死/.test(item)))
})

test('saveReport: writes UTF-8 JSON under $DSH_HOME/coredump', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-coredump-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const file = await saveReport(report, { host: 'prod-1', core: '/data/core.18422' })
    assert.ok(file.startsWith(path.join(home, 'coredump')))
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'))
    assert.equal(parsed.crashThread, 2)
    assert.equal(parsed.signal.name, 'SIGSEGV')
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    fs.rmSync(home, { recursive: true, force: true })
  }
})
