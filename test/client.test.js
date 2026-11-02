/**
 * Static/offline smoke test for the browser half.
 *
 * There is no browser control in this environment, so this test does not claim
 * to verify appearance. It does verify: the module loader contract, that both
 * slots are registered with the expected ids, that the locale dictionaries are
 * balanced, and that the components render once without throwing (a throwing
 * component is what blanks a slot entry).
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'

const SOURCE = fs.readFileSync(new URL('../client.js', import.meta.url), 'utf8')

/** Minimal React stand-in: enough for createElement + hooks + walking the tree. */
function makeReact() {
  const React = {
    createElement(type, props, ...children) {
      return { type, props: { ...(props || {}), children } }
    },
    useState(initial) {
      return [typeof initial === 'function' ? initial() : initial, () => {}]
    },
    useEffect() {},
    useRef(value) {
      return { current: value }
    },
    useCallback(fn) {
      return fn
    },
    useMemo(fn) {
      return fn()
    },
  }
  return React
}

/** Load client.js in a sandbox and return the module its factory produced. */
function loadClient() {
  let captured
  const sandbox = {
    window: {
      __ModuleLoader__: {
        load(definition) {
          captured = definition
        },
      },
    },
    console,
  }
  vm.runInNewContext(SOURCE, sandbox, { filename: 'client.js' })
  assert.ok(captured, 'window.__ModuleLoader__.load was not called')
  assert.equal(captured.id, 'dsh-coredump')
  const module = captured.factory((id) => {
    if (id === 'react') return makeReact()
    throw new Error(`unexpected require(${id})`)
  })
  return { definition: captured, module }
}

/** Render a React element tree with plain function calls (no DOM). */
function renderTree(node) {
  if (Array.isArray(node)) {
    for (const child of node) renderTree(child)
    return
  }
  if (node === null || node === undefined || typeof node !== 'object') return
  if (typeof node.type === 'function') {
    renderTree(node.type(node.props))
    return
  }
  if (node.props && Array.isArray(node.props.children)) renderTree(node.props.children)
}

test('client: loader contract, exports and slot registrations', () => {
  const { module } = loadClient()
  // Arrays built inside the vm realm have a different prototype; compare copies.
  assert.deepEqual(Array.from(module.inject), ['slots', 'locale'])

  const registrations = []
  const ctx = {
    effect(fn) {
      const dispose = fn()
      return typeof dispose === 'function' ? dispose : () => {}
    },
    locale: {
      register() {
        return () => {}
      },
      bind() {
        return key => key
      },
    },
    slots: {
      inject(owner, callback) {
        assert.equal(typeof owner, 'string')
        return callback()
      },
      register(options, component) {
        registrations.push({ options, component })
        return () => {}
      },
    },
  }

  const dispose = module.apply(ctx)
  assert.equal(typeof dispose, 'function')
  assert.doesNotThrow(() => dispose())

  const panelRow = registrations.find(item => item.options.name === 'sidebar.panellist')
  assert.ok(panelRow, 'sidebar.panellist row missing')
  assert.equal(panelRow.options.id, 'coredump')

  const main = registrations.find(item => item.options.name === 'main')
  assert.ok(main, 'main panel missing')
  assert.equal(main.options.key, 'coredump', 'main key must equal the panellist id')
  assert.equal(typeof main.options.inject, 'function')
  assert.equal(typeof main.options.inject().t, 'function')
})

test('client: dictionaries are balanced and cover the metadata', () => {
  const { module } = loadClient()
  const dictionaries = []
  const ctx = {
    effect(fn) {
      return fn() || (() => {})
    },
    locale: {
      register(ns, locale, dict) {
        dictionaries.push({ ns, locale, dict })
        return () => {}
      },
      bind() {
        return key => key
      },
    },
    slots: {
      inject(owner, callback) {
        return callback() || (() => {})
      },
      register() {
        return () => {}
      },
    },
  }
  module.apply(ctx)
  const zh = dictionaries.find(item => item.locale === 'zh')
  const en = dictionaries.find(item => item.locale === 'en')
  assert.ok(zh && en)
  assert.equal(zh.ns, 'dsh-coredump')
  const zhKeys = Object.keys(zh.dict).sort()
  const enKeys = Object.keys(en.dict).sort()
  assert.deepEqual(zhKeys, enKeys, 'zh/en dictionaries must declare the same keys')
  assert.ok(zhKeys.includes('meta.title'))
  assert.ok(zhKeys.includes('meta.description'))
})

test('client: sidebar icon and panel render without throwing', () => {
  const { module } = loadClient()
  const registrations = []
  const ctx = {
    effect(fn) {
      return fn() || (() => {})
    },
    locale: {
      register() {
        return () => {}
      },
      bind() {
        return key => key
      },
    },
    slots: {
      inject(owner, callback) {
        return callback() || (() => {})
      },
      register(options, component) {
        registrations.push({ options, component })
        return () => {}
      },
    },
  }
  module.apply(ctx)

  const icon = registrations.find(item => item.options.name === 'sidebar.panellist').component
  const iconTree = icon({ size: 16, active: true })
  assert.equal(iconTree.type, 'svg')

  const page = registrations.find(item => item.options.name === 'main').component
  assert.doesNotThrow(() => renderTree(page({ t: key => key })))
})
