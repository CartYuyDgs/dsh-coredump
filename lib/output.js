/**
 * Pure helpers shared by the tool: engine-output parsing and text clipping.
 * Kept free of DSH imports so `node --test` can cover them offline.
 */

/** Truncate one display string. */
export function clip(value, limit) {
  const text = String(value ?? '')
  return text.length <= limit ? text : text.slice(0, limit - 1) + '…'
}

/**
 * Pull the engine's JSON out of ssh stdout.
 * Non-interactive ssh is silent, but a `Banner` directive can still prepend
 * text, so we scan from the end for the first parseable object.
 * @param {string} stdout - raw stdout.
 * @returns {object|undefined} the parsed report, or undefined.
 */
export function parseEngineOutput(stdout) {
  const lines = String(stdout || '').split(/\r?\n/).filter(line => line.trim() !== '')
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index].trim()
    if (!line.startsWith('{')) continue
    try {
      return JSON.parse(line)
    } catch {
      // keep scanning: a banner line may coincidentally start with "{"
    }
  }
  return undefined
}

/**
 * Split marked remote output into named sections.
 * The scan command prints `@@cdparse:<name>@@` headers so one ssh round-trip
 * can carry several unrelated outputs without guessing where one ends.
 * @param {string} stdout - raw remote output.
 * @param {string} [prefix] - marker prefix.
 * @returns {Record<string, string>} section name → trimmed body.
 */
export function splitSections(stdout, prefix = '@@cdparse:') {
  const sections = {}
  let current
  let buffer = []
  const flush = () => {
    if (current !== undefined) sections[current] = buffer.join('\n').trim()
  }
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.startsWith(prefix) && trimmed.endsWith('@@')) {
      flush()
      current = trimmed.slice(prefix.length, -2)
      buffer = []
      continue
    }
    if (current !== undefined) buffer.push(line)
  }
  flush()
  return sections
}
