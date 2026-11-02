/**
 * Minimal tool-definition helpers.
 *
 * Deliberate design choice: this package is installed as a LINK into the DSH
 * profile, so Node resolves its bare imports from the package's real path
 * (the source checkout), where `@deepseek-ai/dsh-tools` does not exist — the
 * import would fail and the whole plugin would stay unmounted. The registry
 * accepts a plain definition whose `parameters` / `output.schema` are already
 * JSON Schema, so we build those literals here and keep the package free of
 * runtime dependencies on the host.
 *
 * The `defineTool` convenience in dsh-tools additionally validates model
 * arguments; every tool in this package re-checks and clamps its own inputs
 * instead, which is required anyway for remote/ssh arguments.
 */

/**
 * Build an object-rooted JSON Schema from a property map.
 * @param {Record<string, object>} properties - raw JSON Schema per property.
 * @param {string[]} [required] - property names the model must supply.
 * @returns {object} JSON Schema.
 */
export function objectSchema(properties, required) {
  const schema = {
    type: 'object',
    additionalProperties: false,
    properties,
  }
  if (Array.isArray(required) && required.length > 0) schema.required = required
  return schema
}

/** Shorthand for one required string property. */
export const requiredString = description => ({ type: 'string', description })

/** Shorthand for one optional string property. */
export const optionalString = description => ({ type: 'string', description })

/** Shorthand for one optional integer property. */
export const optionalInteger = description => ({ type: 'integer', description })

/** Shorthand for one optional boolean property. */
export const optionalBoolean = description => ({ type: 'boolean', description })

/** Shorthand for one optional string-array property. */
export const optionalStringArray = description => ({
  type: 'array',
  items: { type: 'string' },
  description,
})

/**
 * The ssh connection parameters shared by every tool in this package.
 * Kept in one place so the three tools cannot drift apart.
 */
export const SSH_PARAMETERS = {
  jumps: optionalStringArray('跳板机链路，按顺序传给 ssh -J（可含 user@host:port）；跳板机已在 ~/.ssh/config 的 ProxyJump 里配好时不用传。'),
  port: optionalInteger('SSH 端口，默认 22。'),
  user: optionalString('SSH 用户名；host 里已带 user@ 时忽略。'),
  identityFile: optionalString('指定私钥文件路径（相当于 ssh -i）；不传则用 ssh-agent / ~/.ssh/config / 默认密钥。'),
}

/** Read the ssh connection fields out of tool arguments. */
export function sshOptions(args) {
  return {
    host: String(args.host ?? '').trim(),
    user: args.user,
    port: toInt(args.port),
    // `ssh -J` is comma-separated, so "a,b" and ["a","b"] must both work.
    jumps: toArray(args.jumps)
      .flatMap(item => item.split(','))
      .map(item => item.trim())
      .filter(item => item !== ''),
    identityFile: args.identityFile,
    strictHostKeyChecking: args.strictHostKeyChecking,
  }
}

/** A required non-empty string argument, or ''. */
export function toText(value) {
  return String(value ?? '').trim()
}

/** An integer argument clamped into [min, max]; NaN falls back. */
export function toInt(value, fallback, min, max) {
  const parsed = Number(value)
  if (!Number.isFinite(parsed)) return fallback
  const integer = Math.trunc(parsed)
  if (min !== undefined && integer < min) return min
  if (max !== undefined && integer > max) return max
  return integer
}

/** A string array argument; a single string is promoted, not dropped. */
export function toArray(value) {
  if (value === undefined || value === null || value === '') return []
  const list = Array.isArray(value) ? value : [value]
  return list.map(item => String(item ?? '').trim()).filter(item => item !== '')
}

/**
 * Render one tool result as a single text block.
 * @param {string} text - markdown card.
 * @returns {Array<{type: 'text', text: string}>} tool content blocks.
 */
export function textContent(text) {
  return [{ type: 'text', text }]
}

/**
 * Drop undefined top-level fields before returning a tool value.
 * The runtime requires lossless JSON, and `{ reportPath: undefined }` is not.
 * @param {object} value - tool result.
 * @returns {object} the same object without undefined fields.
 */
export function finish(value) {
  for (const key of Object.keys(value)) {
    if (value[key] === undefined) delete value[key]
  }
  return value
}
