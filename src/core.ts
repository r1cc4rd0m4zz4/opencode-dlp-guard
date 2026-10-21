/**
 * opencode-dlp-guard — core primitives.
 *
 * Pure Node.js: no OpenCode imports, so every rule is unit-testable on its own.
 *
 * Layers:
 *  - path protection          isPathProtected()
 *  - shell write analysis     checkBashCommand()
 *  - tool call routing        scanToolCall()
 *  - deterministic redaction  SecretRedactor
 */

import * as cp from "node:child_process"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

export interface DlpGuardConfig {
  /** Blocked for read and write. */
  protectedPaths: string[]
  /** Blocked for write only (the agent may still read them). */
  integrityPaths: string[]
  enableGitleaks: boolean
  gitleaksMinBytes: number
  gitleaksTimeoutMs: number
}

export const DEFAULT_CONFIG: DlpGuardConfig = {
  protectedPaths: [
    ".env",
    ".env.*",
    "**/.git/config",
    "**/.git/hooks/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.gnupg/**",
    "~/.kube/**",
    "~/.netrc",
    "~/.zshrc*",
    "~/.bashrc*",
    "~/.bash_profile",
    "~/.profile",
    "**/*rc.local",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "~/.config/opencode/auth.json",
    "~/.local/share/opencode/opencode.db",
    "~/.local/share/opencode/opencode.db-*",
  ],
  integrityPaths: ["~/.config/opencode/**", "~/.local/share/opencode/**"],
  enableGitleaks: true,
  gitleaksMinBytes: 4096,
  gitleaksTimeoutMs: 500,
}

const TEMPLATE_ENV = /^\.env\.(?:example|sample|template)$/i
const ENV_PATTERN = /(?:^|\/)\.env(?:\.\*)?$/i

let guardDir = ""

/** Protect the installed package itself from agent writes (anti-tampering). */
export function setGuardDirectory(dir: string): void {
  guardDir = dir ? path.resolve(dir) : ""
}

export function homeDir(): string {
  try {
    return fs.realpathSync(os.homedir())
  } catch {
    return os.homedir()
  }
}

export function configFilePath(): string {
  const override = process.env.OPENCODE_DLP_CONFIG
  if (override) return path.resolve(override)
  const xdg = process.env.XDG_CONFIG_HOME
  const base = xdg ? path.resolve(xdg) : path.join(homeDir(), ".config")
  return path.join(base, "opencode", "dlp-guard.json")
}

export function loadConfig(file: string = configFilePath()): DlpGuardConfig {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf-8")) as Record<string, unknown>
    const list = (value: unknown, fallback: string[]) =>
      Array.isArray(value) && value.every((item) => typeof item === "string") ? (value as string[]) : fallback
    const num = (value: unknown, fallback: number) =>
      typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : fallback
    return {
      protectedPaths: list(parsed.protectedPaths, DEFAULT_CONFIG.protectedPaths),
      integrityPaths: list(parsed.integrityPaths, DEFAULT_CONFIG.integrityPaths),
      enableGitleaks:
        typeof parsed.enableGitleaks === "boolean" ? parsed.enableGitleaks : DEFAULT_CONFIG.enableGitleaks,
      gitleaksMinBytes: num(parsed.gitleaksMinBytes, DEFAULT_CONFIG.gitleaksMinBytes),
      gitleaksTimeoutMs: num(parsed.gitleaksTimeoutMs, DEFAULT_CONFIG.gitleaksTimeoutMs),
    }
  } catch {
    return { ...DEFAULT_CONFIG }
  }
}

/** Creates the config file on first run. Returns true when the file was created. */
export function ensureConfigFile(file: string = configFilePath(), config: DlpGuardConfig = DEFAULT_CONFIG): boolean {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, { flag: "wx", mode: 0o600 })
    return true
  } catch {
    return false
  }
}

// -----------------------------------------------------------------------------
// Secret redaction
// -----------------------------------------------------------------------------

// Each rule captures the secret in group 1 (or the first defined group).
const RULES: { category: string; rx: RegExp }[] = [
  {
    category: "PRIVATE_KEY",
    rx: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g,
  },
  { category: "AWS_KEY", rx: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { category: "GITHUB_TOKEN", rx: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})(?![\w])/g },
  { category: "SLACK_TOKEN", rx: /\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b/g },
  {
    category: "API_KEY",
    rx: /\b(sk-ant-[\w-]{20,}|sk-proj-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[\w-]{35}|[rs]k_live_[0-9A-Za-z]{24,})(?![\w-])/g,
  },
  { category: "JWT", rx: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { category: "URL_CREDENTIAL", rx: /:\/\/[^\s:/@]+:([^\s@/]+)@/g },
  {
    // NAME=value / NAME: value / "name": "value", where a NAME segment is a secret word.
    category: "SECRET",
    rx: /(?:^|[\s;,{("'])(?:export\s+)?(?:[A-Za-z0-9]+[_-])*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PASS|AUTH|PRIVATE)(?:[_-][A-Za-z0-9]+)*["']?\s*[=:]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([^\s"',;]{8,}))/gi,
  },
  { category: "BEARER", rx: /\bBearer\s+([A-Za-z0-9._~+/=-]{20,})/g },
]

/** The same secret always maps to the same token within one session. */
export class SecretRedactor {
  config: DlpGuardConfig
  private readonly secretToToken = new Map<string, string>()
  private readonly counters = new Map<string, number>()

  constructor(config: DlpGuardConfig = DEFAULT_CONFIG) {
    this.config = config
  }

  get size(): number {
    return this.secretToToken.size
  }

  clear(): void {
    this.secretToToken.clear()
    this.counters.clear()
  }

  private tokenFor(secret: string, category: string): string {
    let token = this.secretToToken.get(secret)
    if (!token) {
      const next = (this.counters.get(category) ?? 0) + 1
      this.counters.set(category, next)
      token = `[REDACTED_${category}_#${next}]`
      this.secretToToken.set(secret, token)
    }
    return token
  }

  /** Replaces secrets with stable tokens. gitleaks (optional) only runs on large inputs. */
  redact(text: string, useGitleaks = false): string {
    if (typeof text !== "string" || !text) return text
    let out = text
    for (const { category, rx } of RULES) {
      out = out.replace(rx, (match: string, ...groups: unknown[]) => {
        const secret = groups.slice(0, 3).find((group) => typeof group === "string" && group) as string | undefined
        if (!secret || /^(?:\[REDACTED_|[$<{(])/.test(secret)) return match
        const index = match.lastIndexOf(secret)
        return match.slice(0, index) + this.tokenFor(secret, category) + match.slice(index + secret.length)
      })
    }
    if (useGitleaks && this.config.enableGitleaks && out.length >= this.config.gitleaksMinBytes) {
      for (const secret of scanWithGitleaks(out, this.config.gitleaksTimeoutMs)) {
        out = out.split(secret).join(this.tokenFor(secret, "SECRET"))
      }
    }
    return out
  }
}

let gitleaksAvailable: boolean | null = null

export function hasGitleaks(): boolean {
  if (gitleaksAvailable === null) {
    gitleaksAvailable =
      cp.spawnSync("gitleaks", ["version"], { timeout: 500, stdio: "ignore" }).status === 0
  }
  return gitleaksAvailable
}

export function scanWithGitleaks(text: string, timeoutMs = 500): string[] {
  if (!hasGitleaks()) return []
  try {
    const result = cp.spawnSync(
      "gitleaks",
      ["stdin", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"],
      { input: text, timeout: timeoutMs, encoding: "utf-8", maxBuffer: 5 * 1024 * 1024 },
    )
    const found = JSON.parse(result.stdout || "[]") as unknown
    if (!Array.isArray(found)) return []
    return found
      .map((entry) => (entry && typeof entry === "object" ? (entry as { Secret?: unknown }).Secret : ""))
      .filter((secret): secret is string => typeof secret === "string" && secret.length >= 8)
  } catch {
    return []
  }
}

// -----------------------------------------------------------------------------
// Path protection
// -----------------------------------------------------------------------------

function expandHome(value: string): string {
  return value.replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, homeDir())
}

/** Glob to RegExp: `**` crosses directories, `*` does not; `**\/` may match nothing. */
function globToRegExp(glob: string): RegExp {
  let out = ""
  for (let i = 0; i < glob.length; i++) {
    const char = glob[i]
    if (char === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") {
        out += "(?:.*/)?"
        i += 2
      } else {
        out += ".*"
        i += 1
      }
    } else if (char === "*") out += "[^/]*"
    else out += char.replace(/[.+^${}()|[\]\\?]/g, "\\$&")
  }
  return new RegExp(`^${out}$`, "i")
}

/** Does an absolute path match a pattern? A bare name matches any basename. */
function matches(pattern: string, abs: string, cwd: string): boolean {
  let glob = expandHome(pattern.replace(/\\/g, "/"))
  if (!glob.includes("/")) return globToRegExp(glob).test(path.basename(abs))
  if (!glob.startsWith("/") && !glob.startsWith("**")) glob = `${cwd.replace(/\\/g, "/")}/${glob}`
  if (globToRegExp(glob).test(abs)) return true
  if (glob.endsWith("/**") && globToRegExp(glob.slice(0, -3)).test(abs)) return true

  // On macOS /var is a symlink to /private/var: also check the canonical prefix.
  const prefix = glob.replace(/\/\*\*?.*$/, "")
  const canonicalPrefix = canonical(prefix)
  if (canonicalPrefix !== prefix) {
    const canonicalGlob = canonicalPrefix + glob.slice(prefix.length)
    if (globToRegExp(canonicalGlob).test(abs)) return true
    if (canonicalGlob.endsWith("/**") && globToRegExp(canonicalGlob.slice(0, -3)).test(abs)) return true
  }
  return false
}

/** Follows symlinks, including dangling ones, and ancestors of files that do not exist yet. */
function canonical(target: string, depth = 0): string {
  try {
    return fs.realpathSync(target)
  } catch {
    // not resolvable as-is
  }
  try {
    if (depth < 8 && fs.lstatSync(target).isSymbolicLink()) {
      return canonical(path.resolve(path.dirname(target), fs.readlinkSync(target)), depth + 1)
    }
  } catch {
    // does not exist
  }
  const parent = path.dirname(target)
  return parent === target ? target : path.join(canonical(parent, depth), path.basename(target))
}

export interface PathCheck {
  protected: boolean
  reason?: string
}

export function isPathProtected(
  targetPath: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  op: "read" | "write" = "read",
): PathCheck {
  if (typeof targetPath !== "string" || !targetPath.trim()) return { protected: false }
  const lexical = path.resolve(cwd, expandHome(targetPath.trim()))
  const template = TEMPLATE_ENV.test(path.basename(lexical))
  const candidates = new Set([lexical, canonical(lexical)])

  for (const pattern of config.protectedPaths) {
    // Templates are documentation: keep them readable even when `.env.*` is protected.
    if (template && ENV_PATTERN.test(pattern.replace(/\\/g, "/"))) continue
    for (const absolute of candidates) {
      if (matches(pattern, absolute, cwd)) {
        return { protected: true, reason: `protected path "${pattern}"` }
      }
    }
  }

  if (op === "write") {
    const integrity = [...config.integrityPaths, ...(guardDir ? [`${guardDir}/**`] : [])]
    for (const pattern of integrity) {
      for (const absolute of candidates) {
        if (matches(pattern, absolute, cwd)) {
          return { protected: true, reason: `guard integrity: write blocked on "${pattern}"` }
        }
      }
    }
  }

  return { protected: false }
}

// -----------------------------------------------------------------------------
// Bash analysis: split chained commands, track `cd`, check write targets
// -----------------------------------------------------------------------------

interface Segment {
  words: string[]
  redirects: string[]
}

/** Splits on ; && || | & and newlines outside quotes. Redirect targets are collected apart. */
function parseSegments(command: string): Segment[] {
  const segments: Segment[] = []
  let segment: Segment = { words: [], redirects: [] }
  let word = ""
  let inWord = false
  let quote = ""
  let redirect = false

  const endWord = () => {
    if (inWord) (redirect ? segment.redirects : segment.words).push(word)
    if (inWord) redirect = false
    word = ""
    inWord = false
  }
  const endSegment = () => {
    endWord()
    redirect = false
    if (segment.words.length || segment.redirects.length) segments.push(segment)
    segment = { words: [], redirects: [] }
  }

  for (let i = 0; i < command.length; i++) {
    const char = command[i]
    if (quote) {
      if (char === quote) quote = ""
      else if (char === "\\" && quote === '"' && i + 1 < command.length) word += command[++i]
      else word += char
    } else if (char === "'" || char === '"') {
      quote = char
      inWord = true
    } else if (char === "\\" && i + 1 < command.length) {
      word += command[++i]
      inWord = true
    } else if (char === ";" || char === "\n" || char === "|") {
      endSegment()
    } else if (char === "&" && command[i - 1] !== ">" && command[i + 1] !== ">") {
      endSegment()
    } else if (char === ">") {
      endWord()
      if (command[i + 1] === ">") i++
      redirect = true
    } else if (char === "<") {
      endWord() // input redirection is a read: not checked here
      if (command[i + 1] === "<") i++
    } else if (/\s/.test(char)) {
      endWord()
    } else {
      word += char
      inWord = true
    }
  }
  endSegment()
  return segments
}

const WRAPPERS = new Set(["sudo", "env", "command", "nohup", "time", "exec", "nice", "builtin", "xargs"])
const MUTATORS = new Set([
  "rm",
  "rmdir",
  "mv",
  "cp",
  "ln",
  "install",
  "rsync",
  "touch",
  "truncate",
  "dd",
  "chmod",
  "chown",
  "chgrp",
  "tee",
  "shred",
  "unlink",
  "mkdir",
  "patch",
  "tar",
  "zip",
  "unzip",
])
const IN_PLACE_EDITORS = new Set(["sed", "perl", "ruby"])
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"])

function shellScript(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(args[i])) {
      const rest = args.slice(i + 1)
      if (rest.length) return rest.join(" ")
    }
  }
  return undefined
}

export interface BashCheck {
  block: boolean
  reason?: string
}

export function checkBashCommand(
  command: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  depth = 0,
): BashCheck {
  if (typeof command !== "string" || !command.trim() || depth > 3) return { block: false }
  const deny = (target: string, reason?: string) => ({
    block: true,
    reason: `write blocked on "${target}" (${reason})`,
  })
  let here = cwd

  // Nested code: $(...), `...`, sh -c "...", eval "..."
  const nested = [...command.matchAll(/\$\(([^()]*)\)|`([^`]*)`/g)].map((match) => match[1] ?? match[2])

  for (const { words, redirects } of parseSegments(command)) {
    let i = 0
    while (i < words.length && (/^[A-Za-z_]\w*=/.test(words[i]) || WRAPPERS.has(path.basename(words[i])))) i++
    const name = path.basename(words[i] ?? "")
    const args = words.slice(i + 1)

    if (name === "cd" || name === "pushd") {
      if (args[0]) here = path.resolve(here, expandHome(args[0]))
      continue
    }
    if (SHELLS.has(name)) {
      const script = shellScript(args)
      if (script) nested.push(script)
    }
    if (name === "eval") nested.push(args.join(" "))

    const inPlace = IN_PLACE_EDITORS.has(name) && args.some((arg) => /^-[A-Za-z]*i|^--in-place/.test(arg))
    let targets = MUTATORS.has(name) || inPlace ? [...args.filter((arg) => !arg.startsWith("-")), ...redirects] : redirects
    if (name === "dd") {
      targets = [...targets, ...args.filter((arg) => arg.startsWith("of=")).map((arg) => arg.slice(3))]
    }
    for (const target of targets) {
      const check = isPathProtected(target, config, here, "write")
      if (check.protected) return deny(target, check.reason)
    }
  }

  for (const inner of nested) {
    const result = checkBashCommand(inner, config, here, depth + 1)
    if (result.block) return result
  }
  return { block: false }
}

// -----------------------------------------------------------------------------
// Tool call routing
// -----------------------------------------------------------------------------

const SHELL_TOOL = /^(?:shell|bash|sh|exec|run_command|terminal)$/i
const WRITE_TOOL = /write|edit|replace|patch|create|delete|move|rename|apply|upload|install/i
const PATH_KEY =
  /^(?:path|paths|file|files|filepath|file_path|filename|directory|dir|cwd|workdir|root|target|destination|dest)$/i

function collectPaths(value: unknown, out: string[], depth = 0): void {
  if (depth > 5 || !value || typeof value !== "object") return
  if (Array.isArray(value)) {
    for (const item of value) collectPaths(item, out, depth + 1)
    return
  }
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (PATH_KEY.test(key)) {
      const values = Array.isArray(item) ? item : [item]
      for (const entry of values) {
        if (typeof entry === "string" && entry.trim() && !entry.includes("://")) out.push(entry)
      }
    } else if (item && typeof item === "object") {
      collectPaths(item, out, depth + 1)
    }
  }
}

function patchPaths(input: Record<string, unknown>): string[] {
  const text =
    typeof input.patchText === "string"
      ? input.patchText
      : typeof input.patch === "string"
        ? input.patch
        : typeof input.input === "string"
          ? input.input
          : ""
  if (!text) return []
  const found: string[] = []
  for (const match of text.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm)) found.push(match[1].trim())
  for (const match of text.matchAll(/^\*\*\* Move to: (.+)$/gm)) found.push(match[1].trim())
  for (const match of text.matchAll(/^(?:\+\+\+|---) (?:[ab]\/)?(.+)$/gm)) {
    const target = match[1].trim()
    if (target !== "/dev/null") found.push(target)
  }
  return found
}

export interface ToolCheck {
  block: boolean
  reason?: string
}

export function scanToolCall(
  tool: string,
  input: unknown,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
): ToolCheck {
  const data = (input && typeof input === "object" ? input : {}) as Record<string, unknown>
  const workdir =
    typeof data.workdir === "string"
      ? path.resolve(cwd, expandHome(data.workdir))
      : typeof data.cwd === "string"
        ? path.resolve(cwd, expandHome(data.cwd))
        : cwd

  if (SHELL_TOOL.test(tool)) {
    const command =
      typeof data.command === "string" ? data.command : typeof data.cmd === "string" ? data.cmd : ""
    return checkBashCommand(command, config, workdir)
  }

  const op = WRITE_TOOL.test(tool) ? "write" : "read"
  const targets: string[] = []
  collectPaths(data, targets)
  if (op === "write") targets.push(...patchPaths(data))

  for (const target of targets) {
    const check = isPathProtected(target, config, workdir, op)
    if (check.protected) return { block: true, reason: `${target}: ${check.reason}` }
  }
  return { block: false }
}

// -----------------------------------------------------------------------------
// Redaction of tool results and outbound context
// -----------------------------------------------------------------------------

type RedactFn = (value: string) => string

function deepRedact(value: unknown, redact: RedactFn, depth = 0): unknown {
  if (typeof value === "string") return redact(value)
  if (depth > 12 || !value || typeof value !== "object") return value
  if (Array.isArray(value)) {
    let changed = false
    const next = value.map((item) => {
      const redacted = deepRedact(item, redact, depth + 1)
      if (redacted !== item) changed = true
      return redacted
    })
    return changed ? next : value
  }
  let changed = false
  const next: Record<string, unknown> = {}
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const redacted = deepRedact(item, redact, depth + 1)
    if (redacted !== item) changed = true
    next[key] = redacted
  }
  return changed ? next : value
}

/** Redacts a tool result in place. Returns true when something changed. */
export function redactToolResult(
  result: Record<string, unknown>,
  redactor: SecretRedactor,
  useGitleaks = true,
): boolean {
  let changed = false
  const redact: RedactFn = (value) => {
    const next = redactor.redact(value, useGitleaks)
    if (next !== value) changed = true
    return next
  }

  if (typeof result.content === "string") {
    result.content = redact(result.content)
  } else if (Array.isArray(result.content)) {
    result.content = result.content.map((part) => {
      if (part && typeof part === "object" && (part as { type?: string }).type === "text") {
        const text = (part as { text?: unknown }).text
        if (typeof text === "string") return { ...part, text: redact(text) }
      }
      return part
    })
  }
  if (typeof result.output === "string") result.output = redact(result.output)
  else if (result.output && typeof result.output === "object") {
    result.output = deepRedact(result.output, redact)
  }
  if (result.metadata && typeof result.metadata === "object") {
    result.metadata = deepRedact(result.metadata, redact)
  }
  return changed
}

/** Redacts text-bearing parts of outbound model messages in place. Returns true when something changed. */
export function redactContextMessages(messages: readonly unknown[], redactor: SecretRedactor): boolean {
  let changed = false
  const redact: RedactFn = (value) => {
    const next = redactor.redact(value)
    if (next !== value) changed = true
    return next
  }

  const redactPart = (part: unknown): void => {
    if (!part || typeof part !== "object") return
    const value = part as Record<string, unknown>
    const type = value.type

    if ((type === "text" || type === "reasoning") && typeof value.text === "string") {
      value.text = redact(value.text)
      return
    }

    if (type === "tool-call" && value.input !== undefined) {
      value.input = deepRedact(value.input, redact)
      return
    }

    if (type === "tool-result" && value.result && typeof value.result === "object") {
      const result = value.result as Record<string, unknown>
      if (typeof result.value === "string") result.value = redact(result.value)
      else if (result.value && typeof result.value === "object") {
        result.value = deepRedact(result.value, redact)
      }
    }
  }

  for (const message of messages) {
    if (!message || typeof message !== "object") continue
    const content = (message as { content?: unknown }).content
    if (Array.isArray(content)) for (const part of content) redactPart(part)
  }
  return changed
}
