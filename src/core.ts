/**
 * opencode-dlp-guard — core primitives.
 *
 * Pure Node.js: no OpenCode imports, so every rule is unit-testable on its own.
 *
 * Layers:
 *  - path protection          isPathProtected()
 *  - deep shell analysis      checkBashCommand()
 *  - tool call routing        scanToolCall()
 *  - deterministic redaction  SecretRedactor & detectSecrets()
 */

import * as cp from "node:child_process"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

export interface DlpGuardConfig {
  enabled?: boolean
  /** Blocked for read and write. */
  protectedPaths: string[]
  /** Blocked for write only (the agent may still read them). */
  integrityPaths: string[]
  enableGitleaks: boolean
  gitleaksMinBytes: number
  gitleaksTimeoutMs: number
  blockInlineSecretsInCommands?: boolean
  blockReaderCommandsOnProtected?: boolean
  blockWriteSecrets?: boolean
}

export const DEFAULT_CONFIG: DlpGuardConfig = {
  enabled: true,
  protectedPaths: [
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "**/.git/**",
    "**/.git/config",
    "**/.git/hooks/**",
    "~/.ssh/**",
    "/etc/ssh/**",
    "/etc/shadow*",
    "/etc/gshadow*",
    "/etc/sudoers*",
    "~/.aws/**",
    "~/.config/gcloud/**",
    "~/.gcloud/**",
    "~/.gcp/**",
    "~/.azure/**",
    "~/.oci/**",
    "~/.gnupg/**",
    "~/.password-store/**",
    "~/.local/share/keyrings/**",
    "~/Library/Keychains/**",
    "~/.config/gh/**",
    "~/.config/gh/hosts.yml",
    "~/.config/glab-cli/**",
    "~/.config/op/**",
    "~/.op/**",
    "~/.config/sops/**",
    "~/.config/age/**",
    "~/.kube/**",
    "~/.docker/config.json",
    "~/.terraform.d/**",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.tfvars",
    "~/.vault-token",
    "~/.netrc",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.gem/credentials",
    "~/.cargo/credentials*",
    "~/.composer/auth.json",
    "~/.zshrc*",
    "~/.zprofile",
    "~/.zshenv",
    "~/.zsh_history",
    "~/.bashrc*",
    "~/.bash_profile",
    "~/.bash_history",
    "~/.profile",
    "**/*rc.local",
    "**/*.pem",
    "**/*.key",
    "**/*.pkcs12",
    "**/*.pfx",
    "**/*.p12",
    "**/*.jks",
    "**/*.keystore",
    "**/*.age",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/id_dsa*",
    "~/.config/opencode/auth.json",
    "~/.local/share/opencode/opencode.db",
    "~/.local/share/opencode/opencode.db-*",
    "~/.pi/agent/auth.json",
    "~/.claude/.credentials.json",
  ],
  integrityPaths: [
    "~/.config/opencode/**",
    "~/.local/share/opencode/**",
    ".opencode/**",
    "~/.pi/agent/**",
    "**/.pi/agent/**",
    ".pi/**",
    "~/.gemini/config/**",
    "**/.gemini/config/**",
    ".agents/**",
    ".agent/**",
    "**/dlp-guard.json",
  ],
  enableGitleaks: true,
  gitleaksMinBytes: 4096,
  gitleaksTimeoutMs: 500,
  blockInlineSecretsInCommands: true,
  blockReaderCommandsOnProtected: true,
  blockWriteSecrets: true,
}

const TEMPLATE_ENV = /^\.env\.(?:example|sample|template|dist|default|schema)$/i
const ENV_PATTERN = /(?:^|\/|\*)\.env(?:\.\*)?$/i

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
    const bool = (value: unknown, fallback: boolean) => (typeof value === "boolean" ? value : fallback)
    return {
      enabled: bool(parsed.enabled, true),
      protectedPaths: list(parsed.protectedPaths, DEFAULT_CONFIG.protectedPaths),
      integrityPaths: list(parsed.integrityPaths, DEFAULT_CONFIG.integrityPaths),
      enableGitleaks: bool(parsed.enableGitleaks, DEFAULT_CONFIG.enableGitleaks),
      gitleaksMinBytes: num(parsed.gitleaksMinBytes, DEFAULT_CONFIG.gitleaksMinBytes),
      gitleaksTimeoutMs: num(parsed.gitleaksTimeoutMs, DEFAULT_CONFIG.gitleaksTimeoutMs),
      blockInlineSecretsInCommands: bool(parsed.blockInlineSecretsInCommands, true),
      blockReaderCommandsOnProtected: bool(parsed.blockReaderCommandsOnProtected, true),
      blockWriteSecrets: bool(parsed.blockWriteSecrets, true),
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
// Secret Detection & Relational Redaction
// -----------------------------------------------------------------------------

const SEC_WORDS = "SECRET|KEY|TOKEN|PASSWORD|PASSWD|PASS|PW|AUTH|PRIVATE|CREDENTIAL"

const RULES: { category: string; rx: RegExp }[] = [
  {
    category: "PRIVATE_KEY",
    rx: /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)/g,
  },
  { category: "AGE_SECRET_KEY", rx: /\b(AGE-SECRET-KEY-1[A-Z0-9]{58})\b/g },
  { category: "AWS_KEY", rx: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g },
  { category: "GITHUB_TOKEN", rx: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})(?![\w])/g },
  { category: "GITLAB_TOKEN", rx: /\b(glpat-[0-9a-zA-Z\-_]{20,})\b/g },
  { category: "HUGGINGFACE_TOKEN", rx: /\b(hf_[A-Za-z0-9]{34,})\b/g },
  { category: "NPM_TOKEN", rx: /\b(npm_[A-Za-z0-9]{36})(?![\w])/g },
  { category: "PYPI_TOKEN", rx: /\b(pypi-[A-Za-z0-9\-_]{50,})(?![\w-])/g },
  { category: "SLACK_TOKEN", rx: /\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b/g },
  {
    category: "API_KEY",
    rx: /\b(sk-(?:ant|proj|svcacct|admin)-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z_-]{35}|[rs]k_live_[0-9A-Za-z]{24,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|do[po]_v1_[a-f0-9]{64})(?![\w-])/g,
  },
  { category: "JWT", rx: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { category: "URL_CREDENTIAL", rx: /:\/\/(?:[^\s:/@]*:)?([^\s@/]{3,})@/g },
  {
    category: "SECRET",
    rx: new RegExp(
      `(?:^|[\\s;,{("'])(?:export\\s+)?(?:[A-Za-z0-9]+[_-])*(?:${SEC_WORDS})(?:[_-][A-Za-z0-9]+)*["']?\\s*[=:]\\s*(?:"([^"\\r\\n]{8,})"|'([^'\\r\\n]{8,})'|([A-Za-z0-9_~%+=-]{8,})(?![A-Za-z0-9_~%+=-]|[.(]))`,
      "gi",
    ),
  },
  { category: "BEARER", rx: /\bBearer\s+([A-Za-z0-9._~+/=-]{16,})/gi },
]

const BENIGN_SET = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "none",
  "unknown",
  "example",
  "changeme",
  "dummy",
  "placeholder",
  "password",
  "secret",
  "token",
])

function isSafeOrPlaceholder(secret: string | undefined, quoteType?: "double" | "single" | "none"): boolean {
  if (!secret || typeof secret !== "string") return true
  if (BENIGN_SET.has(secret.trim().toLowerCase())) return true
  if (/^\[REDACTED_[A-Z_]+_#\d+\]$/.test(secret)) return true
  if (/^(?:<[A-Za-z0-9_ -]+>|\([A-Za-z0-9_ -]+\)|\[[A-Za-z0-9_ -]+\]|\*+|\.+)$/.test(secret)) return true
  // Single-quoted strings in shell/JSON are literal values, not variable expansions
  if (quoteType === "single") return false
  if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(secret)) return true
  return false
}

export function detectSecrets(
  text: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  useGitleaks = true,
): { category: string; detected: string; sample: string } | null {
  if (typeof text !== "string" || !text) return null
  for (const { category, rx } of RULES) {
    rx.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = rx.exec(text)) !== null) {
      let captured: string | undefined
      let quoteType: "double" | "single" | "none" | undefined
      if (category === "SECRET") {
        if (m[1]) {
          captured = m[1]
          quoteType = "double"
        } else if (m[2]) {
          captured = m[2]
          quoteType = "single"
        } else if (m[3]) {
          captured = m[3]
          quoteType = "none"
        }
      } else {
        captured = m.slice(1, 4).find((g): g is string => typeof g === "string" && g.length > 0)
      }
      if (captured && !isSafeOrPlaceholder(captured, quoteType)) {
        return {
          category,
          detected: captured,
          sample: captured.length > 8 ? `${captured.slice(0, 4)}...${captured.slice(-4)}` : "[SECRET]",
        }
      }
    }
  }
  if (useGitleaks && config.enableGitleaks && text.length >= config.gitleaksMinBytes) {
    const leaks = scanWithGitleaks(text, config.gitleaksTimeoutMs)
    if (leaks.length > 0) {
      const first = leaks[0]
      return {
        category: "GITLEAKS_DETECTED",
        detected: first,
        sample: first.length > 8 ? `${first.slice(0, 4)}...${first.slice(-4)}` : "[SECRET]",
      }
    }
  }
  return null
}

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

  private replaceKnown(text: string): string {
    if (this.secretToToken.size === 0) return text
    let out = text
    const sorted = [...this.secretToToken.keys()].sort((a, b) => b.length - a.length)
    for (const secret of sorted) {
      if (out.includes(secret)) {
        out = out.split(secret).join(this.secretToToken.get(secret)!)
      }
    }
    return out
  }

  /** Replaces secrets with stable tokens. gitleaks (optional) only runs on large inputs. */
  redact(text: string, useGitleaks = false): string {
    if (typeof text !== "string" || !text) return text
    let out = this.replaceKnown(text)

    for (const { category, rx } of RULES) {
      rx.lastIndex = 0
      out = out.replace(rx, (match: string, ...args: unknown[]) => {
        const offsetIndex = args.findIndex((a) => typeof a === "number")
        const groups = (offsetIndex >= 0 ? args.slice(0, offsetIndex) : args.slice(0, -2)) as (string | undefined)[]
        let secret: string | undefined
        let quoteType: "double" | "single" | "none" | undefined

        if (category === "SECRET") {
          if (groups[0]) {
            secret = groups[0]
            quoteType = "double"
          } else if (groups[1]) {
            secret = groups[1]
            quoteType = "single"
          } else if (groups[2]) {
            secret = groups[2]
            quoteType = "none"
          }
        } else {
          secret = groups.find((group): group is string => typeof group === "string" && group.length > 0)
        }

        if (!secret || isSafeOrPlaceholder(secret, quoteType)) return match
        const index = match.lastIndexOf(secret)
        const token = this.tokenFor(secret, category)
        return match.slice(0, index) + token + match.slice(index + secret.length)
      })
    }

    out = this.replaceKnown(out)

    if (useGitleaks && this.config.enableGitleaks && out.length >= this.config.gitleaksMinBytes) {
      for (const secret of scanWithGitleaks(out, this.config.gitleaksTimeoutMs)) {
        if (!isSafeOrPlaceholder(secret)) {
          out = out.split(secret).join(this.tokenFor(secret, "SECRET"))
        }
      }
    }
    return out
  }
}

let gitleaksAvailable: boolean | null = null

export function hasGitleaks(): boolean {
  if (gitleaksAvailable === null) {
    try {
      gitleaksAvailable = cp.spawnSync("gitleaks", ["version"], { timeout: 500, stdio: "ignore" }).status === 0
    } catch {
      gitleaksAvailable = false
    }
  }
  return gitleaksAvailable
}

export function scanWithGitleaks(text: string, timeoutMs = 500): string[] {
  if (!hasGitleaks()) return []
  try {
    const result = cp.spawnSync(
      "gitleaks",
      ["stdin", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"],
      { input: text, timeout: timeoutMs, encoding: "utf-8", maxBuffer: 10 * 1024 * 1024 },
    )
    const found = JSON.parse(result.stdout || "[]") as unknown
    if (!Array.isArray(found)) return []
    return found
      .map((entry) => (entry && typeof entry === "object" ? (entry as { Secret?: unknown }).Secret : ""))
      .filter((secret): secret is string => typeof secret === "string" && secret.length >= 8 && !isSafeOrPlaceholder(secret))
  } catch {
    return []
  }
}

// -----------------------------------------------------------------------------
// Path Protection (Null-byte, URL-decoding, Braces, Wildcards, Symlinks)
// -----------------------------------------------------------------------------

const SAMPLE_SENSITIVE_BASENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".envrc",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "private.key",
  "server.pem",
  "cert.p12",
  "cert.pfx",
  ".netrc",
  ".git-credentials",
  ".bashrc",
  ".zshrc",
  "auth.json",
]

function expandHome(value: string, cwd: string = process.cwd()): string {
  if (typeof value !== "string") return ""
  const home = homeDir()
  return value
    .replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, home)
    .replace(/\$\{HOME\}|\$HOME\b/g, home)
    .replace(/^(?:~\+|\$PWD|\$\{PWD\})(?=\/|$)/, cwd)
    .replace(/\$\{PWD\}|\$PWD\b/g, cwd)
}

function expandBraces(input: string, depth = 0): string[] {
  if (typeof input !== "string" || depth > 4) return [input]
  const m = input.match(/^(.*?)\{([^{}]+)\}(.*)$/)
  if (!m || !m[2].includes(",")) return [input]
  return m[2]
    .split(",")
    .slice(0, 16)
    .flatMap((part) => expandBraces(m[1] + part + m[3], depth + 1))
}

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

function shellWildcardToRegExp(pat: string): RegExp {
  let s = ""
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i]
    if (c === "*") s += "[^/]*"
    else if (c === "?") s += "[^/]"
    else if (c === "[") {
      const close = pat.indexOf("]", i + 1)
      if (close !== -1) {
        s += `[${pat.slice(i + 1, close).replace(/\\/g, "\\\\")}]`
        i = close
      } else s += "\\["
    } else s += c.replace(/[.+^${}()|\\]/g, "\\$&")
  }
  return new RegExp(`^${s}$`, "i")
}

function canonical(target: string, depth = 0): string {
  try {
    return fs.realpathSync(target)
  } catch {
    // not resolvable as-is
  }
  try {
    if (depth < 8 && fs.lstatSync(target).isSymbolicLink()) {
      const linkTarget = fs.readlinkSync(target)
      return canonical(path.isAbsolute(linkTarget) ? linkTarget : path.resolve(path.dirname(target), linkTarget), depth + 1)
    }
  } catch {
    // does not exist
  }
  const parent = path.dirname(target)
  return parent === target ? target : path.join(canonical(parent, depth), path.basename(target))
}

function matches(pattern: string, abs: string, cwd: string): boolean {
  let glob = expandHome(pattern.replace(/\\/g, "/"), cwd)
  const norm = abs.replace(/\\/g, "/")
  if (!glob.includes("/")) return globToRegExp(glob).test(path.basename(norm))
  const isAbs = glob.startsWith("/") || /^[A-Za-z]:\//.test(glob)
  if (!isAbs && !glob.startsWith("**")) glob = `${cwd.replace(/\\/g, "/")}/${glob}`
  if (globToRegExp(glob).test(norm)) return true
  if (glob.endsWith("/**") && globToRegExp(glob.slice(0, -3)).test(norm)) return true

  const prefix = glob.replace(/\/\*\*?.*$/, "")
  const canonicalPrefix = canonical(prefix).replace(/\\/g, "/")
  if (canonicalPrefix !== prefix) {
    const canonicalGlob = canonicalPrefix + glob.slice(prefix.length)
    if (globToRegExp(canonicalGlob).test(norm)) return true
    if (canonicalGlob.endsWith("/**") && globToRegExp(canonicalGlob.slice(0, -3)).test(norm)) return true
  }
  return false
}

export interface PathCheck {
  protected: boolean
  reason?: string
}

function checkSinglePath(
  cleaned: string,
  config: DlpGuardConfig,
  cwd: string,
  op: "read" | "write",
  allowWildcardExpand = true,
): PathCheck {
  const lexical = path.resolve(cwd, expandHome(cleaned, cwd))
  const canon = canonical(lexical)
  const template = TEMPLATE_ENV.test(path.basename(lexical)) && TEMPLATE_ENV.test(path.basename(canon))
  const candidates = new Set([lexical, canon])

  for (const pattern of config.protectedPaths) {
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

  const base = path.basename(lexical)
  if (allowWildcardExpand && /[*?[\]]/.test(base)) {
    const wildRx = shellWildcardToRegExp(base)
    const parentDir = path.dirname(lexical)
    try {
      if (fs.existsSync(parentDir) && fs.statSync(parentDir).isDirectory()) {
        for (const entry of fs.readdirSync(parentDir)) {
          if (wildRx.test(entry)) {
            const sub = checkSinglePath(path.join(parentDir, entry), config, cwd, op, false)
            if (sub.protected) return sub
          }
        }
      }
    } catch {
      // ignore unreadable directory
    }
    const nonWild = base.replace(/[*?[\]]/g, "")
    if (nonWild.length >= 2 || base.startsWith(".")) {
      for (const sample of SAMPLE_SENSITIVE_BASENAMES) {
        if (wildRx.test(sample)) {
          const sub = checkSinglePath(path.join(parentDir, sample), config, cwd, op, false)
          if (sub.protected) return sub
        }
      }
    }
  }

  return { protected: false }
}

export function isPathProtected(
  targetPath: string,
  config: DlpGuardConfig = DEFAULT_CONFIG,
  cwd: string = process.cwd(),
  op: "read" | "write" = "read",
): PathCheck {
  if (typeof targetPath !== "string" || !targetPath.trim()) return { protected: false }
  if (targetPath.includes("\0")) return { protected: true, reason: "null-byte injection detected" }

  let cleaned = targetPath.trim()
  for (let pass = 0; pass < 2; pass++) {
    try {
      if (!/%[0-9a-fA-F]{2}/.test(cleaned)) break
      const decoded = decodeURIComponent(cleaned)
      if (decoded === cleaned) break
      cleaned = decoded
    } catch {
      break
    }
  }
  if (cleaned.includes("\0")) return { protected: true, reason: "null-byte injection detected" }

  for (const variant of expandBraces(cleaned)) {
    const res = checkSinglePath(variant, config, cwd, op, true)
    if (res.protected) return res
  }
  return { protected: false }
}

// -----------------------------------------------------------------------------
// Deep Bash Analysis & Anti-Obfuscation Engine
// -----------------------------------------------------------------------------

interface Segment {
  words: string[]
  redirects: string[]
  inputRedirects: string[]
  pipedToNext: boolean
}

function decodeAnsiC(str: string): string {
  return str
    .replace(/\\x([0-9a-fA-F]{1,2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{1,4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\0?([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\(['"\\])/g, "$1")
}

function parseSegments(cmd: string): Segment[] {
  const segments: Segment[] = []
  let seg: Segment = { words: [], redirects: [], inputRedirects: [], pipedToNext: false }
  let word = ""
  let inWord = false
  let quote = ""
  let ansiC = false
  let ansiBuf = ""
  let redirMode: "write" | "read" | null = null

  const endWord = () => {
    if (!inWord) return
    if (redirMode === "write") seg.redirects.push(word)
    else if (redirMode === "read") seg.inputRedirects.push(word)
    else seg.words.push(word)
    redirMode = null
    word = ""
    inWord = false
  }

  const endSegment = (isPipe = false) => {
    endWord()
    redirMode = null
    while (seg.words[0] === "{") seg.words.shift()
    while (seg.words[seg.words.length - 1] === "}") seg.words.pop()
    if (seg.words.length || seg.redirects.length || seg.inputRedirects.length) {
      seg.pipedToNext = isPipe
      segments.push(seg)
    }
    seg = { words: [], redirects: [], inputRedirects: [], pipedToNext: false }
  }

  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (!quote && (cmd.startsWith("$IFS", i) || cmd.startsWith("${IFS}", i))) {
      endWord()
      i += cmd[i + 1] === "{" ? 5 : 3
      continue
    }
    if (quote) {
      if (c === quote) {
        if (ansiC) {
          word += decodeAnsiC(ansiBuf)
          ansiBuf = ""
          ansiC = false
        }
        quote = ""
      } else if (ansiC) {
        ansiBuf += c === "\\" && i + 1 < cmd.length ? c + cmd[++i] : c
      } else if (c === "\\" && quote === '"' && i + 1 < cmd.length) {
        word += cmd[++i]
      } else {
        word += c
      }
    } else if (c === "$" && (cmd[i + 1] === "'" || cmd[i + 1] === '"')) {
      quote = cmd[++i]
      ansiC = quote === "'"
      ansiBuf = ""
      inWord = true
    } else if (c === "$" && cmd[i + 1] === "(") {
      let depth = 1
      word += "$("
      inWord = true
      i += 2
      while (i < cmd.length && depth > 0) {
        if (cmd[i] === "(") depth++
        else if (cmd[i] === ")") depth--
        word += cmd[i++]
      }
      i--
    } else if (c === "'" || c === '"') {
      quote = c
      inWord = true
    } else if (c === "\\" && i + 1 < cmd.length) {
      word += cmd[++i]
      inWord = true
    } else if (c === "(" || c === ")") {
      endSegment(false)
    } else if (c === "|" && cmd[i + 1] !== "|") {
      endSegment(true)
    } else if (c === "|" && cmd[i + 1] === "|") {
      i++
      endSegment(false)
    } else if (c === ";" || c === "\n") {
      endSegment(false)
    } else if (c === "&") {
      const prev = cmd[i - 1]
      const next = cmd[i + 1]
      if (next === "&") {
        i++
        endSegment(false)
      } else if (next === ">") {
        endWord()
        i++
        if (cmd[i + 1] === ">") i++
        redirMode = "write"
      } else if (prev === ">" || prev === "<") {
        if (/[0-9-]/.test(next || "")) {
          word += c
          inWord = true
        } else {
          redirMode = "write"
        }
      } else {
        endSegment(false)
      }
    } else if (c === ">") {
      if (inWord && /^[0-9]+$/.test(word)) {
        word = ""
        inWord = false
      } else {
        endWord()
      }
      if (cmd[i + 1] === ">" || cmd[i + 1] === "|") i++
      if (cmd[i + 1] === "(") endSegment(false)
      else redirMode = "write"
    } else if (c === "<") {
      if (inWord && /^[0-9]+$/.test(word)) {
        word = ""
        inWord = false
      } else {
        endWord()
      }
      if (cmd[i + 1] === "<") {
        i++
        if (cmd[i + 1] === "<") i++
        redirMode = null
      } else if (cmd[i + 1] === ">") {
        i++
        redirMode = "write"
      } else if (cmd[i + 1] === "(") {
        endSegment(false)
      } else {
        redirMode = "read"
      }
    } else if (/\s/.test(c)) {
      endWord()
    } else {
      word += c
      inWord = true
    }
  }
  endSegment(false)
  return segments
}

function extractSubshells(cmd: string): string[] {
  const out: string[] = []
  let i = 0
  while (i < cmd.length) {
    if (cmd[i] === "$" && cmd[i + 1] === "(") {
      let depth = 1
      const start = i + 2
      i += 2
      while (i < cmd.length && depth > 0) {
        if (cmd[i] === "(") depth++
        else if (cmd[i] === ")") depth--
        i++
      }
      out.push(cmd.slice(start, depth === 0 ? i - 1 : i))
    } else {
      i++
    }
  }
  for (const m of cmd.matchAll(/`([^`]+)`/g)) {
    if (m[1]) out.push(m[1])
  }
  return out
}

const WRAPPERS = new Set(["sudo", "env", "command", "nohup", "time", "exec", "nice", "builtin", "xargs", "doas", "su", "timeout", "strace", "ltrace"])
const OPTS_WITH_ARG = new Set(["-u", "-g", "-C", "-U", "-r", "-t", "-D", "-n", "-d", "-I", "--user", "--group"])
const MUTATORS = new Set(["rm", "rmdir", "mv", "cp", "ln", "install", "rsync", "touch", "truncate", "chmod", "chown", "chgrp", "tee", "shred", "unlink", "mkdir", "patch", "srm", "wipe", "chattr", "unzip"])
const READERS = new Set(["cat", "head", "tail", "more", "less", "base64", "xxd", "hexdump", "strings", "bat", "view", "nl", "tac", "od", "rev", "shuf", "sort", "uniq", "cut", "paste", "column", "fmt", "pr", "fold", "expand", "unexpand", "wc", "diff", "cmp", "comm", "zcat", "bzcat", "xzcat", "source", "."])
const ARCHIVERS = new Set(["tar", "zip", "7z", "gzip", "bzip2", "xz", "zstd", "cpio"])
const GREP_CMDS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack"])
const AWK_CMDS = new Set(["awk", "gawk", "mawk", "nawk"])
const JQ_CMDS = new Set(["jq", "yq"])
const INTERPRETERS = new Set(["python", "python3", "python2", "node", "bun", "deno", "ruby", "perl", "php", "lua"])
const IN_PLACE_EDITORS = new Set(["sed", "perl", "ruby"])
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"])
const VAR_DECL_CMDS = new Set(["export", "local", "declare", "typeset", "readonly"])

const isFdOrSafe = (t: string) =>
  /^&?[0-9-]+$/.test(t) ||
  t === "-" ||
  /^\/dev\/(?:null|zero|u?random|std(?:out|err|in))$/.test(t)

function applyVars(str: string, vars: Map<string, string>): string {
  if (!vars.size || !str) return str
  return str.replace(/\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)/g, (m, g1, g2) => {
    const k = g1 || g2
    return vars.has(k) ? (vars.get(k) as string) : m
  })
}

function resolveTargetCandidates(raw: string, vars: Map<string, string>): string[] {
  if (!raw) return []
  const withVars = applyVars(raw, vars)
  const out = new Set([raw, withVars])
  for (const base of [raw, withVars]) {
    const sub = base
      .replace(/\$\(\s*echo\s+(?:-[neE]+\s+)?(["']?)([^()"']*)\1\s*\)/g, "$2")
      .replace(/`\s*echo\s+(?:-[neE]+\s+)?(["']?)([^`"']*)\1\s*`/g, "$2")
      .replace(/\$\(\s*printf\s+(?:["']%s["']\s+)?(["']?)([^()"']*)\1\s*\)/g, "$2")
      .replace(/\$\{[A-Za-z_]\w*:[=-]([^}]*)\}/g, "$1")
    out.add(sub)
    const stripped = sub.replace(/\$\{(?!HOME\b|PWD\b)[A-Za-z_]\w*\}|\$(?!HOME\b|PWD\b)[A-Za-z_]\w*/g, "")
    if (stripped && stripped !== "/") out.add(stripped)
  }
  return [...out]
}

function unwrapWords(words: string[]): { cmdName: string; args: string[]; usedXargs: boolean } {
  let i = 0
  let usedXargs = false
  while (i < words.length) {
    const w = words[i]
    if (/^[A-Za-z_]\w*=/.test(w)) {
      i++
      continue
    }
    const base = path.basename(w)
    if (WRAPPERS.has(base)) {
      if (base === "xargs") usedXargs = true
      i++
      if (base === "timeout" && i < words.length && /^[0-9]/.test(words[i])) i++
      while (i < words.length && words[i].startsWith("-")) {
        const next = words[i + 1]
        if (OPTS_WITH_ARG.has(words[i]) && next && !next.startsWith("-") && !MUTATORS.has(next) && !READERS.has(next) && !WRAPPERS.has(next)) {
          i += 2
        } else {
          i++
        }
      }
      continue
    }
    break
  }
  return { cmdName: words[i] ? path.basename(words[i]) : "", args: words.slice(i + 1), usedXargs }
}

function shellScript(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(args[i])) {
      const rest = args.slice(i + 1)
      if (rest.length) return rest[0]
    }
  }
  return undefined
}

function extractStringLiterals(code: string): string[] {
  let folded = code
  for (let pass = 0; pass < 4; pass++) {
    const next = folded
      .replace(/"([^"\\]*)"\s*\+\s*"([^"\\]*)"/g, '"$1$2"')
      .replace(/'([^'\\]*)'\s*\+\s*'([^'\\]*)'/g, "'$1$2'")
    if (next === folded) break
    folded = next
  }
  const literals: string[] = []
  const rx = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`/g
  for (const src of new Set([code, folded])) {
    let m: RegExpExecArray | null
    while ((m = rx.exec(src)) !== null) {
      const lit = (m[1] ?? m[2] ?? m[3] ?? "").trim()
      if (lit) literals.push(lit)
    }
  }
  return literals
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
  if (typeof command !== "string" || !command.trim() || depth > 5) return { block: false }

  if (config.blockInlineSecretsInCommands !== false) {
    const hit = detectSecrets(command, config)
    if (hit) return { block: true, reason: `inline secret detected in command (${hit.category})` }
  }

  const blockReaders = config.blockReaderCommandsOnProtected !== false
  let here = cwd
  const vars = new Map<string, string>()
  const deny = (target: string, reason?: string) => ({
    block: true,
    reason: `shell operation blocked on "${target}" (${reason})`,
  })
  const checkTarget = (raw: string, op: "read" | "write", prefix = "") => {
    for (const c of resolveTargetCandidates(raw, vars)) {
      if (!c || isFdOrSafe(c)) continue
      const check = isPathProtected(c, config, here, op)
      if (check.protected) return deny(raw, prefix ? `${prefix}: ${check.reason}` : check.reason)
    }
    return null
  }

  const nested = extractSubshells(command)
  let pipedArgs: string[] = []
  let pipedFromDecoder = false

  for (const { words, redirects, inputRedirects, pipedToNext } of parseSegments(command)) {
    if (!words.length && !redirects.length && !inputRedirects.length) {
      pipedArgs = []
      pipedFromDecoder = false
      continue
    }

    for (const tok of words) {
      if (VAR_DECL_CMDS.has(tok) || tok.startsWith("-")) continue
      const eq = tok.match(/^([A-Za-z_]\w*)=(.*)$/)
      if (eq) vars.set(eq[1], applyVars(eq[2], vars))
      else break
    }

    const expanded = words.map((w) => applyVars(w, vars))
    const { cmdName, args: rawArgs, usedXargs } = unwrapWords(expanded)
    const args = usedXargs && pipedArgs.length ? [...rawArgs, ...pipedArgs] : rawArgs

    if (cmdName === "agy-dlp" || cmdName === "agy-dlp-guard" || words.some((w) => /agy-dlp(?:-guard)?(?:\.mjs)?$/.test(w))) {
      const tIdx = args.findIndex((a) => /^toggle$/i.test(a))
      if (
        args.some((a) => /^(?:uninstall|off|disable)$/i.test(a)) ||
        (tIdx !== -1 && /^(?:off|false|0|disable)$/i.test(args[tIdx + 1] || ""))
      ) {
        return deny(cmdName || "agy-dlp", "guard integrity: disabling DLP Guard is not allowed")
      }
    }
    if ((cmdName === "opencode" || cmdName === "pi") && args.some((a) => /^(?:uninstall|remove|disable)$/i.test(a)) && args.some((a) => /dlp-guard/i.test(a))) {
      return deny(cmdName, "guard integrity: removing DLP Guard is not allowed")
    }

    if (pipedFromDecoder && (SHELLS.has(cmdName) || cmdName === "eval" || cmdName === "source" || cmdName === ".")) {
      return deny(cmdName, "executing decoded payload piped into shell is blocked")
    }

    if (cmdName === "cd" || cmdName === "pushd") {
      if (args[0]) {
        const resolved = resolveTargetCandidates(args[0], vars).pop() || args[0]
        here = path.resolve(here, expandHome(resolved, here))
      }
      pipedArgs = []
      pipedFromDecoder = false
      continue
    }

    if (SHELLS.has(cmdName)) {
      const script = shellScript(args)
      if (script) nested.push(script)
      else if (blockReaders) {
        for (const a of args.filter((x) => !x.startsWith("-"))) {
          const hit = checkTarget(a, "read", `read/exec via ${cmdName}`)
          if (hit) return hit
        }
      }
    }
    if (cmdName === "eval") nested.push(args.join(" "))

    for (const t of redirects) {
      const hit = checkTarget(t, "write")
      if (hit) return hit
    }
    if (blockReaders) {
      for (const t of inputRedirects) {
        const hit = checkTarget(t, "read", "unauthorized input redirect")
        if (hit) return hit
      }
    }

    if (cmdName === "dd") {
      for (const a of args) {
        if (a.startsWith("if=") && blockReaders) {
          const hit = checkTarget(a.slice(3), "read", "read via dd")
          if (hit) return hit
        } else if (a.startsWith("of=")) {
          const hit = checkTarget(a.slice(3), "write")
          if (hit) return hit
        }
      }
    }

    const inPlace = IN_PLACE_EDITORS.has(cmdName) && args.some((a) => /^-[A-Za-z]*i|^--in-place/.test(a))
    if (MUTATORS.has(cmdName) || inPlace) {
      const targets = cmdName === "sed" ? args.filter((a, idx) => !a.startsWith("-") && idx > 0) : args.filter((a) => !a.startsWith("-"))
      for (const t of targets) {
        const hit = checkTarget(t, "write")
        if (hit) return hit
      }
    }

    if (blockReaders && READERS.has(cmdName)) {
      for (const t of args.filter((a) => !a.startsWith("-"))) {
        const hit = checkTarget(t, "read", `read via ${cmdName}`)
        if (hit) return hit
      }
    }

    if (blockReaders && GREP_CMDS.has(cmdName)) {
      let hasPat = false
      const pos: string[] = []
      const optArg = new Set(["-m", "-A", "-B", "-C", "-g", "-t", "--max-count", "--after-context", "--before-context", "--context", "--glob", "--type", "--include", "--exclude", "--exclude-dir", "--color"])
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        if (a === "-e" || a === "--regexp") {
          hasPat = true
          j++
        } else if (a.startsWith("--regexp=")) hasPat = true
        else if (a === "-f" || a === "--file") {
          hasPat = true
          if (args[j + 1]) {
            const hit = checkTarget(args[++j], "read", `pattern file read via ${cmdName}`)
            if (hit) return hit
          }
        } else if (a.startsWith("--file=")) {
          hasPat = true
          const hit = checkTarget(a.slice(7), "read", `pattern file read via ${cmdName}`)
          if (hit) return hit
        } else if (optArg.has(a)) j++
        else if (!a.startsWith("-")) pos.push(a)
      }
      for (const t of hasPat ? pos : pos.slice(1)) {
        const hit = checkTarget(t, "read", `search/read via ${cmdName}`)
        if (hit) return hit
      }
    }

    if (blockReaders && (cmdName === "sed" || AWK_CMDS.has(cmdName) || JQ_CMDS.has(cmdName))) {
      let hasExpr = false
      const pos: string[] = []
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        if (a === "-f" || a === "--file" || a === "--from-file") {
          hasExpr = true
          if (args[j + 1]) {
            const hit = checkTarget(args[++j], "read", `read via ${cmdName}`)
            if (hit) return hit
          }
        } else if (a.startsWith("--file=")) {
          hasExpr = true
          const hit = checkTarget(a.slice(7), "read", `read via ${cmdName}`)
          if (hit) return hit
        } else if (a === "-e" || a === "--expression") {
          hasExpr = true
          j++
        } else if (a === "-F" || a === "-v") j++
        else if ((a === "--slurpfile" || a === "--rawfile") && j + 2 < args.length) {
          const hit = checkTarget(args[j + 2], "read", `read via ${cmdName}`)
          if (hit) return hit
          j += 2
        } else if ((a === "--arg" || a === "--argjson") && j + 2 < args.length) j += 2
        else if (!a.startsWith("-")) pos.push(a)
      }
      for (const t of hasExpr ? pos : pos.slice(1)) {
        const hit = checkTarget(t, "read", `read via ${cmdName}`)
        if (hit) return hit
      }
    }

    if (ARCHIVERS.has(cmdName)) {
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        if ((a === "-C" || a === "--directory" || a === "-f" || a === "--file") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write")
          if (hit) return hit
        } else if (!a.startsWith("-")) {
          if (blockReaders) {
            const hitR = checkTarget(a, "read", `archive read via ${cmdName}`)
            if (hitR) return hitR
          }
          const hitW = checkTarget(a, "write")
          if (hitW) return hitW
        }
      }
    }

    if (cmdName === "find") {
      const hasDel = args.includes("-delete")
      const execIdx = args.findIndex((a) => a === "-exec" || a === "-execdir" || a === "-ok")
      const targets: string[] = []
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        if (a === "-exec" || a === "-execdir" || a === "-ok") break
        if ((a === "-name" || a === "-iname" || a === "-path" || a === "-wholename") && args[j + 1]) targets.push(args[++j])
        else if (!a.startsWith("-") && a !== "!" && a !== ";") targets.push(a)
      }
      for (const t of targets) {
        if (hasDel) {
          const hit = checkTarget(t, "write")
          if (hit) return hit
        }
        if (blockReaders && (execIdx !== -1 || t !== ".")) {
          const hit = checkTarget(t, "read", "find on protected path")
          if (hit) return hit
        }
      }
      if (execIdx !== -1) {
        const execTokens = args
          .slice(execIdx + 1)
          .filter((a) => a !== ";" && a !== "\\;" && a !== "+")
          .map((a) => (a === "{}" && targets[0] ? targets[0] : a))
        if (execTokens.length) nested.push(execTokens.join(" "))
      }
    }

    if (cmdName === "git") {
      const sub = args[0]
      const isGitMutator = sub === "checkout" || sub === "restore" || sub === "clean"
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        let cand: string | null = null
        if (a.startsWith("--file=")) cand = a.slice(7)
        else if ((a === "-f" || a === "--file") && sub === "config" && args[j + 1]) cand = args[++j]
        else if (!a.startsWith("-") && a !== "--" && j > 0) cand = a.includes(":") && !a.includes("://") ? (a.split(":").pop() ?? a) : a
        if (cand) {
          if (isGitMutator) {
            const hitW = checkTarget(cand, "write", "git mutation on protected path")
            if (hitW) return hitW
          }
          if (blockReaders) {
            const hitR = checkTarget(cand, "read", "git read on protected path")
            if (hitR) return hitR
          }
        }
      }
    }

    if (cmdName === "openssl") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        if ((a === "-in" || a === "-inkey" || a === "-certin") && args[j + 1] && blockReaders) {
          const hit = checkTarget(args[++j], "read", "read via openssl")
          if (hit) return hit
        } else if (a.startsWith("file:") && blockReaders) {
          const hit = checkTarget(a.slice(5), "read", "read via openssl")
          if (hit) return hit
        } else if ((a === "-out" || a === "-keyout") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write")
          if (hit) return hit
        }
      }
    }

    if (cmdName === "scp" || cmdName === "sftp") {
      for (const a of args.filter((x) => !x.startsWith("-"))) {
        const local = a.includes(":") && !a.includes("://") ? (a.split(":").pop() ?? a) : a
        if (blockReaders) {
          const hitR = checkTarget(local, "read", `transfer via ${cmdName}`)
          if (hitR) return hitR
        }
        const hitW = checkTarget(local, "write")
        if (hitW) return hitW
      }
    }

    if (INTERPRETERS.has(cmdName)) {
      const codeFlags = new Set(["-c", "-e", "-p", "-r", "--eval", "--print", "eval"])
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        if (codeFlags.has(a) && args[j + 1]) {
          const code = args[++j]
          const mut = /\b(?:write|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|remove|removedirs|rmtree|rename|replace|chmod|chown|truncate|copyFile|cpSync|shutil)\b/i.test(code)
          for (const lit of extractStringLiterals(code)) {
            if (blockReaders) {
              const hitR = checkTarget(lit, "read", `inline script access via ${cmdName}`)
              if (hitR) return hitR
            }
            if (mut) {
              const hitW = checkTarget(lit, "write", `inline script write via ${cmdName}`)
              if (hitW) return hitW
            }
          }
        } else if (!a.startsWith("-") && blockReaders) {
          const hit = checkTarget(a, "read", `exec/read via ${cmdName}`)
          if (hit) return hit
        }
      }
    }

    if (cmdName === "curl") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        let rT: string | null = null
        let wT: string | null = null
        if (a.startsWith("@")) rT = a.slice(1)
        else if (a.includes("=@")) rT = a.split("=@")[1]
        else if ((a === "-T" || a === "--upload-file") && args[j + 1]) rT = args[++j]
        else if ((a === "-o" || a === "--output") && args[j + 1]) wT = args[++j]
        else if (a.startsWith("--output=")) wT = a.slice(9)
        if (rT) {
          const hit = checkTarget(rT, "read", "exfiltration via curl")
          if (hit) return hit
        }
        if (wT) {
          const hit = checkTarget(wT, "write")
          if (hit) return hit
        }
      }
    }

    if (cmdName === "wget") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j]
        let rT: string | null = null
        let wT: string | null = null
        if (a.startsWith("--post-file=")) rT = a.slice(12)
        else if (a === "--post-file" && args[j + 1]) rT = args[++j]
        else if ((a === "-O" || a === "--output-document" || a === "-P" || a === "--directory-prefix") && args[j + 1]) wT = args[++j]
        else if (a.startsWith("--output-document=")) wT = a.slice(18)
        else if (a.startsWith("--directory-prefix=")) wT = a.slice(19)
        if (rT) {
          const hit = checkTarget(rT, "read", "exfiltration via wget")
          if (hit) return hit
        }
        if (wT) {
          const hit = checkTarget(wT, "write")
          if (hit) return hit
        }
      }
    }

    if (pipedToNext) {
      if (cmdName === "echo" || cmdName === "printf") {
        pipedArgs = args.filter((a) => !a.startsWith("-"))
        pipedFromDecoder = false
      } else if ((cmdName === "base64" && args.some((a) => /^-(?:d|D|-decode)$/.test(a))) || (cmdName === "xxd" && args.includes("-r"))) {
        pipedFromDecoder = true
        for (const cand of pipedArgs) {
          try {
            const dec = Buffer.from(cand, "base64").toString("utf-8")
            if (dec && /^[\x20-\x7e\s]+$/.test(dec)) nested.push(dec)
          } catch {
            // ignore
          }
        }
      } else {
        pipedArgs = []
        pipedFromDecoder = false
      }
    } else {
      pipedArgs = []
      pipedFromDecoder = false
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
const WRITE_TOOL =
  /write|edit|replace|patch|create|delete|remove|destroy|unlink|move|rename|apply|upload|install|save|put|store|append|touch|truncate/i
const OUTBOUND_TOOL = /search|web|fetch|http|url|curl|request|send|post|mcp/i
const PATH_KEY =
  /^(?:path|paths|file|files|filepath|file_path|filename|directory|dir|folder|cwd|workdir|root|target|destination|dest|source|src|from|to|uri|url|old_?path|new_?path|source_?path|target_?path|dest_?path)$/i

function extractFilePath(raw: string): string | undefined {
  if (typeof raw !== "string" || !raw.trim()) return undefined
  let val = raw.trim()
  if (val.startsWith("file://")) {
    try {
      val = fileURLToPath(val)
    } catch {
      val = val.slice(7)
    }
  } else if (val.includes("://")) {
    return undefined
  }
  return val
}

function collectPaths(value: unknown, out: string[], depth = 0, isWriteTool = false): void {
  if (depth > 6 || !value || typeof value !== "object") return
  if (Array.isArray(value)) {
    for (const item of value) collectPaths(item, out, depth + 1, isWriteTool)
    return
  }
  const obj = value as Record<string, unknown>
  const hasExplicitFilePath = Object.keys(obj).some((k) => /^(?:path|paths|file|files|filepath|file_path|target_?file|target_?path)$/i.test(k))
  for (const [key, item] of Object.entries(obj)) {
    // On edit/replace tools, `target` is the text snippet to replace when a file path key is already present
    if (isWriteTool && hasExplicitFilePath && /^target$/i.test(key)) continue
    if (PATH_KEY.test(key)) {
      const values = Array.isArray(item) ? item : [item]
      for (const entry of values) {
        if (typeof entry === "string") {
          const p = extractFilePath(entry)
          if (p) out.push(p)
        }
      }
    } else if (item && typeof item === "object") {
      collectPaths(item, out, depth + 1, isWriteTool)
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

function extractWriteTexts(input: Record<string, unknown>): string {
  const chunks: string[] = []
  for (const k of ["content", "Content", "replacement", "Replacement", "replacementContent", "ReplacementContent", "newText", "new_str", "patchText", "patch"]) {
    if (typeof input[k] === "string" && input[k]) chunks.push(input[k] as string)
  }
  const list = input.edits || input.Edits || input.replacementChunks || input.ReplacementChunks
  if (Array.isArray(list)) {
    for (const item of list) {
      if (item && typeof item === "object") {
        const rec = item as Record<string, unknown>
        const txt = rec.newText || rec.new_str || rec.replacement || rec.Replacement || rec.replacementContent || rec.ReplacementContent || rec.content || ""
        if (typeof txt === "string" && txt) chunks.push(txt)
      }
    }
  }
  return chunks.join("\n")
}

function extractOutboundTexts(input: Record<string, unknown>): string {
  const out: string[] = []
  for (const [k, v] of Object.entries(input)) {
    if (PATH_KEY.test(k) && k.toLowerCase() !== "url") continue
    if (typeof v === "string" && v) out.push(v)
  }
  return out.join(" ")
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
      ? path.resolve(cwd, expandHome(data.workdir, cwd))
      : typeof data.cwd === "string"
        ? path.resolve(cwd, expandHome(data.cwd, cwd))
        : cwd

  if (SHELL_TOOL.test(tool)) {
    const command =
      typeof data.command === "string"
        ? data.command
        : typeof data.CommandLine === "string"
          ? data.CommandLine
          : typeof data.cmd === "string"
            ? data.cmd
            : ""
    return checkBashCommand(command, config, workdir)
  }

  const isWrite = WRITE_TOOL.test(tool)
  const op = isWrite ? "write" : "read"
  const targets: string[] = []
  collectPaths(data, targets, 0, isWrite)
  if (isWrite) targets.push(...patchPaths(data))

  for (const target of targets) {
    const check = isPathProtected(target, config, workdir, op)
    if (check.protected) return { block: true, reason: `${target}: ${check.reason}` }
  }

  if (isWrite && config.blockWriteSecrets !== false) {
    const hit = detectSecrets(extractWriteTexts(data), config, true)
    if (hit) return { block: true, reason: `${targets[0] || tool}: plaintext secret detected (${hit.category})` }
  }

  if (!isWrite && (OUTBOUND_TOOL.test(tool) || targets.length === 0)) {
    const hit = detectSecrets(extractOutboundTexts(data), config, false)
    if (hit) return { block: true, reason: `${tool}: outbound secret exfiltration blocked (${hit.category})` }
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
