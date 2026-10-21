/**
 * Regression suite for opencode-dlp-guard. Run with `pnpm test`.
 * HOME and XDG_CONFIG_HOME point to temp dirs so the real config never leaks in.
 */

import assert from "node:assert/strict"
import cp from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import test from "node:test"

const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dlp-home-")))
const cwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dlp-cwd-")))
process.env.HOME = home
process.env.XDG_CONFIG_HOME = path.join(home, ".config")
delete process.env.OPENCODE_DLP_CONFIG
process.chdir(cwd)

const core = await import("../src/core.ts")
const C = core.DEFAULT_CONFIG
core.setGuardDirectory(path.join(home, "guard"))

const AWS = ["AKIA", "IOSFODNN7EXAMPLE"].join("")
const GH = ["ghp_", "1234567890".repeat(3), "123456"].join("")
const NPM = ["npm_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"].join("")
const JWT = [
  "eyJhbGciOiJIUzI1NiJ9",
  "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
  "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
].join(".")

const prot = (target: string, op: "read" | "write" = "read", config = C) =>
  core.isPathProtected(target, config, cwd, op).protected
const blocked = (command: string) => core.checkBashCommand(command, C, cwd).block
const hasGitleaks =
  cp.spawnSync("gitleaks", ["version"], { stdio: "ignore" }).status === 0

test("path guard: .env variants are protected, templates are not", () => {
  for (const target of [".env", ".env.local", "./.env", "../../.env", "a/b/../../.env"]) {
    assert.ok(prot(target), target)
  }
  for (const target of [".env.example", ".env.sample", ".env.template"]) {
    assert.ok(!prot(target), target)
  }
})

test("path guard: credentials, keys and shell rc files", () => {
  for (const target of [
    "~/.ssh/id_rsa",
    "$HOME/.aws/credentials",
    ".git/config",
    "certs/server.pem",
    "keys/private.key",
    "~/.zshrc.local",
    "~/.config/opencode/auth.json",
  ]) {
    assert.ok(prot(target), target)
  }
})

test("path guard: benign files are not protected", () => {
  for (const target of ["src/index.ts", "package.json", "README.md", "environment.ts", "my.git/notes.txt"]) {
    assert.ok(!prot(target), target)
  }
})

test("path guard: cwd-relative patterns only match under cwd", () => {
  const config = { ...C, protectedPaths: ["secrets/**"] }
  assert.ok(prot("secrets/a.txt", "read", config))
  assert.ok(!prot("other/secrets/a.txt", "read", config))
})

test("path guard: symlink to a built-in protected file", () => {
  fs.writeFileSync(path.join(cwd, ".env"), "X=1\n")
  fs.symlinkSync(path.join(cwd, ".env"), path.join(cwd, "innocent.txt"))
  assert.ok(prot("innocent.txt"))
})

test("path guard: symlink to a configured protected file", () => {
  const config = { ...C, protectedPaths: ["**/vault.txt"] }
  fs.writeFileSync(path.join(cwd, "vault.txt"), "x")
  fs.symlinkSync(path.join(cwd, "vault.txt"), path.join(cwd, "plain"))
  assert.ok(prot("plain", "read", config))
})

test("path guard: dangling symlink into an integrity path is blocked for write", () => {
  fs.symlinkSync(path.join(home, ".config/opencode/plugins/evil.ts"), path.join(cwd, "dangling"))
  assert.ok(prot("dangling", "write"))
  assert.ok(!prot("dangling", "read"))
})

test("path guard: integrity paths allow reads and block writes", () => {
  assert.ok(!prot("~/.config/opencode/settings.json", "read"))
  assert.ok(prot("~/.config/opencode/settings.json", "write"))
  assert.ok(prot("~/.config/opencode/dlp-guard.json", "write"))
  assert.ok(prot("~/.local/share/opencode/opencode.db", "read"))
})

test("path guard: the package's own directory is write-protected", () => {
  const own = path.join(home, "guard", "src", "index.ts")
  assert.ok(prot(own, "write"))
  assert.ok(!prot(own, "read"))
})

test("path guard: templates do not punch holes in directory protections", () => {
  assert.ok(!prot("src/.env.example", "read"))
  assert.ok(prot("~/.ssh/.env.example", "read"))
  assert.ok(prot("~/.ssh/.env.example", "write"))
})

test("config: loads overrides, falls back on invalid values, creates the file", () => {
  const file = path.join(home, "custom", "dlp.json")
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(
    file,
    JSON.stringify({
      protectedPaths: ["secret/**"],
      integrityPaths: [],
      enableGitleaks: false,
      gitleaksMinBytes: 10,
      gitleaksTimeoutMs: 20,
    }),
  )
  const loaded = core.loadConfig(file)
  assert.deepEqual(loaded.protectedPaths, ["secret/**"])
  assert.equal(loaded.enableGitleaks, false)
  assert.equal(loaded.gitleaksMinBytes, 10)

  const missing = path.join(home, "fresh", "dlp.json")
  assert.equal(core.ensureConfigFile(missing, C), true)
  assert.equal(fs.existsSync(missing), true)
  assert.equal(core.ensureConfigFile(missing, C), false)
  assert.deepEqual(core.loadConfig(missing).protectedPaths, C.protectedPaths)
})

test("config: invalid JSON returns defaults", () => {
  const file = path.join(home, "broken.json")
  fs.writeFileSync(file, "{ not json")
  assert.deepEqual(core.loadConfig(file).protectedPaths, C.protectedPaths)
})

test("bash guard: redirects and tee to protected paths", () => {
  for (const command of [
    "echo x > .env",
    "echo x >> ~/.config/opencode/settings.json",
    "echo x>~/.config/opencode/s.json",
    "echo x | tee ~/.ssh/k",
  ]) {
    assert.ok(blocked(command), command)
  }
})

test("bash guard: mutating commands", () => {
  for (const command of [
    "rm -rf ~/.config/opencode",
    "cp evil.ts ~/.config/opencode/plugins/",
    "ln -s evil ~/.config/opencode/plugins/e.ts",
    "sed -i s/a/b/ ~/.config/opencode/settings.json",
    "mv x $HOME/.config/opencode/y",
    "dd if=/dev/zero of=.env",
    "install -m 600 evil.ts .env",
    "tar -xf archive.tar -C ~/.ssh",
    "truncate -s 0 .env",
  ]) {
    assert.ok(blocked(command), command)
  }
})

test("bash guard: chained and sequential commands", () => {
  for (const command of [
    "cd /tmp && rm -rf ~/.config/opencode",
    "ls; rm ~/.config/opencode/settings.json",
    "true || cp x ~/.config/opencode/y",
    "echo a & rm ~/.ssh/known_hosts",
    "echo a | cat\nrm ~/.config/opencode/settings.json",
  ]) {
    assert.ok(blocked(command), command)
  }
})

test("bash guard: cd is tracked across a chain", () => {
  assert.ok(blocked("cd ~/.config/opencode && rm settings.json"))
  assert.ok(blocked("cd ~/.config/opencode && echo x > settings.json"))
  assert.ok(!blocked("cd ~/.config/opencode && cat settings.json"))
})

test("bash guard: nested code (sh -c, eval, $(), backticks)", () => {
  for (const command of [
    'sh -c "rm ~/.config/opencode/settings.json"',
    'bash -lc "rm ~/.config/opencode/settings.json"',
    'eval "rm ~/.config/opencode/settings.json"',
    "echo $(rm ~/.config/opencode/settings.json)",
    "echo `rm ~/.config/opencode/settings.json`",
  ]) {
    assert.ok(blocked(command), command)
  }
})

test("bash guard: quote splitting does not hide the target", () => {
  assert.ok(blocked("rm ~/.config/opencode/sett''ings.json"))
  assert.ok(blocked('rm "$HOME/.config/opencode/settings.json"'))
})

test("bash guard: reads, searches and ordinary commands pass", () => {
  for (const command of [
    "cat ~/.config/opencode/settings.json",
    "cat .env",
    'grep -rn "\\.env" src/',
    "git status",
    "pnpm test",
    "echo hi > /tmp/out.txt && cat .env",
    "ls 2>/dev/null",
    "echo err >&2",
    "cp a.txt b.txt",
    "cat > /tmp/x.txt << 'EOF'\nsee .env docs\nEOF",
  ]) {
    assert.ok(!blocked(command), command)
  }
})

test("tool routing: structured tools by path and operation", () => {
  assert.equal(core.scanToolCall("read", { path: ".env" }, C, cwd).block, true)
  assert.equal(core.scanToolCall("write", { path: "src/a.ts", content: "x" }, C, cwd).block, false)
  assert.equal(core.scanToolCall("write", { path: "src/a.ts", content: ".env" }, C, cwd).block, false)
  assert.equal(core.scanToolCall("edit", { filePath: "~/.config/opencode/opencode.json" }, C, cwd).block, true)
  assert.equal(core.scanToolCall("read", { paths: ["src/a.ts", "~/.ssh/id_rsa"] }, C, cwd).block, true)
  assert.equal(core.scanToolCall("mcp_server_read_file", { path: "certs/x.pem" }, C, cwd).block, true)
})

test("tool routing: patch headers", () => {
  const patchText = [
    "*** Begin Patch",
    "*** Update File: src/a.ts",
    "*** Move to: .env",
    "*** End Patch",
  ].join("\n")
  assert.equal(core.scanToolCall("patch", { patchText }, C, cwd).block, true)

  const clean = ["*** Begin Patch", "*** Add File: src/b.ts", "*** End Patch"].join("\n")
  assert.equal(core.scanToolCall("patch", { patchText: clean }, C, cwd).block, false)
})

test("tool routing: shell uses workdir for relative targets", () => {
  assert.equal(core.scanToolCall("shell", { command: "rm known_hosts", workdir: "~/.ssh" }, C, cwd).block, true)
  assert.equal(core.scanToolCall("shell", { command: "git status", workdir: cwd }, C, cwd).block, false)
})

test("redaction: known token formats", () => {
  const redactor = new core.SecretRedactor(C)
  const cases: Record<string, string | string[]> = {
    AWS_KEY: AWS,
    GITHUB_TOKEN: GH,
    API_KEY: [
      "sk-ant-api03-" + "Ab1_".repeat(20),
      "AIzaSy" + "A1b2C3d4E5".repeat(3) + "f6G",
      "sk-" + "a1B2c3D4e5".repeat(4) + "abcd",
    ],
    SLACK_TOKEN: ["xoxb-", "1234567890-", "abcdefghij"].join(""),
    URL_CREDENTIAL: "postgres://admin:S3cretPw@db:5432/x",
    PRIVATE_KEY: ["-----", "BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m8d\n-----", "END RSA PRIVATE KEY-----"].join(""),
    JWT,
    BEARER: "Bearer abcdefghijklmnopqrstuvwxyz0123456789",
  }
  for (const [category, values] of Object.entries(cases)) {
    for (const value of ([] as string[]).concat(values)) {
      const out = redactor.redact(`x ${value} y`)
      assert.match(out, new RegExp(`\\[REDACTED_${category}_#\\d+\\]`), `${category}: ${out}`)
      assert.ok(!out.includes(value.slice(8, 20)), `${category} leaked`)
    }
  }
})

test("redaction: NAME=value forms, including bare PASSWORD/TOKEN/SECRET and JSON", () => {
  for (const value of [
    "export DATABASE_PASSWORD='ultra_secure_db_pass_999'",
    "PASSWORD=hunter2hunter2",
    "TOKEN=abcdef123456",
    "SECRET=abcdef123456",
    "DB_PASS=hunter2hunter2",
    '{"api_key": "abcdef0123456789"}',
  ]) {
    const redactor = new core.SecretRedactor(C)
    assert.match(redactor.redact(value), /\[REDACTED_SECRET_#1\]/, value)
  }
})

test("redaction: the same secret keeps the same token, different secrets differ", () => {
  const redactor = new core.SecretRedactor(C)
  const other = ["AKIA", "1".repeat(16)].join("")
  const out = redactor.redact(`${AWS} ${AWS} ${other}`)
  assert.equal(out.match(/#1\]/g)?.length, 2)
  assert.equal(out.match(/#2\]/g)?.length, 1)
})

test("redaction: idempotent, placeholders are never re-redacted", () => {
  const redactor = new core.SecretRedactor(C)
  const once = redactor.redact(`API_KEY=hunter2hunter2 and ${AWS}`)
  assert.equal(redactor.redact(once), once)
})

test("redaction: no false positives", () => {
  const redactor = new core.SecretRedactor(C)
  for (const value of [
    "MONKEY=banana12345",
    "AUTHOR=John Smith Jr",
    "KEY=short",
    "API_KEY=$OTHER_VARIABLE",
    "const port = 3000;",
    "commit 3f786850e387550fdab836ed7e6dc881de23001b",
  ]) {
    assert.equal(redactor.redact(value), value, value)
  }
})

test("redaction: tool result text parts and nested output", () => {
  const redactor = new core.SecretRedactor(C)
  const result: Record<string, unknown> = {
    content: [
      { type: "text", text: `key ${GH}` },
      { type: "file", uri: "file:///tmp/x", mime: "text/plain" },
    ],
    output: { headers: { authorization: `Bearer ${"a".repeat(30)}` } },
  }
  assert.equal(core.redactToolResult(result, redactor, false), true)
  const content = result.content as { type: string; text?: string }[]
  assert.match(content[0].text ?? "", /\[REDACTED_GITHUB_TOKEN_#1\]/)
  assert.match(JSON.stringify(result.output), /REDACTED_BEARER/)
})

test("redaction: clean tool result is untouched", () => {
  const redactor = new core.SecretRedactor(C)
  const result: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] }
  const before = JSON.stringify(result)
  assert.equal(core.redactToolResult(result, redactor, false), false)
  assert.equal(JSON.stringify(result), before)
})

test("redaction: outbound context messages", () => {
  const redactor = new core.SecretRedactor(C)
  const messages = [
    { role: "user", content: [{ type: "text", text: `my key ${AWS}` }] },
    {
      role: "tool",
      content: [
        { type: "tool-result", result: { type: "text", value: GH } },
        { type: "tool-result", result: { type: "json", value: { token: GH } } },
      ],
    },
    {
      role: "assistant",
      content: [{ type: "tool-call", id: "1", name: "shell", input: { command: `echo ${AWS}` } }],
    },
  ]
  assert.equal(core.redactContextMessages(messages, redactor), true)
  const text = JSON.stringify(messages)
  assert.doesNotMatch(text, new RegExp(AWS))
  assert.doesNotMatch(text, new RegExp(GH))
  assert.match(text, /REDACTED_AWS_KEY/)
  assert.match(text, /REDACTED_GITHUB_TOKEN/)
})

test("redaction: clean context is untouched", () => {
  const redactor = new core.SecretRedactor(C)
  const messages = [{ role: "user", content: [{ type: "text", text: "hello" }] }]
  assert.equal(core.redactContextMessages(messages, redactor), false)
})

test("gitleaks: safety net catches formats the regexes do not know (large buffers only)", { skip: !hasGitleaks }, () => {
  const redactor = new core.SecretRedactor(C)
  const big = `${"x".repeat(5000)}\nsee ${NPM}\n`
  assert.ok(core.scanWithGitleaks(`see ${NPM}\n`).length > 0)
  assert.ok(!redactor.redact(big, true).includes(NPM), "tool result path must redact")
  assert.ok(redactor.redact(big, false).includes(NPM), "context path is regex-only by design")
})

test("gitleaks: regexes keep working when gitleaks is disabled", () => {
  const redactor = new core.SecretRedactor({ ...C, enableGitleaks: false })
  assert.match(redactor.redact(AWS, true), /\[REDACTED_AWS_KEY_#1\]/)
})
