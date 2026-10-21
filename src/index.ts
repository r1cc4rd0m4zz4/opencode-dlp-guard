/**
 * opencode-dlp-guard — OpenCode V2 plugin entry point.
 *
 * Hooks:
 *  - tool execute.before: blocks protected paths and shell writes
 *  - tool execute.after:  redacts secrets from tool output
 *  - session context:     redacts secrets from outbound model messages
 *  - command /dlp:        status, on, off, reload
 */

import { Plugin } from "@opencode/plugin"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import {
  checkBashCommand,
  configFilePath,
  ensureConfigFile,
  hasGitleaks,
  isPathProtected,
  loadConfig,
  redactContextMessages,
  redactToolResult,
  scanToolCall,
  SecretRedactor,
  setGuardDirectory,
  type DlpGuardConfig,
} from "./core.ts"

const PACKAGE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const HELP = [
  "[DLP Guard] commands:",
  "/dlp          show status",
  "/dlp on       enable for this session",
  "/dlp off      disable for this session",
  "/dlp reload   reload the config file",
].join("\n")

function statusText(
  enabled: boolean,
  config: DlpGuardConfig,
  secrets: number,
): string {
  return [
    `[DLP Guard] ${enabled ? "ACTIVE" : "DISABLED"}`,
    `gitleaks: ${config.enableGitleaks ? (hasGitleaks() ? "active" : "not found in PATH") : "disabled"}`,
    `secrets redacted in this session: ${secrets}`,
    `protected paths: ${config.protectedPaths.length}, integrity paths: ${config.integrityPaths.length}`,
    `config: ${configFilePath()}`,
  ].join("\n")
}

export default Plugin.define({
  id: "opencode.dlp-guard",
  async setup(ctx) {
    setGuardDirectory(PACKAGE_DIR)
    ensureConfigFile()

    let config = loadConfig()
    const disabled = new Set<string>()
    const redactors = new Map<string, SecretRedactor>()

    const redactorFor = (sessionID: string): SecretRedactor => {
      let redactor = redactors.get(sessionID)
      if (!redactor) {
        redactor = new SecretRedactor(config)
        redactors.set(sessionID, redactor)
      }
      return redactor
    }

    const reload = () => {
      config = loadConfig()
      for (const redactor of redactors.values()) redactor.config = config
      return config
    }

    await ctx.tool.hook("execute.before", (event) => {
      if (disabled.has(event.sessionID)) return
      const check = scanToolCall(event.tool, event.input, config, ctx.location.directory)
      if (!check.block) return
      console.warn(`[dlp-guard] blocked ${event.tool}: ${check.reason}`)
      throw new Error(`🛑 [DLP Guard] ${check.reason}`)
    })

    await ctx.tool.hook("execute.after", (event) => {
      if (disabled.has(event.sessionID)) return
      const redactor = redactorFor(event.sessionID)

      if (event.status === "error") {
        try {
          const err = event.error as unknown as Record<string, unknown>
          if (typeof err.message === "string") {
            const next = redactor.redact(err.message)
            if (next !== err.message) {
              try {
                err.message = next
              } catch {
                event.error = Object.create(Object.getPrototypeOf(err), {
                  ...Object.getOwnPropertyDescriptors(err),
                  message: { value: next, writable: true, enumerable: true, configurable: true },
                })
              }
            }
          }
          if (err.metadata && typeof err.metadata === "object") {
            const metaStr = JSON.stringify(err.metadata)
            const redactedMeta = redactor.redact(metaStr)
            if (redactedMeta !== metaStr) {
              try {
                err.metadata = JSON.parse(redactedMeta)
              } catch {
                // keep original if parse fails
              }
            }
          }
        } catch {
          // best effort: never break the session on a redaction failure
        }
        return
      }

      const result = { ...event.result } as Record<string, unknown>
      if (redactToolResult(result, redactor, true)) event.result = result
    })

    await ctx.session.hook("context", (event) => {
      if (disabled.has(event.sessionID)) return
      const redactor = redactorFor(event.sessionID)
      for (const part of event.system) {
        const next = redactor.redact(part.text)
        if (next !== part.text) (part as { text: string }).text = next
      }
      redactContextMessages(event.messages, redactor)
    })

    await ctx.command.transform((editor) => {
      editor.add({
        name: "dlp",
        description: "DLP Guard: /dlp [status|on|off|reload]",
        execute: async ({ sessionID, prompt }) => {
          const raw = (prompt.text ?? "").trim()
          const arg = raw.replace(/^\/dlp\b/i, "").trim().toLowerCase()
          const redactor = redactorFor(sessionID)
          let text: string

          if (arg === "off") {
            disabled.add(sessionID)
            text = statusText(false, config, redactor.size)
          } else if (arg === "on") {
            disabled.delete(sessionID)
            text = statusText(true, config, redactor.size)
          } else if (arg === "reload") {
            const next = reload()
            text = `[DLP Guard] config reloaded\n${statusText(!disabled.has(sessionID), next, redactor.size)}`
          } else if (arg === "" || arg === "status") {
            text = statusText(!disabled.has(sessionID), config, redactor.size)
          } else {
            text = HELP
          }

          await ctx.session.synthetic({ sessionID, text })
        },
      })
    })
  },
})
