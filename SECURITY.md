# Security Policy

## Reporting a Vulnerability

Security is paramount for `opencode-dlp-guard`. If you discover a vulnerability, bypass vector, or security issue, please do **NOT** open a public GitHub issue.

Instead, please report it via one of the following methods:
1. **GitHub Private Vulnerability Reporting**: Use the "Report a vulnerability" button on the GitHub Security tab of this repository.
2. **Direct Email**: Send details and reproduction steps to `riccardo.mazza.dev@gmail.com` or via the author's GitHub profile.

Please include:
- A clear description of the vulnerability (e.g., regex evasion, path traversal bypass, command injection, shell parser flaw).
- Minimal reproducible example or tool call payload.
- Expected impact and environment details (Node version, OS, OpenCode version).

We commit to acknowledging your report within 48 hours and working on a prompt remediation.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Security Architecture & Threat Model

`opencode-dlp-guard` is designed as **Defense in Depth** specifically for AI coding agents running on [OpenCode V2](https://opencode.ai/v2/).

### Threat Model Assumptions

1. **Accidental Exfiltration**:
   - The primary goal is preventing accidental leakage of developer credentials, cloud keys, tokens, and system secrets to LLM providers via prompt context or tool execution outputs.
2. **Untrusted Agent Actions**:
   - Guard integrity protections (`integrityPaths` and the plugin installation directory) prevent an agent (whether confused, hijacked via prompt injection, or malfunctioning) from tampering with its own security settings, disabling plugins, or rewriting guards.
3. **Canonical Path Resolution**:
   - All filesystem operations are verified against canonical paths (`realpath`) to neutralize directory traversal (`../../`), symlink evasion, and dangling symlink poisoning.
4. **Relational Redaction**:
   - Redaction maintains token consistency within a session (`[REDACTED_CATEGORY_#N]`) so the LLM retains semantic understanding across turns without accessing the raw plaintext secrets.
   - Session memory ensures that any secret detected once is automatically redacted if output nakedly anywhere else in subsequent turns or error traces.

### Defense in Depth Notice

Lexical analysis of shell commands (`bash`/`shell`) blocks mutators, redirects, and wrapper evasions (`sudo`, `env`, `nice`, subshells, etc.). However, it **does not** replace an OS-level sandbox or container isolation. Malicious arbitrary code execution via secondary interpreters (e.g. custom binaries, embedded Python/Node scripts) must be constrained with OpenCode's native permissions and operating system sandboxing.
