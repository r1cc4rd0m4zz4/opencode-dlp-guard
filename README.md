# opencode-dlp-guard 🛡️

> **DLP, path protection and deterministic secret redaction for [OpenCode V2](https://opencode.ai/v2/).**

[![Test](https://github.com/r1cc4rd0m4zz4/opencode-dlp-guard/actions/workflows/test.yml/badge.svg)](https://github.com/r1cc4rd0m4zz4/opencode-dlp-guard/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Plugin OpenCode V2, zero dipendenze runtime proprie. Riduce l'esfiltrazione accidentale di credenziali e protegge l'integrità della configurazione dell'agente.

```sh
opencode plugin add github:r1cc4rd0m4zz4/opencode-dlp-guard
```

Oppure in `~/.config/opencode/opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["github:r1cc4rd0m4zz4/opencode-dlp-guard"]
}
```

Per lo sviluppo locale:

```jsonc
{
  "plugins": ["/percorso/assoluto/opencode-dlp-guard"]
}
```

## Modello di sicurezza

Il plugin è **difesa in profondità**, non una sandbox. L'analisi dei comandi shell è lessicale: non ferma un attaccante determinato che usa interpreti secondari, offuscamento o chiamate dirette a basso livello. Per un isolamento reale affianca `permissions` di OpenCode e una sandbox a livello OS.

### 1. Protezione dei percorsi (`tool execute.before`)

Blocca lettura e scrittura su:

- `.env` e varianti (`.env.example`, `.env.sample`, `.env.template` restano leggibili);
- `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**`, `~/.kube/**`, `~/.netrc`;
- `~/.zshrc*`, `~/.bashrc*`, `~/.bash_profile`, `~/.profile`;
- `~/.config/opencode/auth.json`, database OpenCode;
- chiavi private `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`;
- `**/.git/config`, `**/.git/hooks/**`.

Riconosce i campi percorso di qualsiasi tool (`path`, `paths`, `file`, `filePath`, `file_path`, `workdir`, `cwd`, …), inclusi tool MCP, e i path dentro `patchText` (`*** Update File`, `*** Move to`, header unified diff).

La risoluzione è canonica (`realpath`): `../../`, symlink e symlink dangling non aggirano i controlli.

### 2. Scritture shell (`shell` / `bash`)

Analizza la command line scomponendo `&&`, `||`, `;`, `|`, `&` e newline; segue `cd`/`pushd`; entra in `sh -c`, `bash -lc`, `eval`, `$(...)` e backtick.

Blocca mutatori (`rm`, `mv`, `cp`, `ln`, `install`, `rsync`, `touch`, `truncate`, `dd`, `chmod`, `tee`, `shred`, `tar`, `unzip`, …), editor in-place (`sed -i`, `perl -i`, `ruby -i`) e redirezioni (`>`, `>>`, `| tee`) verso path protetti o file di integrità.

Le letture e le ricerche passive (`cat .env`, `grep -rn "\.env" src/`) non vengono bloccate: l'output passa dal livello di mascheramento.

### 3. Integrità del guardiano

Scrittura e cancellazione sono vietate su:

- `~/.config/opencode/**`;
- `~/.local/share/opencode/**`;
- la directory del plugin stesso.

La lettura resta consentita dove serve a OpenCode. L'agente non può modificare la configurazione né il codice del guardiano.

### 4. Mascheramento deterministico

Tool result e messaggi in uscita vengono ripuliti prima di raggiungere il modello:

- `[REDACTED_AWS_KEY_#1]`, `[REDACTED_GITHUB_TOKEN_#1]`, `[REDACTED_API_KEY_#1]`, `[REDACTED_PRIVATE_KEY_#1]`, `[REDACTED_JWT_#1]`, `[REDACTED_SECRET_#1]`, …
- **Relazionale**: la stessa credenziale mantiene lo stesso token nella sessione.
- **Idempotente**: i placeholder non vengono ri-mascherati.
- **Veloce**: nell'hook `context` girano solo regex native; `gitleaks stdin` opzionale interviene solo sui tool result oltre la soglia (default 4 KB).

## Comandi `/dlp`

| Comando | Descrizione |
| --- | --- |
| `/dlp` o `/dlp status` | Stato, gitleaks, segreti mascherati, numero di path protetti |
| `/dlp on` | Attiva per la sessione corrente |
| `/dlp off` | Disattiva per la sessione corrente |
| `/dlp reload` | Ricarica la configurazione senza riavviare |

## Configurazione

File: `~/.config/opencode/dlp-guard.json` (creato al primo avvio, `0600`). Override con `OPENCODE_DLP_CONFIG=/path/file.json`.

```json
{
  "protectedPaths": [
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
    "~/.local/share/opencode/opencode.db-*"
  ],
  "integrityPaths": [
    "~/.config/opencode/**",
    "~/.local/share/opencode/**"
  ],
  "enableGitleaks": true,
  "gitleaksMinBytes": 4096,
  "gitleaksTimeoutMs": 500
}
```

Glob: `**` attraversa le directory, `*` no. Un pattern senza `/` matcha il basename. I pattern relativi sono risolti rispetto alla directory della Location.

## Test

```sh
pnpm install
pnpm test
pnpm typecheck
```

La suite copre path (inclusi symlink e dangling), shell (catene, `cd`, nested code, quote), redaction (formati noti, stabilità, idempotenza, falsi positivi), routing dei tool e gitleaks opzionale.

## Limiti noti

- L'analisi shell è lessicale: `node -e`, `python -c`, binari custom e offuscamento possono scrivere dove vogliono.
- I tool che non espongono path strutturati non vengono ispezionati.
- La redazione riduce il rischio, non garantisce che ogni formato di segreto sia riconosciuto. `gitleaks` è una rete di sicurezza, non una garanzia.
- Non sostituisce `permissions` di OpenCode né una sandbox OS.

## License

MIT © 2026
