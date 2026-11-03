# opencode-dlp-guard 🛡️

> **Zero-dependency DLP, Path Protection and Deterministic Secret Redaction for [OpenCode V2](https://opencode.ai/v2/).**

[![CI](https://github.com/r1cc4rd0m4zz4/opencode-dlp-guard/actions/workflows/test.yml/badge.svg)](https://github.com/r1cc4rd0m4zz4/opencode-dlp-guard/actions/workflows/test.yml)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](package.json)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20-blue.svg)](package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Plugin di sicurezza zero-dependency per **OpenCode V2**, evoluzione architetturale del modulo DLP creato originariamente per il Pi Coding Agent ([`pi-dlp-guard`](https://github.com/r1cc4rd0m4zz4/pi-dlp-guard)). 

Previene l'esfiltrazione accidentale di chiavi di cifratura, credenziali cloud, token di autenticazione e file sensibili verso i modelli di linguaggio, proteggendo al contempo l'integrità del sistema di configurazione dell'agente contro manomissioni o attacchi di prompt injection.

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

## Modello di sicurezza & Threat Model

Il plugin opera come **Defense in Depth** a livello applicativo nell'infrastruttura di runtime di OpenCode:

| Vettore di rischio | Mitigazione DLP Guard | Livello di garanzia |
| :--- | :--- | :--- |
| **Esfiltrazione involontaria** | Mascheramento deterministico session-aware pre-invio al modello | Alta (regex integrate + session memory + gitleaks opzionale) |
| **Path Traversal (`../../`)** | Risoluzione canonica (`realpath`) su file esistenti e dangling | Assoluta su percorsi controllati |
| **Symlink Poisoning** | Ispezione dell'intera catena di puntamento ricorsiva (fino a 8 livelli) | Assoluta su percorsi controllati |
| **Scritture Shell Evasive** | Analisi lessicale multi-segmento con scomposizione di wrapper (`sudo -u`, `env -i`), subshell `(...)`, download mutators (`curl -o`, `wget -O`) e clobber | Elevata per comandi shell standard; non sostituisce sandbox OS |
| **Manomissione Guard** | Blocco in scrittura su `~/.config/opencode/**`, `opencode.db` e cartella del plugin | Elevata a livello di tool e shell standard |

> [!WARNING]
> L'analisi dei comandi shell è lessicale. Sebbene i one-liner degli interpreti principali (`python -c`, `node -e`, `ruby -e`, `perl -e`) vengano ispezionati, binari custom compilati e chiamate di sistema native richiedono un isolamento OS a monte (sandbox o container). Il plugin è pensato per cooperare con le autorizzazioni native di OpenCode.

---

## Architettura a 4 livelli

### 1. Protezione dei percorsi (`tool execute.before`)

Intercetta ogni chiamata a qualsiasi tool (inclusi server MCP e comandi di patch) prima dell'esecuzione. Blocca lettura e scrittura su:

- File d'ambiente: `.env`, `.env.*`, `*.env`, `.envrc`, preservando i template (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.default`, `.env.schema`);
- Credenziali utente, package manager e SSH: `~/.ssh/**`, `/etc/ssh/**`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`, `~/.cargo/credentials*`, `~/.composer/auth.json`, `~/.docker/config.json`, `~/.config/gh/**`, `~/.config/glab-cli/**`;
- Cloud provider & Infrastructure as Code: `~/.aws/**`, `~/.config/gcloud/**`, `~/.gcloud/**`, `~/.gcp/**`, `~/.azure/**`, `~/.oci/**`, `~/.kube/**`, `~/.terraform.d/**`, `**/*.tfstate`, `**/*.tfstate.*`, `**/*.tfvars`, `~/.vault-token`;
- Crittografia, Keyring e GPG: `~/.gnupg/**`, `~/.password-store/**`, `~/.local/share/keyrings/**`, `~/Library/Keychains/**`, `~/.config/op/**`, `~/.op/**`, `~/.config/sops/**`, `~/.config/age/**`, chiavi private `*.pem`, `*.key`, `*.pkcs12`, `*.pfx`, `*.p12`, `*.jks`, `*.keystore`, `*.age`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`, `id_dsa*`;
- Shell profile e history: `~/.zshrc*`, `~/.zprofile`, `~/.zshenv`, `~/.zsh_history`, `~/.bashrc*`, `~/.bash_profile`, `~/.bash_history`, `~/.profile`, `*rc.local`;
- VCS e segreti di sistema: `**/.git/**`, `**/.git/config`, `**/.git/hooks/**`, `/etc/shadow*`, `/etc/gshadow*`, `/etc/sudoers*`;
- Database e auth OpenCode: `~/.config/opencode/auth.json`, `~/.local/share/opencode/opencode.db*`.

Riconosce automaticamente sia percorsi relativi che assoluti, parametri URI `file://`, parametri complessi (`path`, `filePath`, `source`, `destination`, `oldPath`, `newPath`, `from`, `to`, `workdir`, `cwd`), blocca verbi di mutazione filesystem (`write`, `edit`, `patch`, `delete`, `remove`, `unlink`, `save_file`, `append_file`, ecc.) e previene la scrittura di segreti in chiaro nei file sorgente (`content`, `newString`, `new_string`, `newText`, `replacement`, `patchText`, `edits`).

### 2. Ispezione Profonda Shell & Motore Anti-Offuscamento (`shell` / `bash`)

Analizza ed elabora la command line scomponendo catene di comandi, subshell e pipeline:
- Risolve e segue `cd` e `pushd` per determinare la cartella corrente effettiva;
- Ispeziona ed entra ricorsivamente in script innestati: `$(...)` bilanciati, backticks, subshell `(...)`, gruppi `{ ...; }`, process substitution `<(...)` e `>(...)`, `sh -c`, `bash -lc`, `eval`;
- Neutralizza tecniche di evasione ed offuscamento avanzate:
  - Decodifica stringhe ANSI-C (`$'\x2e\x65\x6e\x76'`, `$'\056env'`), quote splitting (`.e''nv`), sostituzioni comando (`$(echo .env)`, `$(printf '%s' .env)`) ed espansioni parametro (`.${empty}env`, `${unset:-.env}`);
  - Tracciamento delle assegnazioni di variabili cross-segmento (`A=.e; B=nv; cat $A$B`, `export TARGET=...`);
  - Spacchettamento di flag ed opzioni per wrapper shell (`sudo -u user`, `env -i`, `nice -n`, `timeout 5`, `nohup`, `xargs`);
  - Normalizzazione della variabile `$IFS` / `${IFS}` fuori dalle virgolette;
  - Blocco dell'esecuzione di payload codificati (`base64 -d | sh`, `xxd -r | bash`) e tracciamento pipeline `echo .env | xargs ...`;
  - Redirezioni di scrittura (`>`, `>>`, `>|`, `&>`, `>&file`, `<>`) e di lettura (`< .env`), più `| tee` e `dd if=/of=`;
  - Blocco di letture/esfiltrazioni su percorsi protetti (`cat`, `head`, `tail`, `base64`, `xxd`, `source`, `.`, `grep`, `rg`, `sed`, `awk`, `jq`, `find`, `git show HEAD:.env`, `git diff --no-index`, `tar`, `zip`, `openssl`, `scp`, `sftp`, `curl -d @.env`, `wget --post-file`) e one-liner di interpreti (`python -c`, `node -e`, `ruby -e`, `perl -e`);
  - Blocco preventivo di segreti in chiaro inline nella riga di comando (`blockInlineSecretsInCommands: true`).
  - Le ricerche nel codice sorgente (es. `grep -rn "\.env" src/`) e la lettura dei file di configurazione non-segreti (`~/.config/opencode/settings.json`) restano consentite.

### 3. Integrità del guardiano (Anti-Tampering)

Scrittura, modifica e cancellazione sono rigorosamente vietate su:
- `~/.config/opencode/**` e `.opencode/**` (configurazioni globali e di progetto);
- `**/opencode.json`, `**/opencode.jsonc` e `**/dlp-guard.json` (manifesti plugin e regole DLP);
- `~/.local/share/opencode/**` (storage locale e database);
- La directory stessa in cui è installato `opencode-dlp-guard` e i comandi CLI `opencode plugin remove/uninstall/disable`.

### 4. Mascheramento deterministico & Session Memory

Tool result ed intero contesto dei messaggi in uscita verso i provider LLM vengono ripuliti preservando l'integrità logica:

- **Famiglie di token coperte nativamente**:
  - `[REDACTED_PRIVATE_KEY_#N]` (RSA, EC, DSA, OPENSSH, e blocchi PGP `PRIVATE KEY BLOCK`);
  - `[REDACTED_AGE_SECRET_KEY_#N]` (`AGE-SECRET-KEY-1...`);
  - `[REDACTED_AWS_KEY_#N]` (`AKIA...`, `ASIA...`);
  - `[REDACTED_GITHUB_TOKEN_#N]` (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`);
  - `[REDACTED_GITLAB_TOKEN_#N]` (`glpat-...`);
  - `[REDACTED_HUGGINGFACE_TOKEN_#N]` (`hf_...`);
  - `[REDACTED_NPM_TOKEN_#N]` (`npm_...`);
  - `[REDACTED_PYPI_TOKEN_#N]` (`pypi-...`);
  - `[REDACTED_SLACK_TOKEN_#N]` (`xoxb-`, `xoxp-`, ecc.);
  - `[REDACTED_API_KEY_#N]` (OpenAI `sk-...`, Anthropic `sk-ant-...`, Google `AIza...`, Stripe `sk_live_`, SendGrid `SG....`, DigitalOcean `dop_v1_`, ecc.);
  - `[REDACTED_JWT_#N]` (JSON Web Token);
  - `[REDACTED_URL_CREDENTIAL_#N]` (URL PostgreSQL, MySQL, MongoDB, Redis `redis://:<PASS>@host`);
  - `[REDACTED_SECRET_#N]` (coppie chiave/valore `.env`, YAML, JSON, shell export, distinguendo password letterali con `$` da variabili shell `$VAR`).
- **Session Memory**: ogni segreto scoperto viene memorizzato nel redattore della sessione e mascherato immediatamente se riappare nudo in stack trace, messaggi d'errore o output successivi.
- **Relazionale & Idempotente**: la medesima credenziale mantiene lo stesso identico identificativo nella sessione, consentendo al modello di ragionare sulle relazioni tra segreti senza esporne il valore. I placeholder `[REDACTED_...]` non vengono mai ri-mascherati.
- **Gitleaks Safety-Net**: se installato in PATH, `gitleaks` viene invocato come fallback di sicurezza per buffer di output superiori alla soglia (default 4 KB).

---

## Comandi `/dlp`

Interfaccia interattiva integrata nella console OpenCode:

| Comando | Descrizione |
| :--- | :--- |
| `/dlp` o `/dlp status` | Visualizza stato, disponibilità gitleaks, conteggio segreti mascherati e percorsi protetti |
| `/dlp on` | Riattiva il guardiano per la sessione corrente |
| `/dlp off` | Disattiva temporaneamente il guardiano per la sessione corrente |
| `/dlp reload` | Ricarica istantaneamente il file di configurazione |

---

## Configurazione

Il file di configurazione predefinito è allocato in:
`~/.config/opencode/dlp-guard.json` (creato automaticamente con permessi `0600`).
È possibile specificare un file custom tramite variabile d'ambiente `OPENCODE_DLP_CONFIG=/path/to/custom.json`.

```json
{
  "enabled": true,
  "protectedPaths": [
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
    "~/.local/share/opencode/opencode.db-*"
  ],
  "integrityPaths": [
    "~/.config/opencode/**",
    "~/.local/share/opencode/**",
    ".opencode/**",
    "**/opencode.json",
    "**/opencode.jsonc",
    "**/dlp-guard.json"
  ],
  "enableGitleaks": true,
  "gitleaksMinBytes": 4096,
  "gitleaksTimeoutMs": 500,
  "blockInlineSecretsInCommands": true,
  "blockReaderCommandsOnProtected": true,
  "blockWriteSecrets": true
}
```

---

## Test & Verifica

La suite di test integrata copre oltre 35 scenari di sicurezza (symlink, dangling links, traversals, shell evasions, wrappers, quote splitting, tokens, false positives, session memory e gitleaks):

```sh
pnpm install
pnpm test
pnpm typecheck
```

---

## License

MIT © 2026 [Riccardo Mazza](https://github.com/r1cc4rd0m4zz4)
