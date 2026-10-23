# DLP Guard Security Policy

Questo ambiente è protetto da **OpenCode DLP Guard (`opencode-dlp-guard`)**:

1. **Percorsi Sensibili Vietati**: Non tentare mai di leggere, scrivere, copiare, archiviare o trasmettere file `.env*` (eccetto `.env.example`/`.env.sample`/`.env.template`), chiavi SSH (`~/.ssh/**`), credenziali cloud (`~/.aws/**`, `~/.config/gcloud/**`, `~/.azure/**`, `~/.oci/**`), keyring GPG (`~/.gnupg/**`), file di stato Terraform (`*.tfstate`, `*.tfvars`), o chiavi private (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.age`).
2. **Integrità Anti-Manomissione**: Non modificare né disattivare i file di configurazione dell'agente (`~/.config/opencode/**`, `~/.local/share/opencode/**`, `.opencode/**`, `~/.pi/agent/**`, `~/.gemini/**`, `.agents/**`) o il plugin `opencode-dlp-guard`.
3. **Zero Segreti in Chiaro**: Non inserire mai chiavi API, token, password o segreti in chiaro all'interno di file sorgente, comandi shell o query esterne. Usa variabili d'ambiente o segnaposto sicuri (`${API_KEY}`).
