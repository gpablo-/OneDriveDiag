# OneDriveDiag

Single-file PowerShell tool that collects a read-only OneDrive health and error baseline, plus an HTML companion guide.
Design baseline and data map: `docs/DataMap.md`.

## Rules

- Client agnostic. Never hard-code or commit client, tenant, user, domain, site, path or ticket values. Everything is discovered at runtime.
- `Copilot Session/` holds raw imported material with client data. It is git-ignored. Read it for technical findings only; never copy identifying values out of it.
- Target Windows PowerShell 5.1 (must also run on PowerShell 7). No modules, no downloads.
- ASCII only. No backtick line continuations or escape sequences (RMM shells mangle them). Australian English, no em dashes.
- Read-only on the target machine. Only write inside the output folder.
- Validate with the real parser on both `powershell.exe` and `pwsh` before committing.
