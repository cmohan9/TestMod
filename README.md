# CyberArk Privilege Cloud – Auto Onboarding Suite

PowerShell suite (Windows PowerShell 5.1 **or** PowerShell 7+) that onboards platforms, safes and accounts into
**CyberArk Privilege Cloud Shared Services** through the REST API, with a full audit trail of *who ran it, from which device*.

## Modes

Run `.\Start-Onboarding.ps1` for a menu, or pass `-Mode`:

| Mode | What it does | Template CSV |
|---|---|---|
| `SafeOnly` | Creates safe(s) and adds the default / derived members | `templates\SafeOnly.csv` |
| `PlatformOnly` | Duplicates a **reference (source) platform** into a new, correctly-named platform and activates it | `templates\PlatformOnly.csv` |
| `Full` | Platform + safe + members + account, then optional Verify / Reconcile | `templates\Full.csv` |
| `AccountOnly` | Onboards accounts into an **existing** safe and platform (never creates either) | `templates\AccountOnly.csv` |
| `Diagnose` | Signs in, dumps the real response shapes of the Platforms/Safes APIs, optionally lists a safe's members (`-DiagnoseSafe <name>`) | – |

```powershell
.\Start-Onboarding.ps1                                                  # menu
.\Start-Onboarding.ps1 -Mode Full -CsvPath .\templates\Full.csv         # interactive confirmations
.\Start-Onboarding.ps1 -Mode Full -CsvPath .\req.csv -WhatIf            # read-only pre-flight, nothing is changed
.\Start-Onboarding.ps1 -Mode Full -CsvPath .\req.csv -Verify Yes -Reconcile No -AssumeYes   # unattended answers
.\Start-Onboarding.ps1 -Mode Diagnose -DiagnoseSafe "SOME-EXISTING-SAFE"
```

Flow: validate CSV (no API calls) → sign in → **read-only pre-flight** (does each platform/safe/account already exist? does the source platform exist?) →
preview → questions (*Run Verify? Run Reconcile?* – each Y/N; a **No** simply moves on) → one final confirmation → execute → summary.
`-WhatIf` stops after the preview and guarantees no write call is ever sent.

## Credentials

The CyberArk **service user name and key are never stored**. The script asks for them every run (the key is a hidden prompt – paste it).
Only the service user *name* is written to the log, for the audit trail. Tenant settings (`identityTenantId`, `subdomain`) live in the config.

## Configuration (`config\`)

Put real values in **`config\onboarding.config.local.json`** (git-ignored; merged over `onboarding.config.json`).

| File | Purpose |
|---|---|
| `onboarding.config.json` | Tenant IDs, Azure Blob settings, retry, description suffix, safe defaults, **managing-CPM map**, account naming, Verify/Reconcile timeouts |
| `safe-members.json` | Permission sets + members added to every safe |
| `naming.json` | Allowed codes for the Safe / Platform naming conventions |

### Safe members
`safe-members.json` ships with the two groups from your permission matrix:

* `Privilege Cloud Administrators` → permission set `PrivilegeCloudAdmin` (everything, incl. `requestsAuthorizationLevel1`; Level 2 off)
* `Global-CyberArk-BGAccount` → permission set `BGAccount` (everything except both authorization levels)

To add more groups later, append to **`additionalMembers`** (`memberName`, `memberType`, `searchIn`, `permissionSet`, `enabled`).
Per-safe groups `Global-Sec-<Safe>-SafeManagers` / `Global-SEC-<Safe>-Users` come from `derivedMembers`. Any group that is
not defined in CyberArk is reported **in red** (white on dark red) as it happens and again in an *ACTION REQUIRED* block at the end, and is
recorded in the results CSV; the safe and accounts are still processed.

### Managing CPM
`safeDefaults.managingCpm` is **blank by default**. Fill `byRegionTier` (`"OCA-T1": "CPM_NAME"`), `byTier`, `byRegion` or `default`; a `ManagingCPM` CSV column overrides per row.

**Precedence (a Tier, when present, always beats the plain region):** CSV column → `REGION-TIER` → `TIER` → `REGION` → `default`.

**If a CPM does not exist in the tenant** (typical in non-prod) the safe is *not* failed: the next CPM in the precedence list is tried and, if none is accepted, the safe is created with a **blank CPM**.
A yellow WARN is logged, the safe's result is `PartialSuccess` with the reason in the `Detail` column, and you can assign a CPM afterwards.
Set `safeDefaults.fallbackToBlankCpm` to `false` if you would rather fail the safe (production).

### Descriptions
Every platform, safe and account gets `<admin description> | Created by <windows-user-id> through script`. (Suffix and separator are configurable; safe
descriptions are limited to 100 characters – the admin text is trimmed, never the suffix. Accounts have no native description field, so the text is
written to the platform property named in `descriptions.accountPropertyName`; if the platform rejects it the account is created without it and a warning is logged.)

## Logging & audit

Every run writes `logs\Onboarding_<timestamp>_<user>.log` and `logs\OnboardingResults_<timestamp>_<user>.csv`. The top of each log is a **RUN CONTEXT** block:
Windows identity/UPN, elevation, computer name/FQDN, IPs and MACs, OS, hardware make/model/serial, PowerShell version, RDP/SSH client, script version + SHA-256, run ID, and the input CSV path + SHA-256.
Secrets, bearer tokens and SAS signatures are redacted from all log lines.

### Azure Blob upload
Configured in `azureBlob` (storage account, container, SAS token with *Create + Write*). At the end of every run – even after an error or Ctrl+C – the log and results CSV are uploaded to
`<container>/<blobPrefix>/<yyyy>/<MM>/<dd>/<file>`.
**If the upload fails the run is not affected**: an `ERROR` line says *"AZURE BLOB UPLOAD FAILED … ACTION REQUIRED – upload this file manually …"* and the file is queued in `logs\PendingUploads.csv`; the next run retries automatically.
(The uploaded copy of a log cannot contain its own final upload-status line – that line is in the local copy.)

## Verify / Reconcile
Asked per run. **Verify** only tests the stored credential. **Reconcile changes the account's password** and needs a reconcile account linked on the platform – answer *No* unless you intend that.

## Things to validate on your tenant
The code was written against the published Privilege Cloud REST API **without access to a live tenant** (the docs site was not reachable from the build environment). Run `-Mode Diagnose` once and confirm:

1. `Platforms/Targets` returns both the numeric ID and the string PlatformID (used by *duplicate* and by *Accounts* respectively).
2. `POST Platforms/Targets/{id}/Duplicate/` (body `{Name, Description}`; response `{ID, PlatformID, Name, Description}`) and `.../activate/` behave as documented. The platform **Name** is documented as alphanumeric and unique; if your tenant rejects the hyphens in `OCA-WIN-AD-LA-RA`, tell me and I will add a configurable separator (e.g. `_`). Also note the platform *settings* (rotation, verify intervals, PSM) are inherited from the source platform - the `RA/RM/RS` code in the name is only a label.
3. Hyphens are accepted in platform names/IDs such as `OCA-WIN-AD-LA-RA`.
4. `memberType`/`searchIn` for your groups (`-DiagnoseSafe` on an existing safe shows what your tenant uses).

## Tests
* `pwsh -File .\tests\Run-Tests.ps1` (or `powershell.exe -File ...`) – offline unit tests, no tenant/network/Pester needed: naming rules, permission sets vs. the supplied matrix, member plan, CPM lookup, descriptions, redaction, config merge, CSV validation.
* `tests\mock_server.py` – tiny mock of the Identity, Privilege Cloud and Azure Blob endpoints for end-to-end dry runs on a workstation: start it (`python tests\mock_server.py 8766`), then point a local override at it
  (`cyberark.identityUrl = http://127.0.0.1:8766/id`, `cyberark.apiBaseUrl = http://127.0.0.1:8766/api`, `azureBlob.endpointOverride = http://127.0.0.1:8766/blob`) and sign in with any user and the key `goodkey`.

## Security notes
* Prefer leaving `InitialSecret` blank in CSVs and typing secrets at the prompt; delete filled-in CSVs after use.
* `Global-CyberArk-BGAccount` has *manage safe / manage members / backup* in the supplied matrix – intentionally very powerful; review that this is what you want.

## Legacy v1 files
`common.ps1`, `onboard-accounts.ps1` and `log.txt` are the previous version and are **superseded** by this suite. They are left in place only so nothing is removed without your say-so;
`log.txt` contains a tenant name and a local path, so it is recommended to delete all three (`git rm common.ps1 onboard-accounts.ps1 log.txt`).
