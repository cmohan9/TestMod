# Non-prod test plan

Everything created by these files carries an `ONB…` marker (team or exception code) so it is easy to find and delete afterwards.
Expected results below come from running the suite's own validator on every file and from an end-to-end run against a mock server;
the **real-tenant** column is what you should confirm.

## Before you start

1. **Non-prod only.** `.\Start-Onboarding.ps1` prompts for the service user + key. Use a non-prod tenant.
2. **Source platforms.** The files use these platform IDs as reference platforms: `WinServerLocal`, `WinDomain`, `UnixSSH`, `Oracle`, `MSSql`.
   Confirm they exist (`-Mode Diagnose`) or find/replace them in the CSVs with IDs from your tenant.
3. **Managing CPM.** Leave `safeDefaults.managingCpm` blank to see the "no CPM" warning, or fill `byRegionTier` / `byTier` / `byRegion` to see the map applied
   (the preview shows `CPM=<name>` or `CPM=(blank)` per safe). A configured CPM that does not exist in your tenant is *not* an error: the safe is created with the next
   candidate or a blank CPM, with a WARN and status `PartialSuccess`.
4. **Groups (red vs green).** Every safe gets `Global-Sec-<SafeName>-SafeManagers` and `Global-SEC-<SafeName>-Users`.
   Create those two groups **only for `OCA-P-WIN-LA-T0-ONBFULL`** if you want to see both outcomes: that safe should be all green,
   the other four `…ONBFULL` safes should raise red `MISSING GROUP` alerts (default groups `Privilege Cloud Administrators` and
   `Global-CyberArk-BGAccount` must exist in every case).
5. Accounts are created with fake `*.corp.test` addresses. Answer **No** to Verify/Reconcile unless you have a real target,
   otherwise Verify will (correctly) report a failure/timeout.

## Run order

Run each with `-WhatIf` first (read-only pre-flight, nothing is changed), then for real.

```powershell
.\Start-Onboarding.ps1 -Mode Full -CsvPath .\templates\testdata\Full_Valid.csv -WhatIf
.\Start-Onboarding.ps1 -Mode Full -CsvPath .\templates\testdata\Full_Valid.csv
```

Exit codes: `0` success, `1` validation/sign-in/unhandled error (nothing changed), `2` run completed but at least one item **Failed**.

## A. Validation failures — nothing is signed in, nothing is called (exit 1)

Each error must be reported in one pass, and **no** service-account prompt may appear.

| File | Mode | Expected |
|---|---|---|
| `SafeOnly_Invalid.csv` | SafeOnly | 8 errors: bad region, environment, technology, access type, tier; missing team; illegal team characters; name >28 chars |
| `PlatformOnly_Invalid.csv` | PlatformOnly | 8 errors: region `OT` (valid for safes, not platforms), flavour, app tower, account type, rotation, vendor, illegal exception, missing source |
| `PlatformOnly_Conflict.csv` | PlatformOnly | 1 error: same target platform requested from two different sources |
| `Full_Invalid.csv` | Full | 18 errors across all safe, platform and account rules (row 2 gives two: safe + platform region) |
| `Full_PlatformConflict.csv` | Full | 1 error: same target platform from two different sources |
| `AccountOnly_Invalid.csv` | AccountOnly | 5 errors: missing SafeName / PlatformID / AccountUserName / Address; bad SecretType |

## B. Happy paths

| # | File | Mode | Expected objects | Also check |
|---|---|---|---|---|
| 1 | `PlatformOnly_Valid.csv` | PlatformOnly | **6 platforms created**: `OCA-WIN-AD-LA-RA-ONBPLAT`, `OCA-WIN-AD-LA-RM-ONBPLAT`, `APAC-UNX-UX-LS-RA-W-ONBPLAT`, `EMEA-DB-ORA-DS-RS-T-ONBPLAT`, `GLB-DB-SQL-DS-RA-D-ONBPLAT`, `JP-WIN-AD-DA-RA-ONBPLAT` | 7 rows → 6 platforms (row 7 is a lower-case duplicate of row 1). Each platform is **active**. Description ends `\| Created by <you> through script`; row 5 has no admin text → suffix only. |
| 2 | `SafeOnly_Valid.csv` | SafeOnly | **8 safes**: `OCA-P-WIN-LA-T0-ONBSAFE`, `APAC-D-LIN-LSA-T1-ONBSAFE`, `EMEA-T-DB-DSA-ONBSAFE` (no tier), `JP-Q-SQL-ENA-T2-ONBSAFE`, `OT-P-NET-DA-T0-ONBSAFE`, `GLB-P-WKS-LA-ONBSAFE` (no tier), `OCA-P-WIN-LA-T1-ONBSAFE` (from lower-case input), `EMEA-P-HTTP-LSA-T0-ONBSAFE` | 9 rows → 8 safes (last-but-one row duplicates the first). Each safe has 4 members: `Privilege Cloud Administrators`, `Global-CyberArk-BGAccount`, and the two derived groups. Permissions must match your matrix (PCA: `requestsAuthorizationLevel1` = TRUE; BG: both FALSE). The `EMEA-P-HTTP…` safe has a >100-char description: a WARN says it was trimmed and the suffix must still be at the end. |
| 3 | `Full_Valid.csv` | Full | **6 platforms** (`…-ONBFULL`): `OCA-WIN-AD-LA-RA`, `OCA-WIN-SD-LA-RM`, `APAC-UNX-UX-LS-RA`, `EMEA-DB-ORA-DS-RS-W`, `GLB-WIN-AD-DA-RA-T`, `JP-WIN-PA-SA-RM-D` · **5 safes**: `OCA-P-WIN-LA-T0`, `APAC-D-LIN-LSA-T1`, `EMEA-T-DB-DSA`, `GLB-P-WIN-DA-T2`, `JP-Q-SQL-ENA-T0` (all `-ONBFULL`) · **7 accounts** | Rows 1–3 share one safe (row 1–2 also share one platform). Account names follow `{PlatformId}-{Address}-{UserName}` except row 4 = `ONB-Custom-Name-Unix01`. Row 4 is manually managed (not auto). Row 3 has an `InitialSecret` → a WARN about secrets in CSVs (and the value must **not** appear in any log). Row 6 sends `LogonDomain=CORP`: if your WinDomain platform rejects that property, the account fails with the API's message — that is a valid finding, not a script bug. Row 7 is lower-case input, normalised to upper case. |
| 4 | `AccountOnly_Valid.csv` | AccountOnly | **3 accounts** in the existing safe `OCA-P-WIN-LA-T0-ONBFULL` on platform `OCA-WIN-AD-LA-RA-ONBFULL` | **Needs step 3 first.** Nothing else is created; row 2 is manual-management with custom name `ONB-Custom-Name-Acct02`. |

## C. Runtime behaviour (valid CSV, but the tenant says no / already exists)

| # | File | Mode | Expected |
|---|---|---|---|
| 5 | `Full_Valid.csv` again | Full | Idempotent: all 6 platforms **Reused**, all 5 safes **Reused** (missing members are still added), all 7 accounts **Exists** and untouched. Exit 0. |
| 6 | `PlatformOnly_SourceMissing.csv` | PlatformOnly | `OCA-WIN-AD-LA-RA-ONBSRC` created; `OCA-WIN-AD-LS-RA-ONBSRC` shows `[ERROR] Source platform 'ONB_DOES_NOT_EXIST' was not found` and is **Failed**. Exit **2**. |
| 7 | `Full_SourceMissing.csv` | Full | Row A fully created (platform, safe, account). Row B: platform `[ERROR]`, its account **Skipped** with reason, but its safe `OCA-D-WIN-LSA-T0-ONBPART` is still created. Exit **2**. |
| 8 | `AccountOnly_Runtime.csv` | AccountOnly | Row 1 safe `…-ONBNOSAFE` → `[ERROR]`, **Skipped**, and the safe is **not** created. Row 2 platform `ONB-NO-SUCH-PLATFORM` → `[ERROR]`, **Skipped**. Row 3 → `[EXISTS]` (needs step 3). Row 4 `onbrt_ok01` is the only account created. |
| 9 | `SafeOnly_CpmOverride.csv` | SafeOnly | Edit `REPLACE_WITH_YOUR_CPM_NAME` to a real CPM first. Safe `OCA-D-WIN-LA-T0-ONBCPM` gets exactly that CPM, overriding the config map. With a bogus name the API's error is shown and the safe is **Failed**. |
| 10 | any Full/AccountOnly file | – | Answer **Yes** to Verify and No to Reconcile, then the reverse, to exercise both questions independently. Reconcile changes passwords; only do it on a throw-away account. |

## D. Logging checks (every run above)

* `logs\Onboarding_<time>_<you>.log` starts with the **RUN CONTEXT** block (your Windows identity, machine, IPs/MACs, OS, script hash, CSV hash).
* `logs\OnboardingResults_*.csv` has one row per platform / safe / account with Action and Status.
* Blob upload: with valid settings both files appear under `<container>/<prefix>/<yyyy>/<MM>/<dd>/`.
  Break the SAS token on purpose → a red `AZURE BLOB UPLOAD FAILED … upload this file manually` line, the run still finishes, and the file is listed in `logs\PendingUploads.csv`;
  fix the token and run anything (even `-WhatIf`) → the queued files upload automatically.
* No secret, bearer token or SAS `sig=` value appears in any log.

## Clean-up (non-prod)

Delete in this order: accounts → safes → platforms.

* Safes ending `-ONBSAFE`, `-ONBFULL`, `-ONBPART`, `-ONBCPM`
* Platforms ending `-ONBPLAT`, `-ONBSRC`, `-ONBFULL`, `-ONBPART`
* Any `logs\` files you no longer need (the folder is git-ignored).
