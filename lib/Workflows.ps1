#=========================================================================
# Workflows.ps1 - CSV validation per mode, read-only pre-flight preview,
# and the execution phases (Platform -> Safe(+members) -> Account).
#=========================================================================

$ModeColumns = @{
    SafeOnly     = @("Region", "Environment", "Technology", "AccessType", "Team")
    PlatformOnly = @("Region", "Flavour", "AppTower", "PlatformAccountType", "RotationPolicy", "SourcePlatformID")
    Full         = @("Region", "Environment", "Technology", "AccessType", "Team", "Flavour", "AppTower", "PlatformAccountType", "RotationPolicy", "SourcePlatformID", "AccountUserName", "Address")
    AccountOnly  = @("SafeName", "PlatformID", "AccountUserName", "Address")
}

function Get-Cell {
    param($Row, [string]$Column)
    $p = $Row.PSObject.Properties[$Column]
    if ($p -and $null -ne $p.Value) { return ([string]$p.Value).Trim() }
    return ""
}

function Add-Result {
    param([string]$Type, [int]$RowNum = 0, [string]$SafeName = "", [string]$PlatformName = "", [string]$AccountUserName = "",
          [string]$AccountId = "", [string]$Action = "", [string]$Status = "", [string]$Verify = "", [string]$Reconcile = "", [string]$Detail = "")
    [void]$Global:Onb.Results.Add([pscustomobject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); RunId = $Global:Onb.RunId; Operator = $Global:Onb.Operator.Identity
        Mode = $Global:Onb.Mode; Type = $Type; RowNum = $RowNum; SafeName = $SafeName; PlatformName = $PlatformName
        AccountUserName = $AccountUserName; AccountId = $AccountId; Action = $Action; Status = $Status
        Verify = $Verify; Reconcile = $Reconcile; Detail = $Detail
    })
}

#region Pass 1: parse + validate CSV (no API calls)
# Returns @{ Errors; Items; Platforms (ordered name->def); Safes (ordered name->def) }
function New-OnboardingPlan {
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)]$Rows)
    $errors = New-Object System.Collections.Generic.List[string]
    $items  = New-Object System.Collections.Generic.List[object]
    $needSafe     = $Mode -in @("SafeOnly", "Full")
    $needPlatform = $Mode -in @("PlatformOnly", "Full")
    $needAccount  = $Mode -in @("Full", "AccountOnly")

    $missing = $ModeColumns[$Mode] | Where-Object { $_ -notin $Rows[0].PSObject.Properties.Name }
    if ($missing) {
        return @{ Errors = @("CSV is missing required column(s) for mode ${Mode}: $($missing -join ', ')"); Items = @(); Platforms = $null; Safes = $null }
    }

    $rowNum = 1
    foreach ($row in $Rows) {
        $rowNum++
        $before = $errors.Count
        $item = [ordered]@{
            RowNum = $rowNum; SafeName = ""; PlatformName = ""; PlatformId = ""; SourcePlatformID = ""
            Region = (Get-Cell $row "Region").ToUpper(); Tier = (Get-Cell $row "Tier").ToUpper()
            Description = (Get-Cell $row "Description"); ManagingCpm = (Get-Cell $row "ManagingCPM")
            AccountUserName = ""; Address = ""; AccountName = ""; SecretType = ""; InitialSecret = ""
            AutoManage = $true; ManualReason = ""; Properties = @{}
        }

        if ($needSafe) {
            $c = Test-SafeNameInputs -Region (Get-Cell $row "Region") -Environment (Get-Cell $row "Environment") -Technology (Get-Cell $row "Technology") `
                -AccessType (Get-Cell $row "AccessType") -Tier (Get-Cell $row "Tier") -Team (Get-Cell $row "Team")
            if ($c.IsValid) { $item.SafeName = $c.SuggestedName } else { $errors.Add("Row ${rowNum} (Safe): $($c.Errors -join '; ')") }
        }
        if ($needPlatform) {
            $c = Test-PlatformNameInputs -Region (Get-Cell $row "Region") -Flavour (Get-Cell $row "Flavour") -AppTower (Get-Cell $row "AppTower") `
                -AccountType (Get-Cell $row "PlatformAccountType") -RotationPolicy (Get-Cell $row "RotationPolicy") -Vendor (Get-Cell $row "Vendor") -Exception (Get-Cell $row "Exception")
            if ($c.IsValid) { $item.PlatformName = $c.SuggestedName } else { $errors.Add("Row ${rowNum} (Platform): $($c.Errors -join '; ')") }
            $item.SourcePlatformID = Get-Cell $row "SourcePlatformID"
            if (-not $item.SourcePlatformID) { $errors.Add("Row ${rowNum}: SourcePlatformID is required") }
        }
        if ($Mode -eq "AccountOnly") {
            $item.SafeName   = Get-Cell $row "SafeName"
            $item.PlatformId = Get-Cell $row "PlatformID"
            if (-not $item.SafeName)   { $errors.Add("Row ${rowNum}: SafeName is required") }
            if (-not $item.PlatformId) { $errors.Add("Row ${rowNum}: PlatformID is required") }
        }
        if ($needAccount) {
            $item.AccountUserName = Get-Cell $row "AccountUserName"
            $item.Address         = Get-Cell $row "Address"
            if (-not $item.AccountUserName) { $errors.Add("Row ${rowNum}: AccountUserName is required") }
            if (-not $item.Address)         { $errors.Add("Row ${rowNum}: Address is required") }
            $item.AccountName   = Get-Cell $row "AccountName"
            $item.SecretType    = if (Get-Cell $row "SecretType") { (Get-Cell $row "SecretType").ToLower() } else { [string]$Global:Onb.Config.accountDefaults.secretType }
            if ($item.SecretType -notin @("password", "key")) { $errors.Add("Row ${rowNum}: SecretType must be 'password' or 'key'") }
            $item.InitialSecret = Get-Cell $row "InitialSecret"
            $item.ManualReason  = Get-Cell $row "ManualManagementReason"
            $am = Get-Cell $row "AutoManage"
            $item.AutoManage = if ($am) { $am -match "^(y|yes|true|1)$" } else { [bool]$Global:Onb.Config.accountDefaults.autoManage }
            foreach ($col in $row.PSObject.Properties.Name) {
                if ($col -like "Prop_*" -and (Get-Cell $row $col)) { $item.Properties[$col.Substring(5)] = Get-Cell $row $col }
            }
        }
        if ($errors.Count -eq $before) { $items.Add([pscustomobject]$item) }
    }

    # Distinct platform / safe definitions (first row wins; conflicts are errors / warnings)
    $platforms = [ordered]@{}
    $safes     = [ordered]@{}
    foreach ($it in $items) {
        if ($needPlatform) {
            if (-not $platforms.Contains($it.PlatformName)) {
                $platforms[$it.PlatformName] = [pscustomobject]@{ Name = $it.PlatformName; SourceId = $it.SourcePlatformID; Description = $it.Description; Rows = @($it.RowNum) }
            } else {
                $def = $platforms[$it.PlatformName]
                if ($def.SourceId -ne $it.SourcePlatformID) { $errors.Add("Row $($it.RowNum): platform '$($it.PlatformName)' is also requested from a different SourcePlatformID ('$($def.SourceId)' vs '$($it.SourcePlatformID)')") }
                $def.Rows += $it.RowNum
            }
        }
        if ($Mode -in @("SafeOnly", "Full", "AccountOnly")) {
            if (-not $safes.Contains($it.SafeName)) {
                $safes[$it.SafeName] = [pscustomobject]@{ Name = $it.SafeName; Region = $it.Region; Tier = $it.Tier; Description = $it.Description; ManagingCpm = $it.ManagingCpm; Rows = @($it.RowNum) }
            } else {
                $safes[$it.SafeName].Rows += $it.RowNum
            }
        }
    }
    return @{ Errors = $errors.ToArray(); Items = $items.ToArray(); Platforms = $platforms; Safes = $safes }
}
#endregion

#region Pre-flight (read-only) + preview
function Invoke-Preflight {
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)]$Plan)
    $Plan.PlatformPre = @{}
    $Plan.SafePre     = @{}
    $Plan.AccountPre  = @{}

    if ($Mode -in @("PlatformOnly", "Full")) {
        foreach ($p in $Plan.Platforms.Values) {
            $pre = @{ Target = $null; Source = $null; Error = $null }
            $t = Find-TargetPlatform -Name $p.Name
            if (-not $t.Ok) { $pre.Error = "Could not check platform '$($p.Name)': $($t.Error)" }
            elseif ($t.Info) { $pre.Target = $t.Info }
            else {
                $s = Find-TargetPlatform -Name $p.SourceId
                if (-not $s.Ok)   { $pre.Error = "Could not check source platform '$($p.SourceId)': $($s.Error)" }
                elseif (-not $s.Info) { $pre.Error = "Source platform '$($p.SourceId)' was not found" }
                elseif ($null -eq $s.Info.NumericId) { $pre.Error = "Source platform '$($p.SourceId)' was found but its numeric ID could not be read (run -Mode Diagnose)" }
                else { $pre.Source = $s.Info }
            }
            $Plan.PlatformPre[$p.Name] = $pre
        }
    }
    if ($Mode -eq "AccountOnly") {
        foreach ($id in ($Plan.Items | ForEach-Object { $_.PlatformId } | Sort-Object -Unique)) {
            $pre = @{ Target = $null; Source = $null; Error = $null }
            $t = Find-TargetPlatform -Name $id
            if (-not $t.Ok) { $pre.Error = "Could not check platform '$id': $($t.Error)" }
            elseif (-not $t.Info) { $pre.Error = "Platform '$id' was not found" }
            elseif (-not $t.Info.Active) { $pre.Error = "Platform '$id' exists but is not active" }
            else { $pre.Target = $t.Info }
            $Plan.PlatformPre[$id] = $pre
        }
    }
    if ($Mode -in @("SafeOnly", "Full", "AccountOnly")) {
        foreach ($s in $Plan.Safes.Values) {
            $e = Test-SafeExists -SafeName $s.Name
            $Plan.SafePre[$s.Name] = @{ Exists = $e.Exists; Error = $(if ($e.Ok) { $null } else { "Could not check safe '$($s.Name)': $($e.Error)" }) }
            if ($Mode -eq "AccountOnly" -and $e.Ok -and -not $e.Exists) { $Plan.SafePre[$s.Name].Error = "Safe '$($s.Name)' does not exist (Account-only mode never creates safes)" }
        }
    }
    if ($Mode -in @("Full", "AccountOnly")) {
        foreach ($it in $Plan.Items) {
            $existsInSafe = $Plan.SafePre[$it.SafeName]
            if ($existsInSafe -and $existsInSafe.Exists) {
                $a = Find-CAAccount -SafeName $it.SafeName -UserName $it.AccountUserName -Address $it.Address
                $Plan.AccountPre[$it.RowNum] = @{ Exists = [bool]$a.Account; Error = $(if ($a.Ok) { $null } else { "Could not check account: $($a.Error)" }) }
            } else {
                $Plan.AccountPre[$it.RowNum] = @{ Exists = $false; Error = $null }
            }
        }
    }
}

function Show-Preview {
    param([Parameter(Mandatory)][string]$Mode, [Parameter(Mandatory)]$Plan)
    Write-Log "=== Preview ($Mode): $($Plan.Safes.Count) safe(s), $($Plan.Platforms.Count) platform(s), $($Plan.Items.Count) row(s) ===" SECTION
    Write-Host ""

    if ($Mode -eq "AccountOnly") {
        Write-Host "PLATFORMS (must already exist and be active)" -ForegroundColor White
        foreach ($id in $Plan.PlatformPre.Keys) {
            $pre = $Plan.PlatformPre[$id]
            if ($pre.Error) { Write-Host ("  [ERROR ] {0}  - {1}" -f $id, $pre.Error) -ForegroundColor Red }
            else            { Write-Host ("  [OK    ] {0}" -f $id) -ForegroundColor Green }
        }
        Write-Host ""
    }
    if ($Plan.Platforms -and $Plan.Platforms.Count -gt 0 -and $Mode -in @("PlatformOnly", "Full")) {
        Write-Host "PLATFORMS" -ForegroundColor White
        foreach ($p in $Plan.Platforms.Values) {
            $pre = $Plan.PlatformPre[$p.Name]
            if ($pre.Error)       { Write-Host ("  [ERROR ] {0}  - {1}" -f $p.Name, $pre.Error) -ForegroundColor Red }
            elseif ($pre.Target)  { Write-Host ("  [REUSE ] {0}  (already exists{1})" -f $p.Name, $(if (-not $pre.Target.Active) { ", inactive -> will activate" } else { "" })) -ForegroundColor Yellow }
            else                  { Write-Host ("  [CREATE] {0}  <- duplicate of {1}" -f $p.Name, $p.SourceId) -ForegroundColor Green }
        }
        Write-Host ""
    }
    if ($Plan.Safes -and $Plan.Safes.Count -gt 0) {
        Write-Host "SAFES" -ForegroundColor White
        foreach ($s in $Plan.Safes.Values) {
            $pre = $Plan.SafePre[$s.Name]
            $cpm = Resolve-ManagingCpm -Region $s.Region -Tier $s.Tier -Override $s.ManagingCpm
            $cpmText = if ($cpm) { "CPM=$cpm" } else { "CPM=(blank)" }
            if ($pre.Error)      { Write-Host ("  [ERROR ] {0}  - {1}" -f $s.Name, $pre.Error) -ForegroundColor Red }
            elseif ($pre.Exists) { Write-Host ("  [REUSE ] {0}  ({1})" -f $s.Name, $(if ($Mode -eq "AccountOnly") { "exists" } else { "exists; missing members will still be added" })) -ForegroundColor Yellow }
            else                 { Write-Host ("  [CREATE] {0}  {1}" -f $s.Name, $cpmText) -ForegroundColor Green }
            if ($Mode -ne "AccountOnly") {
                foreach ($m in (Get-SafeMemberPlan -SafeName $s.Name)) {
                    Write-Host ("             member: {0}  ({1}, {2})" -f $m.MemberName, $m.PermissionSet, $m.Source) -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    }
    if ($Mode -in @("Full", "AccountOnly")) {
        Write-Host "ACCOUNTS" -ForegroundColor White
        foreach ($it in $Plan.Items) {
            $pre = $Plan.AccountPre[$it.RowNum]
            $plat = if ($it.PlatformName) { $it.PlatformName } else { $it.PlatformId }
            $platKey = if ($it.PlatformName) { $it.PlatformName } else { $it.PlatformId }
            $blocker = $null
            if ($Plan.PlatformPre[$platKey] -and $Plan.PlatformPre[$platKey].Error) { $blocker = "platform: " + $Plan.PlatformPre[$platKey].Error }
            elseif ($Plan.SafePre[$it.SafeName] -and $Plan.SafePre[$it.SafeName].Error) { $blocker = "safe: " + $Plan.SafePre[$it.SafeName].Error }
            elseif ($pre -and $pre.Error) { $blocker = $pre.Error }
            $tag = if ($blocker) { "[ERROR ]" } elseif ($pre -and $pre.Exists) { "[EXISTS]" } else { "[CREATE]" }
            $col = if ($tag -eq "[ERROR ]") { "Red" } elseif ($tag -eq "[EXISTS]") { "Yellow" } else { "Green" }
            Write-Host ("  {0} row {1}: {2}@{3}  safe={4}  platform={5}{6}" -f $tag, $it.RowNum, $it.AccountUserName, $it.Address, $it.SafeName, $plat, $(if ($blocker) { "  -> will be SKIPPED ($blocker)" } else { "" })) -ForegroundColor $col
        }
        Write-Host ""
    }
}
#endregion

#region Phase 1: platforms
function Invoke-PlatformPhase {
    param([Parameter(Mandatory)]$Plan)
    $out = @{}
    foreach ($p in $Plan.Platforms.Values) {
        Write-Log "--- Platform: $($p.Name) ---" SECTION
        $pre = $Plan.PlatformPre[$p.Name]
        $act = [bool]$Global:Onb.Config.platformDefaults.activateAfterCreate

        if ($pre.Error) {
            Write-Log $pre.Error ERROR
            $out[$p.Name] = @{ Success = $false; PlatformId = $null }
            Add-Result -Type Platform -PlatformName $p.Name -Action "None" -Status "Failed" -Detail $pre.Error
            continue
        }
        if ($pre.Target) {
            $id = if ($pre.Target.PlatformId) { $pre.Target.PlatformId } else { $p.Name }
            Write-Log "Platform '$($p.Name)' already exists - reusing (PlatformID '$id')." INFO
            $detail = ""
            if (-not $pre.Target.Active -and $act -and $null -ne $pre.Target.NumericId) {
                $a = Enable-TargetPlatform -NumericId $pre.Target.NumericId
                if ($a.Success) { Write-Log "Activated existing inactive platform '$($p.Name)'." SUCCESS; $detail = "Activated" }
                else { $detail = "Exists but could not be activated: $($a.Error)"; Write-Log $detail ERROR }
            }
            $out[$p.Name] = @{ Success = $true; PlatformId = $id }
            Add-Result -Type Platform -PlatformName $p.Name -Action "Reused" -Status "Success" -Detail $detail
            continue
        }

        $desc = Get-CreatedByDescription -Text $p.Description -MaxLength ([int]$Global:Onb.Config.descriptions.platformMaxLength)
        $dup  = Copy-TargetPlatform -SourceNumericId $pre.Source.NumericId -NewName $p.Name -Description $desc
        if (-not $dup.Success) {
            Write-Log "Failed to duplicate '$($p.SourceId)' as '$($p.Name)': $($dup.Error)" ERROR
            $out[$p.Name] = @{ Success = $false; PlatformId = $null }
            Add-Result -Type Platform -PlatformName $p.Name -Action "Create" -Status "Failed" -Detail $dup.Error
            continue
        }
        $new = Resolve-NewPlatform -DuplicateResponse $dup.Data -NewName $p.Name
        $detail = ""
        if ($act) {
            if ($null -ne $new.NumericId) {
                $a = Enable-TargetPlatform -NumericId $new.NumericId
                if ($a.Success) { Write-Log "Platform '$($p.Name)' activated." SUCCESS; $detail = "Created and activated" }
                else { $detail = "Created but activation FAILED: $($a.Error) - activate it in the portal before onboarding accounts"; Write-Log $detail ERROR }
            } else {
                $detail = "Created but numeric ID unknown, so it was NOT activated - activate it in the portal"; Write-Log $detail ERROR
            }
        }
        $platformId = $new.PlatformId
        if (-not $platformId) {
            $platformId = $p.Name
            Write-Log "Could not confirm the PlatformID string for '$($p.Name)'; using the name. If account onboarding says 'platform not found', check the ID in the portal." WARN
        }
        Write-Log "Platform '$($p.Name)' created from '$($p.SourceId)' (PlatformID '$platformId')." SUCCESS
        $out[$p.Name] = @{ Success = $true; PlatformId = $platformId }
        Add-Result -Type Platform -PlatformName $p.Name -Action "Created" -Status "Success" -Detail $detail
    }
    return $out
}
#endregion

#region Phase 2: safes + members
function Invoke-SafePhase {
    param([Parameter(Mandatory)]$Plan)
    $out = @{}
    foreach ($s in $Plan.Safes.Values) {
        Write-Log "--- Safe: $($s.Name) ---" SECTION
        $pre = $Plan.SafePre[$s.Name]
        if ($pre.Error) {
            Write-Log $pre.Error ERROR
            $out[$s.Name] = @{ Success = $false }
            Add-Result -Type Safe -SafeName $s.Name -Action "None" -Status "Failed" -Detail $pre.Error
            continue
        }
        $action = "Reused"; $cpmNote = ""
        if ($pre.Exists) {
            Write-Log "Safe '$($s.Name)' already exists - reusing." INFO
        } else {
            $cands = @(Get-ManagingCpmCandidates -Region $s.Region -Tier $s.Tier -Override $s.ManagingCpm)
            if ($cands.Count -eq 0) { Write-Log "No managing CPM is configured for safe '$($s.Name)' (safeDefaults.managingCpm is blank) - the safe will be created WITHOUT a CPM. Set one before Verify/Reconcile can work." WARN }
            $fallback = ($null -eq $Global:Onb.Config.safeDefaults.fallbackToBlankCpm) -or [bool]$Global:Onb.Config.safeDefaults.fallbackToBlankCpm
            # Try each configured CPM in precedence order; if none is accepted (e.g. it does not exist in this
            # tenant) create the safe with a blank CPM instead of failing - unless fallbackToBlankCpm is off.
            $attempts = @($cands)
            if ($cands.Count -eq 0 -or $fallback) { $attempts += "" }
            $desc = Get-CreatedByDescription -Text $s.Description -MaxLength ([int]$Global:Onb.Config.descriptions.safeMaxLength)
            $r = $null; $usedCpm = $null
            for ($i = 0; $i -lt $attempts.Count; $i++) {
                $try = [string]$attempts[$i]
                $more = ($i -lt $attempts.Count - 1)
                $r = New-CASafe -SafeName $s.Name -Description $desc -ManagingCpm $try -ExpectRejection:($more -and [bool]$try)
                if ($r.Success) { $usedCpm = $try; break }
                if ($r.StatusCode -ne 400 -or -not $try -or -not $more) { break }
                $next = [string]$attempts[$i + 1]
                Write-Log "managingCPM '$try' was not accepted for safe '$($s.Name)' ($($r.Error)) - $(if ($next) { "trying '$next'" } else { 'creating the safe with a BLANK CPM instead' })." WARN
            }
            if (-not $r.Success) {
                Write-Log "Failed to create safe '$($s.Name)': $($r.Error)" ERROR
                if ($r.StatusCode -eq 400) {
                    $hint = "HINT (HTTP 400 = a parameter value was rejected). Values sent: managingCPM='$($attempts[-1])', description='$desc'. Check (1) managingCPM matches an existing CPM name EXACTLY (run -Mode Diagnose: it lists the managingCPM values already used by your safes) and (2) that the description characters are accepted (try descriptions.separator = "" - "" in the config)."
                    Write-Log $hint WARN
                }
                $out[$s.Name] = @{ Success = $false }
                Add-Result -Type Safe -SafeName $s.Name -Action "Create" -Status "Failed" -Detail $r.Error
                continue
            }
            if ($cands.Count -gt 0 -and $usedCpm -ne $cands[0]) {
                $cpmNote = if ($usedCpm) { "Preferred managingCPM '$($cands[0])' was not accepted; safe created with '$usedCpm'" } else { "managingCPM '$($cands[0])' was not accepted (not found in this tenant?); safe created with a BLANK CPM - assign one before Verify/Reconcile" }
                Write-Log $cpmNote WARN
            }
            Write-Log "Safe '$($s.Name)' created." SUCCESS
            $action = "Created"
        }

        $missing = @(); $failed = @(); $added = 0
        foreach ($m in (Get-SafeMemberPlan -SafeName $s.Name)) {
            $r = Add-CASafeMember -SafeName $s.Name -Member $m
            switch ($r.Outcome) {
                "Added"   { $added++; Write-Log "Member '$($m.MemberName)' added to '$($s.Name)' as $($m.PermissionSet)." SUCCESS }
                "Exists"  { Write-Log "Member '$($m.MemberName)' is already on '$($s.Name)'." INFO }
                "Missing" { $missing += $m.MemberName; Write-Alert "MISSING GROUP: '$($m.MemberName)' is not defined in CyberArk, so it was NOT added to safe '$($s.Name)'. Create/sync the group, then add it to the safe ($($m.PermissionSet))." }
                default   { $failed += $m.MemberName; Write-Alert "MEMBER NOT ADDED: '$($m.MemberName)' on safe '$($s.Name)' - $($r.Error)" }
            }
        }
        $detail = @()
        if ($cpmNote) { $detail += $cpmNote }
        if ($missing.Count) { $detail += "MISSING GROUPS: $($missing -join ', ')" }
        if ($failed.Count)  { $detail += "MEMBER ERRORS: $($failed -join ', ')" }
        $out[$s.Name] = @{ Success = $true; Missing = $missing; Failed = $failed }
        Add-Result -Type Safe -SafeName $s.Name -Action $action -Status $(if ($detail.Count) { "PartialSuccess" } else { "Success" }) -Detail ($detail -join " | ")
    }
    return $out
}
#endregion

#region Phase 3: accounts (+ optional Verify / Reconcile)
function Invoke-AccountPhase {
    param([Parameter(Mandatory)]$Plan, $PlatformResults, $SafeResults, [bool]$RunVerify, [bool]$RunReconcile, [bool]$PromptSecrets)
    foreach ($it in $Plan.Items) {
        Write-Log "--- Account: $($it.AccountUserName)@$($it.Address) in safe '$($it.SafeName)' ---" SECTION
        $skip = {
            param($reason, $status = "Skipped")
            Write-Log "Skipping account '$($it.AccountUserName)': $reason" WARN
            Add-Result -Type Account -RowNum $it.RowNum -SafeName $it.SafeName -PlatformName $(if ($it.PlatformName) { $it.PlatformName } else { $it.PlatformId }) `
                -AccountUserName $it.AccountUserName -Action "None" -Status $status -Detail $reason
        }

        # Resolve platform
        $platformId = $it.PlatformId
        if ($it.PlatformName) {
            $pr = $PlatformResults[$it.PlatformName]
            if (-not $pr -or -not $pr.Success) { & $skip "platform '$($it.PlatformName)' failed earlier in this run"; continue }
            $platformId = $pr.PlatformId
        } else {
            $pre = $Plan.PlatformPre[$it.PlatformId]
            if ($pre -and $pre.Error) { & $skip $pre.Error; continue }
        }
        # Resolve safe
        if ($SafeResults) {
            $sr = $SafeResults[$it.SafeName]
            if (-not $sr -or -not $sr.Success) { & $skip "safe '$($it.SafeName)' failed earlier in this run"; continue }
        } else {
            $sp = $Plan.SafePre[$it.SafeName]
            if ($sp -and $sp.Error) { & $skip $sp.Error; continue }
        }
        $ap = $Plan.AccountPre[$it.RowNum]
        if ($ap -and $ap.Error)  { & $skip $ap.Error "Failed"; continue }
        if ($ap -and $ap.Exists) { & $skip "account already exists in the safe (not modified)" "Exists"; continue }

        $secret = $it.InitialSecret
        if (-not $secret -and $PromptSecrets) {
            $sec = Read-SecretPrompt -Prompt "  Initial secret for $($it.AccountUserName)@$($it.Address) (Enter to create without one)"
            if ($sec) { $secret = ConvertFrom-SecureStringPlain -Secure $sec }
        }
        $name = if ($it.AccountName) { $it.AccountName } else { Get-AccountName -PlatformId $platformId -Address $it.Address -UserName $it.AccountUserName }
        $desc = Get-CreatedByDescription -Text $it.Description -MaxLength ([int]$Global:Onb.Config.descriptions.accountMaxLength)

        $r = New-CAAccount -SafeName $it.SafeName -PlatformId $platformId -UserName $it.AccountUserName -Address $it.Address -Name $name `
            -SecretType $it.SecretType -Secret $secret -Properties $it.Properties -AutoManage $it.AutoManage -ManualReason $it.ManualReason -Description $desc
        $secret = $null
        if (-not $r.Success) {
            Write-Log "Failed to onboard account '$($it.AccountUserName)': $($r.Error)" ERROR
            Add-Result -Type Account -RowNum $it.RowNum -SafeName $it.SafeName -PlatformName $platformId -AccountUserName $it.AccountUserName -Action "Create" -Status "Failed" -Detail $r.Error
            continue
        }
        $accountId = [string]$r.Data.id
        Write-Log "Account onboarded, id=$accountId." SUCCESS

        $verify = "NotRequested"; $reconcile = "NotRequested"; $ok = $true; $notes = @()
        if ($RunVerify) {
            $before = Get-AccountTaskMarker -AccountId $accountId -Task Verify
            $t = Invoke-AccountTask -AccountId $accountId -Task Verify
            if ($t.Success) { $w = Wait-AccountTask -AccountId $accountId -Task Verify -Before $before; $verify = $(if ($w.Success) { "Success" } else { $w.Status }); if (-not $w.Success) { $ok = $false } }
            else { $verify = "NotQueued"; $ok = $false; $notes += "Verify not queued: $($t.Error)" }
        }
        if ($RunReconcile) {
            $before = Get-AccountTaskMarker -AccountId $accountId -Task Reconcile
            $t = Invoke-AccountTask -AccountId $accountId -Task Reconcile
            if ($t.Success) { $w = Wait-AccountTask -AccountId $accountId -Task Reconcile -Before $before; $reconcile = $(if ($w.Success) { "Success" } else { $w.Status }); if (-not $w.Success) { $ok = $false } }
            else { $reconcile = "NotQueued"; $ok = $false; $notes += "Reconcile not queued: $($t.Error)" }
        }
        $status = if ($ok) { "Success" } else { "PartialSuccess" }
        if ($status -ne "Success") { Write-Log "Account '$($it.AccountUserName)' onboarded, but follow-up needs attention (verify=$verify, reconcile=$reconcile)." WARN }
        Add-Result -Type Account -RowNum $it.RowNum -SafeName $it.SafeName -PlatformName $platformId -AccountUserName $it.AccountUserName -AccountId $accountId `
            -Action "Created" -Status $status -Verify $verify -Reconcile $reconcile -Detail ($notes -join " | ")
    }
}
#endregion

#region Diagnose + summary
function Invoke-Diagnose {
    param([string]$SafeName)
    Write-Log "--- Diagnose: platforms ---" SECTION
    $r = Invoke-CyberArkApi -Method GET -Path "Platforms/Targets"
    if ($r.Success) {
        $list = @($r.Data.Platforms)
        Write-Log "GET Platforms/Targets OK - $($list.Count) platform(s) returned. Top-level keys: $(($r.Data.PSObject.Properties.Name) -join ', ')" SUCCESS
        if ($list.Count -gt 0) {
            Write-Log "First platform (raw shape): $(($list[0] | ConvertTo-Json -Depth 4 -Compress))" INFO
            $info = ConvertTo-PlatformInfo $list[0]
            Write-Log "Parsed as -> NumericId=$($info.NumericId) PlatformId=$($info.PlatformId) Name='$($info.Name)' Active=$($info.Active)" INFO
            if ($null -eq $info.NumericId -or -not $info.PlatformId) { Write-Log "The numeric ID and/or PlatformID could not be parsed - send this output back so ConvertTo-PlatformInfo can be adjusted." ERROR }
        }
    }
    Write-Log "--- Diagnose: safes ---" SECTION
    $r = Invoke-CyberArkApi -Method GET -Path "Safes?limit=1"
    if ($r.Success) { Write-Log "GET Safes OK. Sample: $(($r.Data | ConvertTo-Json -Depth 3 -Compress))" SUCCESS }
    $many = Invoke-CyberArkApi -Method GET -Path "Safes?limit=100"
    if ($many.Success) {
        $cpms = @(@($many.Data.value) | ForEach-Object { Get-FirstProperty $_ @("managingCPM", "ManagingCPM") } | Where-Object { $_ } | Sort-Object -Unique)
        if ($cpms.Count -gt 0) { Write-Log "managingCPM values in use on existing safes (copy EXACTLY into config): $($cpms -join ' | ')" SUCCESS }
        else { Write-Log "No existing safe (in the first 100) reports a managingCPM value." WARN }
    }
    if ($SafeName) {
        Write-Log "--- Diagnose: members of '$SafeName' ---" SECTION
        $r = Invoke-CyberArkApi -Method GET -Path "Safes/$([uri]::EscapeDataString($SafeName))/Members"
        if ($r.Success) {
            foreach ($m in @($r.Data.value)) { Write-Log ("  {0} | memberType={1} | searchIn={2}" -f $m.memberName, $m.memberType, $m.searchIn) INFO }
        }
    }
}

function Show-RunSummary {
    $res = @($Global:Onb.Results)
    if ($res.Count -gt 0) {
        Write-Host ""
        Write-Host "RESULTS" -ForegroundColor White
        $res | Format-Table Type, SafeName, PlatformName, AccountUserName, Action, Status, Verify, Reconcile -AutoSize | Out-String -Width 200 | Write-Host
    }
    if ($Global:Onb.Alerts.Count -gt 0) {
        Write-Host ""
        Write-Host ("=" * 78) -ForegroundColor White -BackgroundColor DarkRed
        Write-Host " ACTION REQUIRED - the following members were NOT added and must be fixed:" -ForegroundColor White -BackgroundColor DarkRed
        Write-Host ("=" * 78) -ForegroundColor White -BackgroundColor DarkRed
        foreach ($a in $Global:Onb.Alerts) { Write-Host "  * $a" -ForegroundColor White -BackgroundColor DarkRed }
        Write-Host ""
    }
}

function Complete-Run {
    if (-not $Global:Onb -or $Global:Onb.Finalized) { return }
    $Global:Onb.Finalized = $true
    if (-not $Global:Onb.LogFile) { return }
    $results = $null
    if ($Global:Onb.Results.Count -gt 0) {
        try { @($Global:Onb.Results) | Export-Csv -LiteralPath $Global:Onb.ResultsFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false; $results = $Global:Onb.ResultsFile; Write-Log "Results written to $results" INFO }
        catch { Write-Log "Could not write results CSV: $($_.Exception.Message)" ERROR }
    }
    Write-Log "Run finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'). Alerts raised: $($Global:Onb.Alerts.Count)." SECTION
    try { Publish-RunArtifacts -Paths @($Global:Onb.LogFile, $results) }
    catch { Write-Log "Unexpected error while publishing logs: $($_.Exception.Message). Upload '$($Global:Onb.LogFile)' manually." ERROR }
}
#endregion
