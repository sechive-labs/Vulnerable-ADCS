#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Vulnerable-ADCS : deploy intentionally misconfigured AD CS objects to build a
    lab for learning / demonstrating ESC1 through ESC8.

    This is the AD CS analogue of safebuffer/vulnerable-AD. It CREATES the
    weaknesses so you can practise detection & remediation. It does NOT attack,
    exploit, or test anything.

.DESCRIPTION
    Run on an isolated lab Domain Controller that is also (or can reach) an
    Enterprise CA. It will:
      - create a low-privileged test group + user
      - publish deliberately weak certificate templates (ESC1, ESC2, ESC3)
      - weaken template / PKI-object / CA ACLs (ESC4, ESC5, ESC7)
      - set the dangerous CA policy flag (ESC6)
      - ensure the Web Enrollment endpoint is present (ESC8)

    Every change is tagged with the prefix in $Prefix so -Cleanup can find and
    remove them again.

.PARAMETER Prefix
    Name prefix applied to every object this script creates. Default "ESC".

.PARAMETER LowPrivGroup
    Group that receives enrollment / abuse rights. Created if missing.

.PARAMETER LowPrivUser / -LowPrivPassword
    A member of that group, so you have credentials to authenticate as in the lab.

.PARAMETER InstallCA
    If no Enterprise CA is found, install & configure one (Enterprise Root CA +
    Web Enrollment) before deploying. Without this switch a missing CA is a hard
    stop - CA installation never happens implicitly.

.PARAMETER CACommonName
    CN for the CA created by -InstallCA. Default "Lab-Root-CA".

.PARAMETER Cleanup
    Remove everything this script created (best-effort) instead of deploying.
    Note: a CA installed via -InstallCA is NOT uninstalled by -Cleanup; remove it
    from the snapshot or with Uninstall-AdcsCertificationAuthority manually.

.EXAMPLE
    .\Vulnerable-ADCS.ps1
.EXAMPLE
    .\Vulnerable-ADCS.ps1 -InstallCA        # bootstrap CA if missing, then deploy
.EXAMPLE
    .\Vulnerable-ADCS.ps1 -Cleanup

.NOTES
    LAB ONLY. Snapshot the VM first. Untested against your specific environment —
    review before running and expect to tune a few environment-specific details
    (CA name resolution, schema version, remote-registry access for ESC7).
#>

[CmdletBinding()]
param(
    [string]$Prefix          = "ESC",
    [string]$LowPrivGroup    = "ESC-Enrollers",
    [string]$LowPrivUser     = "esc.user",
    [string]$LowPrivPassword = "Passw0rd!Lab123",
    [switch]$InstallCA,
    [string]$CACommonName    = "Lab-Root-CA",
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$script:Domain     = $null
$script:ConfigNC   = $null
$script:TemplateNC = $null
$script:CAName     = $null
$script:CAHost     = $null

# ---- EKU / extended-right OIDs ------------------------------------------------
$EKU = @{
    ClientAuth       = "1.3.6.1.5.5.7.3.2"
    ServerAuth       = "1.3.6.1.5.5.7.3.1"
    SmartcardLogon   = "1.3.6.1.4.1.311.20.2.2"
    PKINITClientAuth = "1.3.6.1.5.2.3.4"
    AnyPurpose       = "2.5.29.37.0"           # ESC2
    EnrollmentAgent  = "1.3.6.1.4.1.311.20.2.1" # ESC3
}
$RIGHT_ENROLL     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
$RIGHT_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# ---- msPKI flag constants -----------------------------------------------------
$CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1        # msPKI-Certificate-Name-Flag
$CT_FLAG_PEND_ALL_REQUESTS         = 0x2        # msPKI-Enrollment-Flag (manager approval)

# =============================================================================
#  Helpers
# =============================================================================
function Write-Step { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Good { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[-] $m" -ForegroundColor Red }

function Initialize-Context {
    Write-Step "Resolving environment..."
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch { throw "ActiveDirectory module not available. Run on a DC or install RSAT-AD-PowerShell." }

    $rootDse           = Get-ADRootDSE
    $script:ConfigNC   = $rootDse.configurationNamingContext
    $script:Domain     = (Get-ADDomain)
    $script:TemplateNC = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

    Write-Good "Domain : $($Domain.DNSRoot)"

    # Find an Enterprise CA published in the config partition.
    $ca = Find-EnterpriseCA
    if (-not $ca) {
        if ($InstallCA) {
            Install-LabCA
            Write-Step "Waiting for the CA to publish into AD..."
            $ca = $null
            for ($i = 0; $i -lt 12 -and -not $ca; $i++) { Start-Sleep 5; $ca = Find-EnterpriseCA }
            if (-not $ca) { throw "CA install ran but no pKIEnrollmentService appeared. Check AD replication / CertSvc, then re-run." }
        } else {
            throw "No Enterprise CA found. Re-run with -InstallCA to bootstrap one, or install/AD-publish an Enterprise CA first."
        }
    }
    $script:CAName = $ca.cn
    $script:CAHost = $ca.dNSHostName
    Write-Good "CA     : $CAName on $CAHost"
}

function Find-EnterpriseCA {
    $caContainer = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    Get-ADObject -SearchBase $caContainer -Filter { objectClass -eq "pKIEnrollmentService" } `
        -Properties dNSHostName, cn -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Install-LabCA {
    Write-Step "No Enterprise CA found - installing '$CACommonName' (Enterprise Root CA)..."

    # Enterprise CA installation writes to the Configuration partition, so this
    # must run as Enterprise Admin on a domain-joined host. Bail early if not.
    $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
    Write-Warn "Running CA install as: $me  (must be Enterprise Admin)"

    Write-Step "Adding role: ADCS-Cert-Authority"
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null

    Write-Step "Configuring Enterprise Root CA"
    try {
        Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
            -CACommonName $CACommonName -KeyLength 2048 -HashAlgorithm SHA256 `
            -ValidityPeriod Years -ValidityPeriodUnits 10 -Force -ErrorAction Stop | Out-Null
        Write-Good "CA role configured."
    } catch {
        # 0x80070520 / "object already exists" style errors mean it's already set up.
        if ($_.Exception.Message -match "already") { Write-Warn "CA role appears already configured - continuing." }
        else { throw }
    }

    Write-Step "Adding role: ADCS-Web-Enrollment (for ESC8 endpoint)"
    Install-WindowsFeature ADCS-Web-Enrollment | Out-Null
    try {
        Install-AdcsWebEnrollment -Force -ErrorAction Stop | Out-Null
        Write-Good "Web Enrollment configured (http://<host>/certsrv)."
    } catch { Write-Warn "Web Enrollment configure step: $($_.Exception.Message)" }

    try { Restart-Service certsvc -Force -ErrorAction SilentlyContinue } catch {}
}

function New-LowPrivPrincipals {
    Write-Step "Ensuring low-privileged test principals..."
    if (-not (Get-ADGroup -Filter "Name -eq '$LowPrivGroup'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $LowPrivGroup -GroupScope Global -GroupCategory Security -Description "Vulnerable-ADCS lab enrollers"
        Write-Good "Created group $LowPrivGroup"
    }
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$LowPrivUser'" -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $LowPrivUser -SamAccountName $LowPrivUser `
            -AccountPassword (ConvertTo-SecureString $LowPrivPassword -AsPlainText -Force) `
            -Enabled $true -PasswordNeverExpires $true `
            -Description "Vulnerable-ADCS lab user"
        Add-ADGroupMember -Identity $LowPrivGroup -Members $LowPrivUser
        Write-Good "Created user $LowPrivUser (member of $LowPrivGroup)"
    }
}

# Clone the built-in "User" template's byte-array/validity attributes so we get a
# schema-valid object, then override the interesting bits.
function New-VulnTemplate {
    param(
        [Parameter(Mandatory)] [string]   $Name,
        [Parameter(Mandatory)] [string[]] $ExtendedKeyUsage,   # empty array = no EKU (SubCA-style, ESC2)
        [int]     $NameFlag       = 0,
        [int]     $EnrollmentFlag = 0,
        [int]     $RASignature    = 0,
        [string[]]$ApplicationPolicy = @()
    )

    $cn     = "$Prefix-$Name"
    $dn     = "CN=$cn,$TemplateNC"
    if (Get-ADObject -Filter "distinguishedName -eq '$dn'" -ErrorAction SilentlyContinue) {
        Write-Warn "Template $cn already exists - skipping create."
        return $cn
    }

    # Pull a known-good source template to copy validity/period/flags from.
    $src = Get-ADObject "CN=User,$TemplateNC" -Properties * -ErrorAction Stop

    $attrs = @{
        displayName                      = $cn
        flags                            = 131649    # typical value; adjust if needed
        revision                         = 100
        "msPKI-Template-Schema-Version"  = 2         # v2 keeps this script simple
        "msPKI-Template-Minor-Revision"  = 1
        "msPKI-Cert-Template-OID"        = (New-TemplateOID)
        pKIDefaultKeySpec                = 1
        "msPKI-Minimal-Key-Size"         = 2048
        pKIMaxIssuingDepth               = 0
        pKIExpirationPeriod              = $src.pKIExpirationPeriod
        pKIOverlapPeriod                 = $src.pKIOverlapPeriod
        pKIKeyUsage                      = $src.pKIKeyUsage
        pKIDefaultCSPs                   = $src.pKIDefaultCSPs
        "msPKI-Certificate-Name-Flag"    = $NameFlag
        "msPKI-Enrollment-Flag"          = $EnrollmentFlag
        "msPKI-Private-Key-Flag"         = 16
        "msPKI-RA-Signature"             = $RASignature
    }
    if ($ExtendedKeyUsage.Count -gt 0) { $attrs["pKIExtendedKeyUsage"] = $ExtendedKeyUsage }
    if ($ApplicationPolicy.Count -gt 0) { $attrs["msPKI-Certificate-Application-Policy"] = $ApplicationPolicy }

    New-ADObject -Name $cn -Type "pKICertificateTemplate" -Path $TemplateNC -OtherAttributes $attrs
    Write-Good "Created template $cn"

    Grant-TemplateEnroll -TemplateCN $cn
    Publish-Template     -TemplateCN $cn
    return $cn
}

function New-TemplateOID {
    # Unique-enough OID under the Microsoft AD CS arc for lab use.
    $r = -join ((1..25) | ForEach-Object { Get-Random -Minimum 0 -Maximum 9 })
    return "1.3.6.1.4.1.311.21.8.$([int64]($r.Substring(0,7))).$([int64]($r.Substring(7,7)))"
}

function Grant-TemplateEnroll {
    param([string]$TemplateCN)
    $dn  = "CN=$TemplateCN,$TemplateNC"
    $grp = Get-ADGroup $LowPrivGroup
    $sid = New-Object System.Security.Principal.SecurityIdentifier $grp.SID
    $obj = [ADSI]"LDAP://$dn"
    $sd  = $obj.psbase.ObjectSecurity

    foreach ($right in @($RIGHT_ENROLL, $RIGHT_AUTOENROLL)) {
        $ace = New-Object System.DirectoryServices.ExtendedRightAccessRule(
            $sid, [System.Security.AccessControl.AccessControlType]::Allow, [guid]$right)
        $sd.AddAccessRule($ace)
    }
    $obj.psbase.ObjectSecurity = $sd
    $obj.psbase.CommitChanges()
    Write-Good "  Granted Enroll/AutoEnroll on $TemplateCN to $LowPrivGroup"
}

function Publish-Template {
    param([string]$TemplateCN)
    $caDn = "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    Set-ADObject -Identity $caDn -Add @{ certificateTemplates = $TemplateCN }
    Write-Good "  Published $TemplateCN to CA $CAName"
}

function Grant-DangerousTemplateAcl {
    # ESC4: give the low-priv group WriteDacl/WriteProperty over a template object
    # so they could rewrite it into an ESC1 template themselves.
    param([string]$TemplateCN)
    $dn  = "CN=$TemplateCN,$TemplateNC"
    $grp = Get-ADGroup $LowPrivGroup
    $sid = New-Object System.Security.Principal.SecurityIdentifier $grp.SID
    $obj = [ADSI]"LDAP://$dn"
    $sd  = $obj.psbase.ObjectSecurity
    $rights = [System.DirectoryServices.ActiveDirectoryRights]"WriteDacl, WriteOwner, GenericWrite"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid, $rights, [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    $sd.AddAccessRule($ace)
    $obj.psbase.ObjectSecurity = $sd
    $obj.psbase.CommitChanges()
    Write-Good "ESC4: granted WriteDacl/WriteOwner/GenericWrite on $TemplateCN to $LowPrivGroup"
}

# =============================================================================
#  ESC deployments
# =============================================================================
function Deploy-ESC1 {
    Write-Step "ESC1 : ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU, no manager approval, low-priv enroll"
    New-VulnTemplate -Name "ESC1" `
        -ExtendedKeyUsage  @($EKU.ClientAuth) `
        -ApplicationPolicy @($EKU.ClientAuth) `
        -NameFlag       $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT `
        -EnrollmentFlag 0 `
        -RASignature    0 | Out-Null
}

function Deploy-ESC2 {
    Write-Step "ESC2 : Any-Purpose EKU (or no EKU), low-priv enroll"
    New-VulnTemplate -Name "ESC2" `
        -ExtendedKeyUsage  @($EKU.AnyPurpose) `
        -ApplicationPolicy @($EKU.AnyPurpose) `
        -NameFlag 0 -EnrollmentFlag 0 | Out-Null
}

function Deploy-ESC3 {
    Write-Step "ESC3 : Certificate-Request-Agent (enrollment agent) template, low-priv enroll"
    New-VulnTemplate -Name "ESC3-Agent" `
        -ExtendedKeyUsage  @($EKU.EnrollmentAgent) `
        -ApplicationPolicy @($EKU.EnrollmentAgent) `
        -NameFlag 0 -EnrollmentFlag 0 | Out-Null
    # A companion target template that accepts an enrollment-agent signature.
    New-VulnTemplate -Name "ESC3-Target" `
        -ExtendedKeyUsage  @($EKU.ClientAuth) `
        -ApplicationPolicy @($EKU.ClientAuth) `
        -NameFlag 0 -EnrollmentFlag 0 -RASignature 1 | Out-Null
}

function Deploy-ESC4 {
    Write-Step "ESC4 : weak ACL over a certificate template"
    # Publish a benign template, then hand the low-priv group write control of it.
    $cn = New-VulnTemplate -Name "ESC4" `
            -ExtendedKeyUsage  @($EKU.ClientAuth) `
            -ApplicationPolicy @($EKU.ClientAuth) `
            -NameFlag 0 -EnrollmentFlag $CT_FLAG_PEND_ALL_REQUESTS
    Grant-DangerousTemplateAcl -TemplateCN $cn
}

function Deploy-ESC5 {
    Write-Step "ESC5 : weak ACL on a PKI object (CA host computer object)"
    try {
        $caComputer = ($CAHost -split '\.')[0]
        $comp = Get-ADComputer -Filter "Name -eq '$caComputer'" -ErrorAction Stop
        $grp  = Get-ADGroup $LowPrivGroup
        $sid  = New-Object System.Security.Principal.SecurityIdentifier $grp.SID
        $obj  = [ADSI]"LDAP://$($comp.DistinguishedName)"
        $sd   = $obj.psbase.ObjectSecurity
        $ace  = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid, [System.DirectoryServices.ActiveDirectoryRights]"GenericAll",
            [System.Security.AccessControl.AccessControlType]::Allow,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        $sd.AddAccessRule($ace)
        $obj.psbase.ObjectSecurity = $sd
        $obj.psbase.CommitChanges()
        Write-Good "ESC5: granted GenericAll over CA computer object to $LowPrivGroup"
    } catch { Write-Warn "ESC5 skipped ($($_.Exception.Message)). Grant control of the CA host / PKI container manually." }
}

function Deploy-ESC6 {
    Write-Step "ESC6 : EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA"
    & certutil -config "$CAHost\$CAName" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
    Write-Good "ESC6: flag set. Restarting CertSvc..."
    Restart-CAService
}

function Get-CASecurityKey {
    # Opens the CA's Security registry key (local or remote) for read/write.
    # Returns the RegistryKey (caller must .Close() it and its base).
    param([bool]$Writable = $false)
    $regPath   = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CAName"
    $caShort   = ($CAHost -split '\.')[0]
    $isLocal   = $caShort -ieq $env:COMPUTERNAME
    if ($isLocal) {
        $base = [Microsoft.Win32.Registry]::LocalMachine
    } else {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $caShort)
    }
    $key = $base.OpenSubKey($regPath, $Writable)
    if (-not $key) { $base.Close(); throw "Cannot open CA registry key '$regPath' on $caShort (remote registry service running?)." }
    return @{ Key = $key; Base = $base }
}

function Restart-CAService {
    $caShort = ($CAHost -split '\.')[0]
    if ($caShort -ieq $env:COMPUTERNAME) { Restart-Service certsvc -Force -ErrorAction SilentlyContinue }
    else {
        try { Invoke-Command -ComputerName $caShort -ScriptBlock { Restart-Service certsvc -Force } -ErrorAction Stop }
        catch { Write-Warn "Could not remote-restart CertSvc on $caShort. Run there: Restart-Service certsvc" }
    }
}

function Deploy-ESC7 {
    # ManageCA (0x1) + ManageCertificates (0x2) live in the CA's self-relative
    # security descriptor at HKLM\...\CertSvc\Configuration\<CA>\Security.
    # Editing that blob natively means no PSPKI dependency.
    Write-Step "ESC7 : ManageCA / ManageCertificates to a low-priv principal"
    $MANAGE_CA = 0x1; $MANAGE_CERTS = 0x2
    $mask = $MANAGE_CA -bor $MANAGE_CERTS
    $sid  = New-Object System.Security.Principal.SecurityIdentifier((Get-ADGroup $LowPrivGroup).SID)

    try {
        $h  = Get-CASecurityKey -Writable $true
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(([byte[]]$h.Key.GetValue("Security")), 0)

        $already = $false
        foreach ($ace in $sd.DiscretionaryAcl) {
            if ($ace.SecurityIdentifier -eq $sid -and
                $ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -and
                (($ace.AccessMask -band $mask) -eq $mask)) { $already = $true; break }
        }
        if ($already) {
            Write-Warn "ESC7: $LowPrivGroup already holds ManageCA/ManageCertificates - skipping."
        } else {
            $ace = New-Object System.Security.AccessControl.CommonAce(
                [System.Security.AccessControl.AceFlags]::None,
                [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                $mask, $sid, $false, $null)
            $sd.DiscretionaryAcl.InsertAce($sd.DiscretionaryAcl.Count, $ace)
            $bytes = New-Object byte[] $sd.BinaryLength
            $sd.GetBinaryForm($bytes, 0)
            $h.Key.SetValue("Security", $bytes, [Microsoft.Win32.RegistryValueKind]::Binary)
            Write-Good "ESC7: granted ManageCA+ManageCertificates to $LowPrivGroup"
        }
        $h.Key.Close(); $h.Base.Close()
        Restart-CAService
    } catch {
        Write-Err  "ESC7 native grant failed: $($_.Exception.Message)"
        Write-Warn "Manual GUI path: certsrv.msc -> right-click CA -> Properties -> Security -> add $LowPrivGroup -> allow 'Manage CA' and 'Issue and Manage Certificates'."
    }
}

function Remove-ESC7 {
    # Revert: drop any Allow ACE for the low-priv group from the CA security descriptor.
    $sid = $null
    try { $sid = New-Object System.Security.Principal.SecurityIdentifier((Get-ADGroup $LowPrivGroup -ErrorAction Stop).SID) } catch { return }
    try {
        $h  = Get-CASecurityKey -Writable $true
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(([byte[]]$h.Key.GetValue("Security")), 0)
        $removed = $false
        for ($i = $sd.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
            if ($sd.DiscretionaryAcl[$i].SecurityIdentifier -eq $sid) { $sd.DiscretionaryAcl.RemoveAce($i); $removed = $true }
        }
        if ($removed) {
            $bytes = New-Object byte[] $sd.BinaryLength
            $sd.GetBinaryForm($bytes, 0)
            $h.Key.SetValue("Security", $bytes, [Microsoft.Win32.RegistryValueKind]::Binary)
            Write-Good "Reverted ESC7 CA rights for $LowPrivGroup."
        }
        $h.Key.Close(); $h.Base.Close()
        if ($removed) { Restart-CAService }
    } catch { Write-Warn "Could not auto-revert ESC7 ($($_.Exception.Message)). Remove $LowPrivGroup in certsrv.msc -> Security." }
}

function Deploy-ESC8 {
    Write-Step "ESC8 : Web Enrollment endpoint present (HTTP, no EPA = relay-able)"
    $feat = Get-WindowsFeature -Name ADCS-Web-Enrollment -ErrorAction SilentlyContinue
    if ($feat -and -not $feat.Installed) {
        Write-Warn "Installing ADCS-Web-Enrollment role service..."
        Install-WindowsFeature ADCS-Web-Enrollment | Out-Null
        Write-Warn "Configure it on the CA: Install-AdcsWebEnrollment -Force"
    }
    Write-Good "ESC8: ensure http://$CAHost/certsrv is reachable and left on plain HTTP without Extended Protection for the lab."
}

# =============================================================================
#  Cleanup
# =============================================================================
function Invoke-Cleanup {
    Write-Step "Cleaning up objects with prefix '$Prefix'..."
    $caDn = "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    Get-ADObject -SearchBase $TemplateNC -Filter "objectClass -eq 'pKICertificateTemplate'" -Properties cn |
        Where-Object { $_.cn -like "$Prefix-*" } | ForEach-Object {
            try { Set-ADObject -Identity $caDn -Remove @{ certificateTemplates = $_.cn } -ErrorAction SilentlyContinue } catch {}
            Remove-ADObject -Identity $_.DistinguishedName -Confirm:$false
            Write-Good "Removed template $($_.cn)"
        }
    & certutil -config "$CAHost\$CAName" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 | Out-Null
    Write-Good "Reverted ESC6 flag (restart CertSvc to apply)."
    Remove-ESC7
    if (Get-ADUser  -Filter "SamAccountName -eq '$LowPrivUser'" -ErrorAction SilentlyContinue) { Remove-ADUser  $LowPrivUser  -Confirm:$false; Write-Good "Removed user $LowPrivUser" }
    if (Get-ADGroup -Filter "Name -eq '$LowPrivGroup'"        -ErrorAction SilentlyContinue) { Remove-ADGroup $LowPrivGroup -Confirm:$false; Write-Good "Removed group $LowPrivGroup" }
    Write-Warn "ESC5 (CA computer-object ACL) and the ESC8 role are not auto-reverted - undo those manually / from snapshot."
}

# =============================================================================
#  Main
# =============================================================================
Write-Host ""
Write-Host "  Vulnerable-ADCS  ::  LAB ONLY - snapshot first" -ForegroundColor Magenta
Write-Host "  ----------------------------------------------" -ForegroundColor Magenta

Initialize-Context

if ($Cleanup) { Invoke-Cleanup; Write-Good "Cleanup complete."; return }

New-LowPrivPrincipals
Deploy-ESC1
Deploy-ESC2
Deploy-ESC3
Deploy-ESC4
Deploy-ESC5
Deploy-ESC6
Deploy-ESC7
Deploy-ESC8

Write-Host ""
Write-Good "Vulnerable-ADCS deployment finished."
if ($InstallCA) { Write-Warn "A CA was ensured via -InstallCA; -Cleanup will NOT uninstall it." }
Write-Warn "Verify with a discovery tool of your choice, then practise remediation."
Write-Warn "Tear down with:  .\Vulnerable-ADCS.ps1 -Cleanup   (or restore the snapshot)."
