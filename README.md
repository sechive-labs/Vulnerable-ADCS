# Vulnerable-ADCS

Create a vulnerable Active Directory Certificate Services (AD CS) environment that allows you to test the most common AD CS attacks (ESC1 to ESC8) in a local lab.

## Main Features

* One-shot deployment of ESC1 through ESC8
* Optionally installs and configures the CA for you (`-InstallCA`)
* No external PowerShell modules required
* Built-in cleanup to tear the lab down (`-Cleanup`)
* Works on Windows Server 2016, 2019 and 2022
* You need to run the script on a DC with an Enterprise CA (or let the script install one)

## Supported Misconfigurations

* ESC1 - Enrollee-supplies-subject + client authentication EKU
* ESC2 - Any Purpose (or no) EKU
* ESC3 - Enrollment Agent (Certificate Request Agent) template
* ESC4 - Vulnerable certificate template ACL
* ESC5 - Vulnerable PKI object ACL
* ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA
* ESC7 - Vulnerable CA ACL (ManageCA / ManageCertificates)
* ESC8 - Web Enrollment enabled over HTTP

## Example

```powershell
# if you already have Active Directory, just run the script
# use -InstallCA to also install the CA if you don't have one yet
.\Vulnerable-ADCS.ps1 -InstallCA

# tear the lab down
.\Vulnerable-ADCS.ps1 -Cleanup
```

## Note

Patched DCs enforce strong certificate mapping (KB5014754), which can stop the issued certificates from authenticating. To make the lab behave like the original research, set the DC to Compatibility mode:

```powershell
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name StrongCertificateBindingEnforcement -Value 1
Restart-Service kdc
```

