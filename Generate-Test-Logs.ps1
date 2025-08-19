# =============================================================================
# Elastic SIEM - Admin Activity Test Script
# =============================================================================

# Step 1: Check for Administrator Privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges. Please right-click the file and select 'Run with PowerShell'."
    Read-Host "Press Enter to exit..."
    exit
}

# A helper function to pause the script
function Wait-And-Continue {
    param(
        [string]$Message
    )
    Write-Host "`n$Message" -ForegroundColor Yellow
    Read-Host "Press Enter to continue to the next test..."
}

# --- SCRIPT START ---
Clear-Host
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Elastic SIEM Admin Activity Generation Tool" -ForegroundColor Cyan
Write-Host "=============================================="
Write-Host "This script will create and modify local users and policies to generate specific"
Write-Host "Windows Security Event Logs. Each step will pause so you can check for the log in Kibana."

# Define a secure password for test users
$Password = ConvertTo-SecureString "P@ssword-123!" -AsPlainText -Force

# =============================================================================
# TEST CASE 1: User Creation (Event ID 4720)
# =============================================================================
Wait-And-Continue "TEST 1: USER CREATION. A user named 'siem-test-user-1' will be created."

New-LocalUser -Name "siem-test-user-1" -Password $Password -FullName "SIEM Test User (Creation)" -Description "Test user for creation event."
Write-Host "--> ACTION: User 'siem-test-user-1' created." -ForegroundColor Green
Write-Host "--> In Kibana, set time to 'Last 5 minutes' and search for: winlog.event_id : 4720"

# =============================================================================
# TEST CASE 2: Disable User (Event ID 4725)
# =============================================================================
Wait-And-Continue "TEST 2: DISABLE USER. The user 'siem-test-user-1' will now be disabled."

net user "siem-test-user-1" /active:no
Write-Host "--> ACTION: User 'siem-test-user-1' disabled." -ForegroundColor Green
Write-Host "--> In Kibana, search for: winlog.event_id : 4725"

# =============================================================================
# TEST CASE 3: User Privilege Escalation (Event ID 4732)
# =============================================================================
Wait-And-Continue "TEST 3: PRIVILEGE ESCALATION. A new user 'siem-test-user-2' will be created and added to the 'Administrators' group."

New-LocalUser -Name "siem-test-user-2" -Password $Password -FullName "SIEM Test User (PrivEsc)" -Description "Test user for privilege escalation event."
Add-LocalGroupMember -Group "Administrators" -Member "siem-test-user-2"
Write-Host "--> ACTION: User 'siem-test-user-2' added to the local Administrators group." -ForegroundColor Green
Write-Host "--> In Kibana, search for: winlog.event_id : 4732"

# =============================================================================
# TEST CASE 4: User Deletion (Event ID 4726)
# =============================================================================
Wait-And-Continue "TEST 4: USER DELETION. The user 'siem-test-user-1' will be deleted."

Remove-LocalUser -Name "siem-test-user-1"
Write-Host "--> ACTION: User 'siem-test-user-1' deleted." -ForegroundColor Green
Write-Host "--> In Kibana, search for: winlog.event_id : 4726"

# =============================================================================
# TEST CASE 5: Audit Policy Change (Event ID 4719)
# =============================================================================
Wait-And-Continue "TEST 5: POLICY CHANGE. The system audit policy for 'Logon' events will be changed."

# We enable both success and failure auditing for the "Logon" subcategory
auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
Write-Host "--> ACTION: System audit policy for 'Logon' was changed." -ForegroundColor Green
Write-Host "--> In Kibana, search for: winlog.event_id : 4719"

# =============================================================================
# TEST CASE 6: User Lockout (Event ID 4740) - AUTOMATED
# =============================================================================
Wait-And-Continue "TEST 6: USER LOCKOUT. This test is now automated."

Write-Host "--> Creating a temporary user 'lockout-test-user'..." -ForegroundColor Green
New-LocalUser -Name "lockout-test-user" -Password $Password -FullName "SIEM Test User (Lockout)"

# Get the account lockout threshold from the system policy
$lockoutThreshold = (net accounts | Select-String "Lockout threshold").ToString().Split(':')[1].Trim()
if ($lockoutThreshold -eq 'Never') {
    Write-Warning "Account lockout threshold is set to 'Never' on this machine. Cannot trigger a lockout. Skipping."
} else {
    # Add 1 to the threshold to ensure a lockout occurs
    $attempts = [int]$lockoutThreshold + 1
    Write-Host "--> Account lockout threshold is $lockoutThreshold. Simulating $attempts failed logins..." -ForegroundColor Yellow
    for ($i = 1; $i -le $attempts; $i++) {
        # Simulate a failed login by trying to access a local resource with bad credentials.
        # Error messages are expected and normal, so they are hidden.
        net use \\127.0.0.1\ipc$ /user:lockout-test-user "a_very_bad_password" *>$null
    }
    Write-Host "--> ACTION: User 'lockout-test-user' should now be locked out." -ForegroundColor Green
    Write-Host "--> In Kibana, search for: winlog.event_id : 4740"
}
# =============================================================================
# FINAL CLEANUP
# =============================================================================
Write-Host "`nAll tests are complete. The script will now clean up the remaining test users." -ForegroundColor Cyan
Remove-LocalUser -Name "siem-test-user-2"
Remove-LocalUser -Name "lockout-test-user"
Write-Host "--> ACTION: All test users have been deleted." -ForegroundColor Green

Read-Host "`nCleanup complete. Press Enter to exit the script."