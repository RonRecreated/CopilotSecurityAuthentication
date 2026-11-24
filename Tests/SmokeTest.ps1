param([string]$BaseUrl = 'https://localhost:7001')
$ErrorActionPreference = 'Stop'

# Run this with PowerShell 7 while the website is running. Only the local development
# certificate check is skipped here; the application's HTTPS requirements stay enabled.
function Assert-Check($condition, $message) {
    if (!$condition) { throw $message }
    Write-Host "PASS: $message"
}

$page = Invoke-WebRequest "$BaseUrl/Login" -SkipCertificateCheck -SessionVariable browser
Assert-Check ($page.StatusCode -eq 200) 'Login page loads'
$token = [regex]::Match($page.Content, 'name="__RequestVerificationToken"[^>]*value="([^"]+)"').Groups[1].Value
Assert-Check ($token.Length -gt 0) 'Form contains an anti-forgery token'
Assert-Check ($page.Headers['Content-Security-Policy'] -match "default-src 'none'") 'CSP header is present'

$privatePage = Invoke-WebRequest "$BaseUrl/" -SkipCertificateCheck -WebSession $browser -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue
Assert-Check ([int]$privatePage.StatusCode -eq 302) 'Account page requires login'
Assert-Check ($privatePage.Headers.Location -match '/Login') 'Anonymous users are redirected to login'

$missingToken = Invoke-WebRequest "$BaseUrl/Login" -Method Post -SkipCertificateCheck -WebSession $browser -SkipHttpErrorCheck -Body @{
    Username = 'alice'; Password = 'a long test password'
}
Assert-Check ([int]$missingToken.StatusCode -eq 400) 'POST without anti-forgery token is rejected'

foreach ($username in @("admin' OR 1=1 --", '<img src=x onerror=alert(1)>')) {
    $reply = Invoke-WebRequest "$BaseUrl/Login" -Method Post -SkipCertificateCheck -WebSession $browser -Body @{
        Username = $username; Password = 'a long test password'; __RequestVerificationToken = $token
    }
    Assert-Check ($reply.Content -match 'Invalid username or password') 'Attack username is rejected'
    Assert-Check ($reply.Content -notmatch '<img src=x') 'Reflected input does not create an HTML element'
    Assert-Check ($reply.Headers['Set-Cookie'] -notmatch '__Host-SecureLogin=') 'Rejected login does not create an authentication cookie'
}

# Fill the remaining login POST quota using input rejected before database access.
$limited = $null
for ($attempt = 0; $attempt -lt 11; $attempt++) {
    $limited = Invoke-WebRequest "$BaseUrl/Login" -Method Post -SkipCertificateCheck -WebSession $browser -SkipHttpErrorCheck -Body @{
        Username = '!'; Password = 'a long test password'; __RequestVerificationToken = $token
    }
    if ([int]$limited.StatusCode -eq 429) { break }
}
Assert-Check ([int]$limited.StatusCode -eq 429) 'Excessive login attempts are rate limited'
