#Requires -Version 5.1
<#
.SYNOPSIS
  Collect issued certificates from a two-tier AD CS hierarchy and validate them by serial.

.DESCRIPTION
  Queries each issuing CA (two or more) for issued and revoked requests, loads the
  certificate, and records the common name, SAN, template, serial, and resolved
  IP addresses.

  Each issued certificate is the base record. Its common name and each SAN are clients of
  that serial. Several clients may use the same certificate; that is not a conflict.
  The collector then probes each client on this network: active, inactive, not in DNS,
  or not on the network. The check is the last-5-minute status for the air-gapped console.

  Output is cert-inventory.json (schema ca-ledger/1) for the CA Ledger console.
  Run this on a machine with the Certification Authority console (certadm.dll).
  The offline root is recorded by name only. End-entity rows come from issuing CAs.

.PARAMETER IssuingCa
  Config strings in the form 'hostname\CA Name'. Pass every issuing CA.

.PARAMETER RootCaName
  Name of the offline root CA. Not contacted.

.PARAMETER OutputPath
  JSON file to write. Default: .\cert-inventory.json

.PARAMETER ExpiryWindowDays
  Window used in the console summary. Default: 30

.PARAMETER IncludeExpired
  Also keep certificates whose NotAfter is already in the past.

.PARAMETER SkipDns
  Do not resolve CN and DNS SAN names.

.PARAMETER Demo
  Write a small sample file and do not contact a CA.

.EXAMPLE
  .\Invoke-CertInventory.ps1 -IssuingCa @(
    'pki-ica01.corp.local\CORP-ISSUING-CA-01',
    'pki-ica02.corp.local\CORP-ISSUING-CA-02'
  ) -RootCaName 'CORP-OFFLINE-ROOT-CA' -OutputPath .\cert-inventory.json
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Live')]
    [string[]] $IssuingCa,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [string] $RootCaName = 'OFFLINE-ROOT-CA',

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [string] $OutputPath = '.\cert-inventory.json',

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [int] $ExpiryWindowDays = 30,

    [Parameter(ParameterSetName = 'Live')]
    [switch] $IncludeExpired,

    [Parameter(ParameterSetName = 'Live')]
    [switch] $SkipDns,

    [Parameter(Mandatory = $true, ParameterSetName = 'Demo')]
    [switch] $Demo
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSCmdlet.ParameterSetName -eq 'Demo') {
    $SkipDns = $true
    $IncludeExpired = $false
} else {
    if (-not $PSBoundParameters.ContainsKey('SkipDns')) { $SkipDns = $false }
    if (-not $PSBoundParameters.ContainsKey('IncludeExpired')) { $IncludeExpired = $false }
}

$CVR_SEEK_GE = 8
$CV_OUT_BASE64 = 1
$CV_OUT_BINARY = 2

function ConvertTo-NormalizedSerial {
    param([string] $Serial)
    if (-not $Serial) { return '0' }
    $hex = ([regex]::Replace($Serial, '[^0-9a-fA-F]', '')).ToLower().TrimStart('0')
    if (-not $hex) { return '0' }
    return $hex
}

function ConvertTo-IsoTime {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [double] -or $Value -is [int] -or $Value -is [decimal]) {
        try { return ([datetime]::FromOADate([double]$Value)).ToUniversalTime().ToString('o') } catch { return $null }
    }
    try { return ([datetimeoffset]::Parse([string]$Value)).UtcDateTime.ToString('o') } catch { return $null }
}

function Test-SystemName {
    param([string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '\s' -or $Name.Contains('@')) { return $false }
    if ($Name -match '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    return $Name.Contains('.')
}

function ConvertTo-ByteArray {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [byte[]]) { return ,$Value }
    if ($Value -is [System.Array] -and $Value.Length -gt 0 -and $Value[0] -is [byte]) {
        $copy = New-Object byte[] $Value.Length
        [Array]::Copy($Value, $copy, $Value.Length)
        return ,$copy
    }
    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ($text -match 'BEGIN CERTIFICATE') {
            $text = [regex]::Replace($text, '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', '')
        }
        $text = $text -replace '\s', ''
        try { return ,[Convert]::FromBase64String($text) } catch { return $null }
    }
    return $null
}

function Read-DerLength {
    param([byte[]] $Bytes, [ref] $Offset)
    if ($Offset.Value -ge $Bytes.Length) { return -1 }
    $first = [int]$Bytes[$Offset.Value]
    $Offset.Value++
    if (($first -band 0x80) -eq 0) { return $first }
    $count = $first -band 0x7F
    if ($count -eq 0 -or $count -gt 4) { return -1 }
    $length = 0
    for ($i = 0; $i -lt $count; $i++) {
        if ($Offset.Value -ge $Bytes.Length) { return -1 }
        $length = ($length -shl 8) -bor [int]$Bytes[$Offset.Value]
        $Offset.Value++
    }
    return $length
}

function Read-GeneralNames {
    param([byte[]] $Bytes)
    $names = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Bytes -or $Bytes.Length -lt 2) { return @() }
    $offset = 0
    if ($Bytes[0] -eq 0x04) {
        $offset = 1
        $outer = Read-DerLength -Bytes $Bytes -Offset ([ref]$offset)
        if ($outer -lt 0) { return @() }
    }
    if ($offset -ge $Bytes.Length -or $Bytes[$offset] -ne 0x30) { return @() }
    $offset++
    $seqLen = Read-DerLength -Bytes $Bytes -Offset ([ref]$offset)
    if ($seqLen -lt 0) { return @() }
    $end = [Math]::Min($Bytes.Length, $offset + $seqLen)
    while ($offset -lt $end) {
        $tag = [int]$Bytes[$offset]
        $offset++
        $len = Read-DerLength -Bytes $Bytes -Offset ([ref]$offset)
        if ($len -lt 0 -or ($offset + $len) -gt $Bytes.Length) { break }
        $payload = New-Object byte[] $len
        [Array]::Copy($Bytes, $offset, $payload, 0, $len)
        $offset += $len
        $choice = $tag -band 0x1F
        if ($choice -eq 2 -or $choice -eq 1 -or $choice -eq 6) {
            $text = [Text.Encoding]::ASCII.GetString($payload)
            $type = 'dns'
            if ($choice -eq 1) { $type = 'email' }
            if ($choice -eq 6) { $type = 'uri' }
            $names.Add([ordered]@{ type = $type; value = $text })
        } elseif ($choice -eq 7) {
            $ip = $null
            if ($payload.Length -eq 4) {
                $ip = ($payload | ForEach-Object { $_.ToString() }) -join '.'
            } elseif ($payload.Length -eq 16) {
                $parts = @()
                for ($i = 0; $i -lt 16; $i += 2) {
                    $parts += ('{0:x2}{1:x2}' -f $payload[$i], $payload[$i + 1])
                }
                $ip = $parts -join ':'
            }
            if ($ip) { $names.Add([ordered]@{ type = 'ip'; value = $ip }) }
        }
    }
    return @($names)
}

function Get-SanFromCertificate {
    param($Certificate)
    $ext = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })
    if ($ext.Count -eq 0) { return @() }
    return @(Read-GeneralNames -Bytes $ext[0].RawData)
}

function Get-TemplateFromCertificate {
    param($Certificate)
    $v1 = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.20.2' })
    if ($v1.Count -gt 0) {
        $fmt = $v1[0].Format($false)
        if ($fmt) { return (($fmt -split '=', 2)[-1]).Trim() }
    }
    $v2 = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' })
    if ($v2.Count -gt 0) {
        $fmt = $v2[0].Format($false)
        if ($fmt -match '\(([^)]+)\)') { return $Matches[1] }
        if ($fmt) { return $fmt }
    }
    return ''
}

function Get-CertificateSerial {
    param($Certificate)
    $bytes = $Certificate.GetSerialNumber()
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return '0' }
    [Array]::Reverse($bytes)
    $hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    return (ConvertTo-NormalizedSerial $hex)
}

function Split-CaConfig {
    param([string] $Config)
    $clean = $Config.Trim().TrimStart('\')
    $parts = $clean -split '\\', 2
    if ($parts.Count -lt 2 -or -not (Test-CaToken -Value $parts[0] -AllowSpace:$false) -or -not (Test-CaToken -Value $parts[1] -AllowSpace:$true)) {
        throw "Issuing CA config must be 'hostname\CA Name'. Got '$Config'."
    }
    return [ordered]@{
        host   = $parts[0]
        name   = $parts[1]
        config = ('{0}\{1}' -f $parts[0], $parts[1])
    }
}

function Test-CaToken {
    param([string] $Value, [bool] $AllowSpace)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 200 -or $Value.StartsWith('-')) { return $false }
    if ($Value -match "[\r\n\x00`"'\x26|;``$<>]") { return $false }
    if (-not $AllowSpace -and $Value -match '\s') { return $false }
    return $true
}

function Get-ColumnRaw {
    param($Column)
    $name = ''
    try { $name = [string]$Column.GetName() } catch { $name = '' }
    if ($name -eq 'RawCertificate') {
        try {
            $binary = ConvertTo-ByteArray $Column.GetValue($CV_OUT_BINARY)
            if ($binary) { return $binary }
        } catch { }
        try { return (ConvertTo-ByteArray $Column.GetValue($CV_OUT_BASE64)) } catch { return $null }
    }
    try { return $Column.GetValue(0) } catch { return $null }
}

function ConvertTo-Disposition {
    param($Value)
    $number = 0
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [decimal]) { $number = [int]$Value }
    else {
        $text = [string]$Value
        if ($text -match '(\d+)') { $number = [int]$Matches[1] }
    }
    if ($number -eq 20 -or $number -eq 3) { return 'issued' }
    if ($number -eq 21 -or $number -eq 6) { return 'revoked' }
    return $null
}

function New-InventoryRecord {
    param(
        $Issuer,
        [int] $RequestId,
        [string] $Serial,
        [string] $CommonName,
        [string] $Subject,
        [string] $Template,
        [string] $Requester,
        [string] $NotBefore,
        [string] $NotAfter,
        [string] $Disposition,
        [string] $RevokedWhen,
        $Sans
    )
    $resolved = New-Object System.Collections.Generic.List[object]
    $ipSans = @($Sans | Where-Object { $_.type -eq 'ip' } | ForEach-Object { [string]$_.value })
    $names = New-Object System.Collections.Generic.List[object]
    if (Test-SystemName $CommonName) { $names.Add([ordered]@{ name = $CommonName; from = 'cn' }) }
    foreach ($san in @($Sans)) {
        if ($san.type -eq 'dns' -and (Test-SystemName $san.value) -and $san.value.ToLower() -ne $CommonName.ToLower()) {
            $names.Add([ordered]@{ name = [string]$san.value; from = 'san' })
        }
    }
    foreach ($entry in $names) {
        $ips = @()
        if (-not $SkipDns) {
            $ips = @(Resolve-InventoryIps -Name $entry.name)
        }
        if ($ips.Count -eq 0) { $ips = @($ipSans) }
        $resolved.Add([ordered]@{ name = $entry.name; ips = @($ips); from = $entry.from })
    }
    return [ordered]@{
        id            = ('{0}-{1}-{2}' -f $Issuer.name, $RequestId, $Serial)
        requestId     = $RequestId
        serial        = $Serial
        issuerConfig  = $Issuer.config
        issuerName    = $Issuer.name
        issuerHost    = $Issuer.host
        cn            = $CommonName
        subject       = $(if ($Subject) { $Subject } else { "CN=$CommonName" })
        sans          = @($Sans)
        template      = $(if ($Template) { $Template } else { 'Unknown' })
        requester     = $Requester
        notBefore     = $NotBefore
        notAfter      = $NotAfter
        disposition   = $Disposition
        revokedWhen   = $(if ($RevokedWhen) { $RevokedWhen } else { $null })
        resolved      = @($resolved)
    }
}

$script:DnsCache = @{}
function Resolve-InventoryIps {
    param([string] $Name)
    if ($script:DnsCache.ContainsKey($Name)) { return @($script:DnsCache[$Name]) }
    $ips = @()
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($Name)
        if ($task.Wait(2000) -and $task.Status -eq [System.Threading.Tasks.TaskStatus]::RanToCompletion) {
            $ips = @($task.Result |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.IPAddressToString } |
                Where-Object { Test-UnicastIpv4 -Name $_ } |
                Select-Object -Unique)
        }
    } catch {
        $ips = @()
    }
    $script:DnsCache[$Name] = $ips
    return @($ips)
}

function Get-RowsFromView {
    param($Issuer, [datetime] $NotAfterFrom)
    $view = New-Object -ComObject CertificateAuthority.View
    $opened = $false
    foreach ($candidate in @($Issuer.config, ('\\{0}' -f $Issuer.config))) {
        try {
            $view.OpenConnection($candidate)
            $opened = $true
            break
        } catch { }
    }
    if (-not $opened) { throw "CertificateAuthority.View could not open '$($Issuer.config)'." }

    $wanted = @(
        'RequestID',
        'SerialNumber',
        'Request.RequesterName',
        'Request.CommonName',
        'Request.Disposition',
        'NotBefore',
        'NotAfter',
        'CertificateTemplate',
        'RevokedWhen',
        'RawCertificate'
    )
    $indexes = @()
    foreach ($name in $wanted) {
        try {
            $idx = $view.GetColumnIndex(0, $name)
            if ($idx -ge 0) { $indexes += [pscustomobject]@{ Name = $name; Index = [int]$idx } }
        } catch { }
    }
    if ($indexes.Count -eq 0) { throw "No readable columns on '$($Issuer.config)'." }
    $view.SetResultColumnCount($indexes.Count) | Out-Null
    foreach ($col in $indexes) { $view.SetResultColumn($col.Index) | Out-Null }

    if (-not $IncludeExpired) {
        try {
            $notAfterIndex = $view.GetColumnIndex(0, 'NotAfter')
            if ($notAfterIndex -ge 0) {
                $view.SetRestriction($notAfterIndex, $CVR_SEEK_GE, 0, $NotAfterFrom.ToLocalTime()) | Out-Null
            }
        } catch {
            Write-Warning "Could not restrict NotAfter on $($Issuer.config). Filtering in memory."
        }
    }

    $rowset = $view.OpenView()
    $records = New-Object System.Collections.Generic.List[object]
    $guard = 0
    while ($guard -lt 100000) {
        $guard++
        $rowIndex = $rowset.Next()
        if ($null -eq $rowIndex -or [int]$rowIndex -eq -1) { break }
        $bag = @{}
        $column = $rowset.EnumCertViewColumn()
        while ($true) {
            $colIndex = $column.Next()
            if ($null -eq $colIndex -or [int]$colIndex -eq -1) { break }
            $colName = ''
            try { $colName = [string]$column.GetName() } catch { continue }
            $bag[$colName] = Get-ColumnRaw -Column $column
        }
        $record = ConvertFrom-CaBag -Issuer $Issuer -Bag $bag
        if ($null -ne $record) { $records.Add($record) }
    }
    return @($records)
}

function ConvertFrom-CaBag {
    param($Issuer, $Bag)
    $disposition = ConvertTo-Disposition $Bag['Request.Disposition']
    if (-not $disposition) { $disposition = ConvertTo-Disposition $Bag['Disposition'] }
    if ($disposition -ne 'issued' -and $disposition -ne 'revoked') { return $null }

    $requestId = 0
    if ($Bag.ContainsKey('RequestID') -and $Bag['RequestID']) { $requestId = [int]$Bag['RequestID'] }
    $requester = [string]$Bag['Request.RequesterName']
    $requestCn = [string]$Bag['Request.CommonName']
    $template = [string]$Bag['CertificateTemplate']
    $notBefore = ConvertTo-IsoTime $Bag['NotBefore']
    $notAfter = ConvertTo-IsoTime $Bag['NotAfter']
    $revokedWhen = ConvertTo-IsoTime $Bag['RevokedWhen']
    $serial = ConvertTo-NormalizedSerial ([string]$Bag['SerialNumber'])
    $subject = ''
    $sans = @()
    $cn = $requestCn

    $raw = ConvertTo-ByteArray $Bag['RawCertificate']
    if ($raw) {
        $cert = $null
        try {
            $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($raw, [NullString]::Value, $flags)
            } catch {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$raw)
            }
            $cn = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            if (-not $cn) { $cn = $requestCn }
            $subject = $cert.Subject
            $serial = Get-CertificateSerial -Certificate $cert
            $sans = @(Get-SanFromCertificate -Certificate $cert)
            $fromCert = Get-TemplateFromCertificate -Certificate $cert
            if ($fromCert) { $template = $fromCert }
            $notBefore = $cert.NotBefore.ToUniversalTime().ToString('o')
            $notAfter = $cert.NotAfter.ToUniversalTime().ToString('o')
        } catch {
            Write-Warning "Request $requestId on $($Issuer.config) could not be parsed as a certificate."
        } finally {
            if ($cert) { $cert.Dispose() }
        }
    }
    if (-not $cn -or -not $notBefore -or -not $notAfter) { return $null }
    if (-not $IncludeExpired) {
        $expiry = [datetimeoffset]::Parse($notAfter)
        if ($expiry.UtcDateTime -le [datetime]::UtcNow) { return $null }
    }
    return New-InventoryRecord -Issuer $Issuer -RequestId $requestId -Serial $serial -CommonName $cn `
        -Subject $subject -Template $template -Requester $requester -NotBefore $notBefore -NotAfter $notAfter `
        -Disposition $disposition -RevokedWhen $revokedWhen -Sans $sans
}

function Get-HexDumpBytes {
    param([string] $Block)
    $list = New-Object System.Collections.Generic.List[byte]
    foreach ($line in ($Block -split '\r?\n')) {
        if ($line -match '^\s+[0-9A-Fa-f]{4}\s{2}((?:[0-9A-Fa-f]{2}\s+)+)') {
            foreach ($hex in ($Matches[1] -split '\s+' | Where-Object { $_ })) {
                $list.Add([Convert]::ToByte($hex, 16))
            }
        }
    }
    if ($list.Count -eq 0) { return $null }
    return ,$list.ToArray()
}

function Get-RowsFromCertutil {
    param($Issuer)
    $blocks = @()
    foreach ($code in @('Disposition=20', 'Disposition=21')) {
        $output = & certutil.exe -config $Issuer.config -view -restrict $code -out 'RequestID,SerialNumber,Request.RequesterName,Request.CommonName,CertificateTemplate,NotBefore,NotAfter,Request.Disposition,RevokedWhen,RawCertificate' 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0 -and $output -notmatch 'Row \d+:') {
            throw "certutil failed for $($Issuer.config): $output"
        }
        $parts = [regex]::Split($output, '(?m)^Row \d+:\s*$')
        foreach ($part in $parts) {
            if ($part -and $part -match 'Request ID:') { $blocks += $part }
        }
    }
    $records = New-Object System.Collections.Generic.List[object]
    foreach ($block in $blocks) {
        $bag = @{}
        if ($block -match '(?m)Request ID:\s*"?(\d+)') { $bag['RequestID'] = [int]$Matches[1] }
        if ($block -match '(?m)Requester Name:\s*(.+)$') { $bag['Request.RequesterName'] = $Matches[1].Trim() }
        if ($block -match '(?m)(?:Request Common Name|Common Name):\s*(.+)$') { $bag['Request.CommonName'] = $Matches[1].Trim().Trim('"') }
        if ($block -match '(?m)Certificate Template:\s*(.+)$') { $bag['CertificateTemplate'] = $Matches[1].Trim() }
        if ($block -match '(?m)Serial Number:\s*"?([0-9A-Fa-f ]+)') { $bag['SerialNumber'] = $Matches[1].Trim().Trim('"') }
        if ($block -match '(?m)Request Disposition:.*?(\d+)') { $bag['Request.Disposition'] = [int]$Matches[1] }
        $pem = [regex]::Match($block, '-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----')
        if ($pem.Success) {
            $bag['RawCertificate'] = $pem.Value
        } else {
            $bag['RawCertificate'] = Get-HexDumpBytes -Block $block
        }
        $record = ConvertFrom-CaBag -Issuer $Issuer -Bag $bag
        if ($null -ne $record) { $records.Add($record) }
    }
    return @($records)
}

function Select-InventorySan {
    param($Cert)
    $dns = @($Cert.sans | Where-Object { $_.type -eq 'dns' })
    foreach ($san in $dns) {
        if ($san.value -like '*.*' -and $san.value.ToLower() -ne $Cert.cn.ToLower()) { return [string]$san.value }
    }
    foreach ($san in $dns) {
        if ($san.value.ToLower() -eq $Cert.cn.ToLower()) { return [string]$san.value }
    }
    if ($dns.Count -gt 0) { return [string]$dns[0].value }
    $ip = @($Cert.sans | Where-Object { $_.type -eq 'ip' })
    if ($ip.Count -gt 0) { return [string]$ip[0].value }
    $all = @($Cert.sans)
    if ($all.Count -gt 0) { return [string]$all[0].value }
    return ''
}

function Test-InventoryValid {
    param($Cert, [datetime] $Now)
    if ($Cert.disposition -ne 'issued') { return $false }
    $start = [datetimeoffset]::Parse([string]$Cert.notBefore).UtcDateTime
    $end = [datetimeoffset]::Parse([string]$Cert.notAfter).UtcDateTime
    return ($start -le $Now -and $end -gt $Now)
}

function Get-SerialFindings {
    param($Certificates, [datetime] $Now)
    # Look up by CN, or by one SAN when the CN is not on a valid certificate.
    # The serial that lookup returns is the serial used for validation.
    $valid = @($Certificates | Where-Object { Test-InventoryValid -Cert $_ -Now $Now })
    $seen = @{}
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($cert in $valid) {
        $san = Select-InventorySan -Cert $cert
        $key = ('{0}|{1}' -f $cert.cn.ToLower(), $san.ToLower())
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $cnCerts = @($valid | Where-Object { $_.cn.ToLower() -eq $cert.cn.ToLower() })
        $sanCerts = @($valid | Where-Object { @($_.sans | Where-Object { $_.value.ToLower() -eq $san.ToLower() }).Count -gt 0 })
        $cnSerials = @($cnCerts | ForEach-Object { $_.serial } | Select-Object -Unique)
        $sanSerials = @($sanCerts | ForEach-Object { $_.serial } | Select-Object -Unique)
        $shared = @($cnSerials | Where-Object { $sanSerials -contains $_ })
        $kind = 'match'
        if (-not $cert.cn -or $cnCerts.Count -eq 0) { $kind = 'cn-missing' }
        elseif (-not $san -or $sanCerts.Count -eq 0) { $kind = 'san-missing' }
        elseif ($shared.Count -eq 0) { $kind = 'mismatch' }
        elseif ($cnSerials.Count -eq $sanSerials.Count -and $shared.Count -eq $cnSerials.Count -and $cnSerials.Count -eq 1) { $kind = 'match' }
        elseif ($cnSerials.Count -eq $sanSerials.Count -and $shared.Count -eq $cnSerials.Count) { $kind = 'duplicate' }
        else { $kind = 'divergent' }
        if ($kind -eq 'match') { continue }
        $findings.Add([ordered]@{
            cn         = $cert.cn
            san        = $san
            kind       = $kind
            cnSerials  = @($cnSerials)
            sanSerials = @($sanSerials)
        })
    }
    return @($findings)
}

function Get-ClientValidations {
    param($Certificates, [datetime] $Now)
    # Verify each client certificate by CN, or by exactly one SAN, then take its serial.
    $valid = @($Certificates | Where-Object { Test-InventoryValid -Cert $_ -Now $Now })
    $seen = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($cert in $valid) {
        $name = [string]$cert.cn
        $via = 'cn'
        $key = ('cn|' + $name.ToLower())
        $matched = @()
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $matched = @($valid | Where-Object { $_.cn.ToLower() -eq $name.ToLower() })
        }
        if ($matched.Count -eq 0) {
            $via = 'san'
            $name = Select-InventorySan -Cert $cert
            $key = ('san|' + $name.ToLower())
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $matched = @($valid | Where-Object {
                @($_.sans | Where-Object { $_.value.ToLower() -eq $name.ToLower() }).Count -gt 0
            })
        }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $serials = @($matched | ForEach-Object { $_.serial } | Select-Object -Unique)
        $rows.Add([ordered]@{
            name     = $name
            via      = $via
            serials  = @($serials)
            verified = ($serials.Count -eq 1)
        })
    }
    return @($rows)
}

$script:ProbeCache = @{}
function Get-CertClientNames {
    param($Cert)
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $cn = [string]$Cert.cn
    if (-not [string]::IsNullOrWhiteSpace($cn)) {
        $rows.Add([ordered]@{ client = $cn; via = 'cn' })
        $seen[$cn.ToLower()] = $true
    }
    foreach ($san in @($Cert.sans)) {
        if ($san.type -ne 'dns' -and $san.type -ne 'ip') { continue }
        $value = [string]$san.value
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($seen.ContainsKey($value.ToLower())) { continue }
        $seen[$value.ToLower()] = $true
        $rows.Add([ordered]@{ client = $value; via = 'san' })
    }
    return @($rows)
}

function Test-UnicastIpv4 {
    param([string] $Name)
    $parts = $Name.Split('.')
    if ($parts.Count -ne 4) { return $false }
    $octets = New-Object System.Collections.Generic.List[int]
    foreach ($part in $parts) {
        $n = 0
        if (-not [int]::TryParse($part, [ref]$n)) { return $false }
        if ($part.Length -gt 1 -and $part.StartsWith('0')) { return $false }
        if ($n -lt 0 -or $n -gt 255) { return $false }
        $octets.Add($n)
    }
    if ($octets[0] -eq 0 -or $octets[0] -ge 224) { return $false }
    return $true
}

function Test-DnsClientName {
    param([string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 253) { return $false }
    if ($Name.StartsWith('.') -or $Name.EndsWith('.')) { return $false }
    foreach ($label in $Name.Split('.')) {
        if ($label.Length -lt 1 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { return $false }
    }
    return $true
}

function Get-ProbeKind {
    param([string] $Name)
    if ($Name -match '^\d{1,3}(\.\d{1,3}){3}$') {
        if (Test-UnicastIpv4 -Name $Name) { return 'ip' }
        return 'rejected-ip'
    }
    if (Test-DnsClientName -Name $Name) { return 'host' }
    return 'rejected-host'
}

function Get-ClientProbe {
    param([string] $Name)
    if ($script:ProbeCache.ContainsKey($Name)) { return $script:ProbeCache[$Name] }
    $kind = Get-ProbeKind -Name $Name
    if ($kind -eq 'rejected-host') {
        $result = [ordered]@{ status = 'not-in-dns'; address = $null }
        $script:ProbeCache[$Name] = $result
        return $result
    }
    if ($kind -eq 'rejected-ip') {
        $result = [ordered]@{ status = 'not-on-network'; address = $null }
        $script:ProbeCache[$Name] = $result
        return $result
    }
    $isIp = $kind -eq 'ip'
    $ips = @()
    if ($isIp) { $ips = @($Name) }
    else { $ips = @(Resolve-InventoryIps -Name $Name) }
    $result = [ordered]@{ status = 'not-in-dns'; address = $null }
    if ($ips.Count -eq 0) {
        $result.status = $(if ($isIp) { 'not-on-network' } else { 'not-in-dns' })
    } else {
        $target = [string]$ips[0]
        $result.address = $target
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($target, 1000)
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $result.status = 'active'
            } else {
                $down = @(
                    [System.Net.NetworkInformation.IPStatus]::DestinationUnreachable,
                    [System.Net.NetworkInformation.IPStatus]::DestinationHostUnreachable,
                    [System.Net.NetworkInformation.IPStatus]::DestinationNetworkUnreachable,
                    [System.Net.NetworkInformation.IPStatus]::DestinationProhibited,
                    [System.Net.NetworkInformation.IPStatus]::DestinationProtocolUnreachable,
                    [System.Net.NetworkInformation.IPStatus]::DestinationPortUnreachable,
                    [System.Net.NetworkInformation.IPStatus]::HardwareError,
                    [System.Net.NetworkInformation.IPStatus]::BadDestination
                )
                if ($down -contains $reply.Status -or $isIp) { $result.status = 'not-on-network' }
                else { $result.status = 'inactive' }
            }
        } catch {
            $result.status = $(if ($isIp) { 'not-on-network' } else { 'inactive' })
        }
    }
    $script:ProbeCache[$Name] = $result
    return $result
}

function Get-ClientChecks {
    param($Certificates, [datetime] $Now, [bool] $DemoMode)
    # CA inventory is the base. Each CN and SAN is a client of that certificate serial.
    # Several clients on one certificate is expected, not a conflict.
    $valid = @($Certificates | Where-Object { Test-InventoryValid -Cert $_ -Now $Now })
    $checked = $Now.ToString('o')
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($cert in $valid) {
        $fallback = @($cert.sans | Where-Object { $_.type -eq 'ip' -and (Test-UnicastIpv4 -Name ([string]$_.value)) } | Select-Object -First 1)
        $fallbackIp = if ($fallback.Count) { [string]$fallback[0].value } else { $null }
        foreach ($item in @(Get-CertClientNames -Cert $cert)) {
            $status = 'active'
            $address = $fallbackIp
            if (-not $DemoMode) {
                $probe = Get-ClientProbe -Name $item.client
                $status = [string]$probe.status
                $address = $probe.address
            } elseif ($item.client -notmatch '\.' ) {
                $status = 'not-in-dns'
                $address = $null
            }
            $rows.Add([ordered]@{
                certId    = $cert.id
                serial    = $cert.serial
                client    = $item.client
                via       = $item.via
                status    = $status
                checkedAt = $checked
                address   = $address
            })
        }
    }
    return @($rows)
}

function Get-DemoSnapshot {
    $now = [datetime]::UtcNow
    function D([int] $Days) { return $now.AddDays($Days).ToString('o') }
    $ca1 = [ordered]@{ config = 'pki-ica01.corp.local\CORP-ISSUING-CA-01'; host = 'pki-ica01.corp.local'; name = 'CORP-ISSUING-CA-01' }
    $ca2 = [ordered]@{ config = 'pki-ica02.corp.local\CORP-ISSUING-CA-02'; host = 'pki-ica02.corp.local'; name = 'CORP-ISSUING-CA-02' }
    $certs = @(
        (New-InventoryRecord -Issuer $ca1 -RequestId 14021 -Serial '4f12a1000001' -CommonName 'es-data-01.obs.corp.local' -Subject 'CN=es-data-01.obs.corp.local' -Template 'Machine' -Requester 'CORP\ES-DATA-01$' -NotBefore (D -400) -NotAfter (D 200) -Disposition 'issued' -RevokedWhen '' -Sans @(
            [ordered]@{ type = 'dns'; value = 'es-data-01.obs.corp.local' },
            [ordered]@{ type = 'ip'; value = '10.16.8.21' }
        )),
        (New-InventoryRecord -Issuer $ca1 -RequestId 10110 -Serial '11aa01000001' -CommonName 'web-iis-01.corp.local' -Subject 'CN=web-iis-01.corp.local' -Template 'WebServer' -Requester 'CORP\WEB-IIS-01$' -NotBefore (D -320) -NotAfter (D 32) -Disposition 'issued' -RevokedWhen '' -Sans @(
            [ordered]@{ type = 'dns'; value = 'web-iis-01.corp.local' },
            [ordered]@{ type = 'dns'; value = 'www.corp.local' },
            [ordered]@{ type = 'ip'; value = '10.16.2.31' }
        )),
        (New-InventoryRecord -Issuer $ca1 -RequestId 16040 -Serial '11aa01000002' -CommonName 'web-iis-01.corp.local' -Subject 'CN=web-iis-01.corp.local' -Template 'WebServer' -Requester 'CORP\WEB-IIS-01$' -NotBefore (D -70) -NotAfter (D 290) -Disposition 'issued' -RevokedWhen '' -Sans @(
            [ordered]@{ type = 'dns'; value = 'web-iis-01.corp.local' },
            [ordered]@{ type = 'dns'; value = 'www.corp.local' },
            [ordered]@{ type = 'ip'; value = '10.16.2.31' }
        )),
        (New-InventoryRecord -Issuer $ca2 -RequestId 9602 -Serial 'd10100000001' -CommonName 'ocp-api.ocp.corp.local' -Subject 'CN=ocp-api.ocp.corp.local' -Template 'WebServer' -Requester 'CORP\OCP-API$' -NotBefore (D -200) -NotAfter (D 3) -Disposition 'issued' -RevokedWhen '' -Sans @(
            [ordered]@{ type = 'dns'; value = 'ocp-api.ocp.corp.local' },
            [ordered]@{ type = 'ip'; value = '10.16.12.10' }
        ))
    )
    return [ordered]@{
        schema           = 'ca-ledger/1'
        collectedAt      = $now.ToString('o')
        collector        = 'Invoke-CertInventory.ps1 -Demo'
        rootName         = $RootCaName
        expiryWindowDays = $ExpiryWindowDays
        issuing          = @($ca1, $ca2)
        certificates     = @($certs)
        errors           = @()
    }
}

function Write-InventoryJson {
    param($Snapshot, [string] $Path)
    $json = $Snapshot | ConvertTo-Json -Depth 8
    if ($Path -match "[\r\n\x00]") { throw "Output path is not valid." }
    $full = [System.IO.Path]::GetFullPath($Path)
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($full, $json, $utf8)
    return $full
}

if ($PSCmdlet.ParameterSetName -eq 'Demo') {
    $snapshot = Get-DemoSnapshot
} else {
    if ($IssuingCa.Count -lt 2) {
        Write-Warning "Expected 2 or more issuing CAs for a two-tier PKI. Continuing with $($IssuingCa.Count)."
    }
    $issuers = @()
    foreach ($config in $IssuingCa) { $issuers += Split-CaConfig -Config $config }
    $certs = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    foreach ($issuer in $issuers) {
        Write-Host ("Collecting {0}" -f $issuer.config)
        try {
            $rows = $null
            $comError = $null
            try {
                $rows = @(Get-RowsFromView -Issuer $issuer -NotAfterFrom ([datetime]::UtcNow))
            } catch {
                $comError = $_.Exception.Message
                Write-Warning "COM view failed ($comError). Falling back to certutil."
                $rows = @(Get-RowsFromCertutil -Issuer $issuer)
            }
            foreach ($row in @($rows)) { if ($null -ne $row) { $certs.Add($row) } }
            Write-Host ("  {0} rows" -f @($rows).Count)
        } catch {
            $message = $_.Exception.Message
            Write-Warning $message
            $errors.Add([ordered]@{ config = $issuer.config; message = $message })
        }
    }
    if ($certs.Count -eq 0) {
        Write-Host 'No issued certificates were collected.'
        foreach ($err in $errors) { Write-Host ("  {0}: {1}" -f $err.config, $err.message) }
        exit 1
    }
    $snapshot = [ordered]@{
        schema           = 'ca-ledger/1'
        collectedAt      = [datetime]::UtcNow.ToString('o')
        collector        = 'Invoke-CertInventory.ps1'
        rootName         = $RootCaName
        expiryWindowDays = $ExpiryWindowDays
        issuing          = @($issuers)
        certificates     = @($certs)
        errors           = @($errors)
    }
}

$nowUtc = [datetime]::UtcNow
$demoMode = $PSCmdlet.ParameterSetName -eq 'Demo'
$checks = @(Get-ClientChecks -Certificates $snapshot.certificates -Now $nowUtc -DemoMode $demoMode)
$snapshot['clientChecks'] = @($checks)
$snapshot['statusWindowMinutes'] = 5
$validCount = @($snapshot.certificates | Where-Object { Test-InventoryValid -Cert $_ -Now $nowUtc }).Count
$expiring = @($snapshot.certificates | Where-Object {
    (Test-InventoryValid -Cert $_ -Now $nowUtc) -and
    ([datetimeoffset]::Parse([string]$_.notAfter).UtcDateTime -le $nowUtc.AddDays($ExpiryWindowDays))
})

$path = Write-InventoryJson -Snapshot $snapshot -Path $OutputPath
Write-Host ''
Write-Host 'CA Ledger collection'
Write-Host ("  Root     {0}" -f $snapshot.rootName)
foreach ($ca in @($snapshot.issuing)) {
    $count = @($snapshot.certificates | Where-Object { $_.issuerName -eq $ca.name -and (Test-InventoryValid -Cert $_ -Now $nowUtc) }).Count
    Write-Host ("  Issuing  {0}  ({1} valid)" -f $ca.config, $count)
}
Write-Host ("  Issued records          {0}" -f @($snapshot.certificates).Count)
Write-Host ("  Valid now               {0}" -f $validCount)
Write-Host ("  Expiring within {0} days {1}" -f $ExpiryWindowDays, $expiring.Count)
foreach ($row in ($expiring | Sort-Object { [datetimeoffset]::Parse([string]$_.notAfter) })) {
    $ips = @($row.resolved | ForEach-Object { $_.ips } | Where-Object { $_ } | Select-Object -Unique)
    $ipText = if ($ips.Count) { $ips -join ', ' } else { 'no IP' }
    $days = [Math]::Ceiling(([datetimeoffset]::Parse([string]$row.notAfter).UtcDateTime - $nowUtc).TotalDays)
    Write-Host ("    {0,3}d  {1}  {2}  {3}" -f $days, $row.cn, $ipText, $row.issuerName)
}
Write-Host ("  Client status, last {0} min" -f 5)
$byStatus = @{ active = 0; inactive = 0; 'not-in-dns' = 0; 'not-on-network' = 0 }
foreach ($check in @($checks)) {
    if ($byStatus.ContainsKey([string]$check.status)) { $byStatus[[string]$check.status]++ }
}
Write-Host ("    active           {0}" -f $byStatus.active)
Write-Host ("    inactive         {0}" -f $byStatus.inactive)
Write-Host ("    not in DNS       {0}" -f $byStatus['not-in-dns'])
Write-Host ("    not on network   {0}" -f $byStatus['not-on-network'])
foreach ($check in @($checks | Where-Object { $_.status -ne 'active' })) {
    Write-Host ("    {0,-16} {1,-3} {2}  serial {3}" -f $check.status, $check.via, $check.client, $check.serial)
}
Write-Host ("Wrote {0}" -f $path)
if (@($snapshot.errors).Count -gt 0) { exit 2 }
exit 0
