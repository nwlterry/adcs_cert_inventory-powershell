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

  Output is cert-inventory.json (schema ca-ledger/1). With -Serve, this process hosts
  the on-prem dashboard beside that file. The page only reads the local inventory.
  It does not resolve names and it does not use the internet.

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

.PARAMETER Serve
  After collection, host the on-prem dashboard until Ctrl+C.

.PARAMETER Listen
  HTTP prefix for -Serve. Default http://127.0.0.1:8787/
  Bind loopback, or one address on the isolated network.
  A container uses http://+:8787/ so the published port is reachable.

.PARAMETER HostOnly
  Serve the JSON already at -OutputPath. Does not contact a CA or the network.

.PARAMETER Demo
  Write a small sample file and do not contact a CA.

.EXAMPLE
  .\Invoke-CertInventory.ps1 -IssuingCa @(
    'pki-ica01.corp.local\CORP-ISSUING-CA-01',
    'pki-ica02.corp.local\CORP-ISSUING-CA-02'
  ) -RootCaName 'CORP-OFFLINE-ROOT-CA' -Serve

.EXAMPLE
  .\Invoke-CertInventory.ps1 -HostOnly -OutputPath .\cert-inventory.json
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
    [Parameter(ParameterSetName = 'Host')]
    [string] $OutputPath = '.\cert-inventory.json',

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [int] $ExpiryWindowDays = 30,

    [Parameter(ParameterSetName = 'Live')]
    [switch] $IncludeExpired,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [switch] $SkipDns,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [switch] $Serve,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'Demo')]
    [Parameter(ParameterSetName = 'Host')]
    [string] $Listen = 'http://127.0.0.1:8787/',

    [Parameter(Mandatory = $true, ParameterSetName = 'Host')]
    [switch] $HostOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'Demo')]
    [switch] $Demo
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:CaReaderReady = $false
$script:CaReaderWarned = $false
$script:ViewIncomplete = $false
$script:DnsCache = @{}
$script:CertUnreadable = 0
$script:CertReject = ''
$script:RowReject = ''
$script:KeptRows = 0
$script:CollectedRows = @()
$script:ProbeCache = @{}
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
    $hex = [regex]::Replace([string]$Serial, '[^0-9a-fA-F]', '')
    $hex = $hex.ToLowerInvariant()
    $hex = $hex -replace '^0+', ''
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
    $text = [string]$Value
    if ($text -match '^(EMPTY|n/?a)$') { return $null }
    try { return ([datetime]::Parse($text)).ToUniversalTime().ToString('o') } catch { }
    try { return ([datetimeoffset]::Parse($text)).UtcDateTime.ToString('o') } catch { return $null }
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
    if ($Value -is [System.Array] -and $Value.Length -gt 0) {
        try {
            $copy = New-Object byte[] $Value.Length
            for ($i = 0; $i -lt $Value.Length; $i++) { $copy[$i] = [byte]$Value[$i] }
            return ,$copy
        } catch { }
    }
    if ($Value -is [string]) {
        $text = $Value.Trim()
        if ($text -match 'BEGIN CERTIFICATE') {
            $text = [regex]::Replace($text, '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', '')
        }
        $text = $text -replace '\s', ''
        if ($text -match '^[0-9A-Fa-f]+$' -and $text.Length -ge 8 -and ($text.Length % 2) -eq 0) {
            $hexBytes = New-Object byte[] ($text.Length / 2)
            for ($i = 0; $i -lt $hexBytes.Length; $i++) {
                $hexBytes[$i] = [Convert]::ToByte($text.Substring($i * 2, 2), 16)
            }
            return ,$hexBytes
        }
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
    $names = New-Object System.Collections.ArrayList
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
            [void]$names.Add([ordered]@{ type = $type; value = $text })
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
            if ($ip) { [void]$names.Add([ordered]@{ type = 'ip'; value = $ip }) }
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
    $clean = $Config.Trim().TrimStart([char]92)
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

function Release-ComObject {
    param($Object)
    if ($null -eq $Object) { return }
    try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Object) } catch { }
}

function Invoke-ViewMethod {
    param($Object, [string] $Name, [object[]] $Arguments)
    $flags = [System.Reflection.BindingFlags]::InvokeMethod
    $type = $Object.GetType()
    if (-not $PSBoundParameters.ContainsKey('Arguments') -or $null -eq $Arguments -or $Arguments.Count -eq 0) {
        try { return $type.InvokeMember($Name, $flags, $null, $Object, $null) } catch { }
        return $type.InvokeMember($Name, $flags, $null, $Object, @())
    }
    return $type.InvokeMember($Name, $flags, $null, $Object, ([object[]] $Arguments))
}

function Get-ColumnRaw {
    param($Column)
    $name = ''
    try { $name = [string](Invoke-ViewMethod -Object $Column -Name 'GetName') } catch {
        try { $name = [string]$Column.GetName() } catch { $name = '' }
    }
    $flags = if ($name -eq 'RawCertificate') { @(2, 1, 3, 0) } else { @(0) }
    foreach ($flag in $flags) {
        $value = $null
        try {
            $value = Invoke-ViewMethod -Object $Column -Name 'GetValue' -Arguments ([object[]] @([int]$flag))
        } catch {
            try { $value = $Column.GetValue([int]$flag) } catch { $value = $null }
        }
        if ($null -eq $value -or $value -eq '') { continue }
        if ($name -eq 'RawCertificate') {
            $binary = ConvertTo-ByteArray $value
            if ($binary -and $binary.Length -gt 16) { return ,$binary }
            continue
        }
        return $value
    }
    return $null
}

function ConvertTo-Disposition {
    param($Value)
    $number = 0
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [decimal]) { $number = [int]$Value }
    else {
        $text = [string]$Value
        if ($text -match 'Issued') { return 'issued' }
        if ($text -match 'Revoked') { return 'revoked' }
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
    $resolved = @()
    $ipSans = @($Sans | Where-Object { $_.type -eq 'ip' } | ForEach-Object { [string]$_.value })
    $names = @()
    if (Test-SystemName $CommonName) { $names += [ordered]@{ name = $CommonName; from = 'cn' } }
    foreach ($san in @($Sans)) {
        if ($san.type -eq 'dns' -and (Test-SystemName $san.value) -and $san.value.ToLowerInvariant() -ne $CommonName.ToLowerInvariant()) {
            $names += [ordered]@{ name = [string]$san.value; from = 'san' }
        }
    }
    foreach ($entry in @($names)) {
        $ips = @()
        if (-not $SkipDns) {
            $ips = @(Resolve-InventoryIps -Name $entry.name)
        }
        if ($ips.Count -eq 0) { $ips = @($ipSans) }
        $resolved += [ordered]@{ name = $entry.name; ips = @($ips); from = $entry.from }
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

$script:CaReaderSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

public static class CaLedgerReader034 {
    public static string Collect(string config, bool includeExpired) {
        if (string.IsNullOrEmpty(config)) throw new InvalidOperationException("CA config is empty.");
        string issued = Query(config, "20", false);
        string revoked = Query(config, "21", true);
        int unreadable = 0;
        var lines = new List<string>();
        unreadable += AppendRows(lines, issued, includeExpired);
        unreadable += AppendRows(lines, revoked, includeExpired);
        if (lines.Count == 0) {
            string sample = Sample(issued);
            if (sample.Length == 0) sample = Sample(revoked);
            throw new InvalidOperationException("certutil returned no issued certificates for " + config + ". " + sample);
        }
        var text = new StringBuilder();
        if (unreadable > 0) {
            text.Append("WARN ");
            text.Append(unreadable.ToString(CultureInfo.InvariantCulture));
            text.Append(" certificate bodies could not be decoded. Database name and dates were kept.");
            text.Append('\n');
        }
        foreach (string line in lines) text.Append(line).Append('\n');
        return text.ToString();
    }

    public static string Resolve(string name) {
        if (string.IsNullOrEmpty(name)) return "";
        try {
            var ips = System.Net.Dns.GetHostAddresses(name);
            var list = new List<string>();
            foreach (var ip in ips) {
                if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                string text = ip.ToString();
                if (IsUnicast(text) && !list.Contains(text)) list.Add(text);
            }
            return string.Join(",", list.ToArray());
        } catch {
            return "";
        }
    }

    static bool IsUnicast(string ip) {
        string[] parts = ip.Split('.');
        if (parts.Length != 4) return false;
        int first;
        if (!int.TryParse(parts[0], out first)) return false;
        return first > 0 && first < 224;
    }

    static string Query(string config, string disposition, bool revokedView) {
        string cols = "RequestID,SerialNumber,Request.RequesterName,Request.CommonName,CertificateTemplate,NotBefore,NotAfter,Request.Disposition,RevokedWhen,RawCertificate";
        string view = revokedView ? "Revoked" : "Log";
        string[] attempts = new string[] {
            "-config " + Quote(config) + " -restrict " + Quote("Disposition=" + disposition) + " -out " + Quote(cols),
            "-config " + Quote(config) + " -restrict " + Quote("Disposition=" + disposition) + " -out " + Quote(cols) + " -view " + view,
            "-config " + Quote(config) + " -out " + Quote(cols) + " -view " + view,
            "-config " + Quote(config) + " -view " + view + " -restrict " + Quote("Disposition=" + disposition) + " -out " + Quote(cols)
        };
        string best = "";
        int bestScore = 0;
        foreach (string attempt in attempts) {
            string output;
            try { output = RunCertutil(attempt); }
            catch { continue; }
            if (output.IndexOf("ACCESS_DENIED", StringComparison.OrdinalIgnoreCase) >= 0 ||
                output.IndexOf("0x80070005", StringComparison.OrdinalIgnoreCase) >= 0) {
                throw new InvalidOperationException("certutil was denied on " + config + ". Read permission on the CA is required.");
            }
            int score = Score(output);
            if (score > bestScore) {
                bestScore = score;
                best = output;
                if (score >= 1) break;
            }
        }
        return best ?? "";
    }

    static int Score(string text) {
        if (string.IsNullOrEmpty(text)) return 0;
        if (text.IndexOf("ERROR_INVALID_FUNCTION", StringComparison.OrdinalIgnoreCase) >= 0) return 0;
        if (text.IndexOf("INCORRECT FUNCTION", StringComparison.OrdinalIgnoreCase) >= 0) return 0;
        int rows = Regex.Matches(text, "(?m)^Row \\d+:").Count;
        int ids = Regex.Matches(text, "Request ID:").Count;
        return Math.Max(rows, ids);
    }

    static string RunCertutil(string arguments) {
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "certutil.exe";
        psi.Arguments = arguments;
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.CreateNoWindow = true;
        Process proc = new Process();
        proc.StartInfo = psi;
        try {
            proc.Start();
        } catch (Exception ex) {
            throw new InvalidOperationException("certutil.exe could not be started. " + ex.Message);
        }
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(300000)) {
            try { proc.Kill(); } catch { }
            throw new InvalidOperationException("certutil timed out.");
        }
        return (stdout ?? "") + "\n" + (stderr ?? "");
    }

    static string Quote(string value) {
        return "\"" + (value ?? "").Replace("\"", "") + "\"";
    }

    static string Sample(string text) {
        if (string.IsNullOrEmpty(text)) return "certutil produced no output.";
        string flat = Regex.Replace(text, "\\s+", " ").Trim();
        if (flat.Length > 280) flat = flat.Substring(0, 280);
        return flat;
    }

    static int AppendRows(List<string> lines, string output, bool includeExpired) {
        if (string.IsNullOrEmpty(output)) return 0;
        int unreadable = 0;
        string[] blocks = Regex.Split(output, "(?m)^Row \\d+:\\s*");
        foreach (string block in blocks) {
            if (block.IndexOf("Request ID:", StringComparison.OrdinalIgnoreCase) < 0) continue;
            string dispositionText = First(block, new string[] { "Request Disposition", "Certificate Disposition", "Disposition" });
            string disposition = DispositionOf(dispositionText);
            if (disposition.Length == 0) continue;
            string requestId = RequestIdOf(First(block, new string[] { "Request ID" }));
            string serial = CleanSerial(First(block, new string[] { "Serial Number" }));
            string cn = Unquote(First(block, new string[] { "Request Common Name", "Issued Common Name", "Common Name" }));
            string template = Unquote(First(block, new string[] { "Certificate Template" }));
            string requester = Unquote(First(block, new string[] { "Requester Name" }));
            string notBefore = Iso(First(block, new string[] { "Certificate Effective Date", "NotBefore" }));
            string notAfter = Iso(First(block, new string[] { "Certificate Expiration Date", "NotAfter" }));
            string revoked = Iso(First(block, new string[] { "Revocation Date", "Revoked When" }));
            string subject = "";
            string san = "";
            string payload = ExtractPayload(block);
            if (payload.Length > 0) {
                Dictionary<string, string> described = Describe(payload);
                if (described == null) unreadable++;
                else {
                    if (described["CommonName"].Length > 0) cn = described["CommonName"];
                    if (described["Serial"].Length > 0) serial = CleanSerial(described["Serial"]);
                    if (described["NotBefore"].Length > 0) notBefore = described["NotBefore"];
                    if (described["NotAfter"].Length > 0) notAfter = described["NotAfter"];
                    if (described["Subject"].Length > 0) subject = described["Subject"];
                    if (described["Template"].Length > 0) template = described["Template"];
                    san = described["San"];
                }
            } else {
                unreadable++;
            }
            if (cn.Length == 0 || notBefore.Length == 0 || notAfter.Length == 0) continue;
            if (!includeExpired && disposition == "issued") {
                DateTimeOffset expiry;
                if (DateTimeOffset.TryParse(notAfter, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out expiry)) {
                    if (expiry.UtcDateTime <= DateTime.UtcNow) continue;
                }
            }
            lines.Add(string.Join("\t", new string[] {
                Cell(requestId), Cell(serial), Cell(cn), Cell(subject), Cell(template),
                Cell(requester), Cell(notBefore), Cell(notAfter), Cell(disposition), Cell(revoked), Cell(san)
            }));
        }
        return unreadable;
    }

    static string First(string block, string[] labels) {
        foreach (string label in labels) {
            Match match = Regex.Match(block, "(?im)^.*" + Regex.Escape(label) + "\\s*:\\s*(.+)$");
            if (match.Success) return match.Groups[1].Value.Trim();
        }
        return "";
    }

    static string Unquote(string value) {
        if (string.IsNullOrEmpty(value)) return "";
        string text = value.Trim();
        if (text.Length >= 2 && text[0] == '"' && text[text.Length - 1] == '"') text = text.Substring(1, text.Length - 2);
        return text.Trim();
    }

    static string RequestIdOf(string text) {
        if (string.IsNullOrEmpty(text)) return "0";
        Match paren = Regex.Match(text, "\\((\\d+)\\)");
        if (paren.Success) return paren.Groups[1].Value;
        Match hex = Regex.Match(text, "0x([0-9A-Fa-f]+)");
        if (hex.Success) return Convert.ToInt32(hex.Groups[1].Value, 16).ToString(CultureInfo.InvariantCulture);
        Match number = Regex.Match(text, "(\\d+)");
        if (number.Success) return number.Groups[1].Value;
        return "0";
    }

    static string DispositionOf(string text) {
        if (string.IsNullOrEmpty(text)) return "";
        if (text.IndexOf("Revoked", StringComparison.OrdinalIgnoreCase) >= 0) return "revoked";
        if (text.IndexOf("Issued", StringComparison.OrdinalIgnoreCase) >= 0 && text.IndexOf("Pending", StringComparison.OrdinalIgnoreCase) < 0) return "issued";
        int number = -1;
        Match paren = Regex.Match(text, "\\((\\d+)\\)");
        if (paren.Success) number = int.Parse(paren.Groups[1].Value, CultureInfo.InvariantCulture);
        else {
            Match numberMatch = Regex.Match(text, "(\\d+)");
            if (numberMatch.Success) number = int.Parse(numberMatch.Groups[1].Value, CultureInfo.InvariantCulture);
        }
        if (number == 20) return "issued";
        if (number == 21) return "revoked";
        return "";
    }

    static string CleanSerial(string text) {
        if (string.IsNullOrEmpty(text)) return "0";
        var sb = new StringBuilder();
        foreach (char c in text) {
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) sb.Append(char.ToLowerInvariant(c));
        }
        string hex = sb.ToString().TrimStart('0');
        return hex.Length == 0 ? "0" : hex;
    }

    static string Iso(string text) {
        text = Unquote(text);
        if (text.Length == 0) return "";
        if (text.Equals("EMPTY", StringComparison.OrdinalIgnoreCase)) return "";
        DateTime when;
        if (DateTime.TryParse(text, CultureInfo.CurrentCulture, DateTimeStyles.AssumeLocal, out when) ||
            DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out when)) {
            if (when.Kind == DateTimeKind.Unspecified) when = DateTime.SpecifyKind(when, DateTimeKind.Local);
            return when.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
        }
        return "";
    }

    static string Cell(string value) {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }

    static string ExtractPayload(string block) {
        int begin = block.IndexOf("BEGIN CERTIFICATE", StringComparison.OrdinalIgnoreCase);
        if (begin >= 0) {
            int end = block.IndexOf("END CERTIFICATE", StringComparison.OrdinalIgnoreCase);
            if (end > begin) return block.Substring(begin, (end - begin) + "END CERTIFICATE".Length);
        }
        var hex = new StringBuilder();
        bool started = false;
        string[] lines = block.Split(new char[] { '\n' });
        foreach (string raw in lines) {
            string line = raw.Trim();
            if (line.IndexOf("Binary Certificate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("Raw Certificate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                line.IndexOf("RawCertificate", StringComparison.OrdinalIgnoreCase) >= 0) {
                started = true;
                continue;
            }
            if (!started) continue;
            if (line.Length == 0) {
                if (hex.Length > 0) break;
                continue;
            }
            string body = line;
            Match offset = Regex.Match(body, "^[0-9A-Fa-f]{4,8}\\s{2,}(.+)$");
            if (offset.Success) body = offset.Groups[1].Value.Trim();
            Match gutter = Regex.Match(body, "^(.*[0-9A-Fa-f]{2})\\s{2,}[^0-9A-Fa-f\\s].*$");
            if (gutter.Success) body = gutter.Groups[1].Value.Trim();
            int before = hex.Length;
            foreach (string token in body.Split(new char[] { ' ', '\t' })) {
                if (token.Length == 2 && IsHexPair(token)) hex.Append(token);
            }
            if (hex.Length == before) {
                if (hex.Length > 0) break;
            }
        }
        return hex.Length >= 32 ? hex.ToString() : "";
    }

    static bool IsHexPair(string token) {
        if (token == null || token.Length != 2) return false;
        return Uri.IsHexDigit(token[0]) && Uri.IsHexDigit(token[1]);
    }

    static Dictionary<string, string> Describe(string payload) {
        byte[] der = Decode(payload);
        if (der == null || der.Length < 16 || der[0] != 0x30) return null;
        try {
            X509Certificate2 cert = new X509Certificate2(der);
            var bag = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            bag["CommonName"] = cert.GetNameInfo(X509NameType.SimpleName, false) ?? "";
            bag["Subject"] = cert.Subject ?? "";
            bag["Serial"] = cert.SerialNumber ?? "";
            bag["NotBefore"] = cert.NotBefore.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            bag["NotAfter"] = cert.NotAfter.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);
            string san = "";
            string template = "";
            foreach (X509Extension ext in cert.Extensions) {
                string oid = ext.Oid == null ? "" : ext.Oid.Value;
                if (oid == "2.5.29.17" && ext.RawData != null) san = Convert.ToBase64String(ext.RawData);
                if (oid == "1.3.6.1.4.1.311.20.2" || oid == "1.3.6.1.4.1.311.21.7") {
                    try { template = ext.Format(false); } catch { }
                }
            }
            bag["San"] = san ?? "";
            bag["Template"] = template ?? "";
            return bag;
        } catch {
            return null;
        }
    }

    static byte[] Decode(string payload) {
        if (string.IsNullOrEmpty(payload)) return null;
        string text = payload.Trim();
        if (text.IndexOf("BEGIN CERTIFICATE", StringComparison.OrdinalIgnoreCase) >= 0) {
            text = text.Replace("-----BEGIN CERTIFICATE-----", "");
            text = text.Replace("-----END CERTIFICATE-----", "");
        }
        var compact = new StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++) {
            char c = text[i];
            if (c == ' ' || c == '\r' || c == '\n' || c == '\t' || c == '"') continue;
            compact.Append(c);
        }
        string body = compact.ToString();
        if (body.Length < 16) return null;
        try {
            if (IsHex(body)) {
                var bytes = new byte[body.Length / 2];
                for (int i = 0; i < bytes.Length; i++) {
                    bytes[i] = byte.Parse(body.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                }
                return bytes;
            }
            return Convert.FromBase64String(body);
        } catch {
            return null;
        }
    }

    static bool IsHex(string text) {
        if (string.IsNullOrEmpty(text) || (text.Length % 2) != 0) return false;
        for (int i = 0; i < text.Length; i++) {
            char c = text[i];
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }
}
'@


function Initialize-CaReader {
    if ($script:CaReaderReady) { return $true }
    if ('CaLedgerReader034' -as [type]) {
        $script:CaReaderReady = $true
        return $true
    }
    try {
        Add-Type -TypeDefinition $script:CaReaderSource -Language CSharp -ErrorAction Stop
        $script:CaReaderReady = $true
        return $true
    } catch {
        if (($_.Exception.Message -match 'already exists') -and ('CaLedgerReader034' -as [type])) {
            $script:CaReaderReady = $true
            return $true
        }
        if (-not $script:CaReaderWarned) {
            Write-Warning "Could not compile the CA reader ($($_.Exception.Message))."
            $script:CaReaderWarned = $true
        }
        return $false
    }
}
$script:DnsCache = @{}
$script:CertUnreadable = 0
$script:CertReject = ''
function Resolve-InventoryIps {
    param([string] $Name)
    if ($script:DnsCache.ContainsKey($Name)) { return @($script:DnsCache[$Name]) }
    $ips = @()
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($Name)
        try { $task.Wait([TimeSpan]::FromSeconds(2)) } catch { }
        if ($task.IsCompleted -and -not $task.IsFaulted -and -not $task.IsCanceled) {
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

function Get-Unquoted {
    param($Value)
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    $text = $text -replace '^\s+', ''
    $text = $text -replace '\s+$', ''
    $text = $text -replace '^"+', ''
    $text = $text -replace '"+$', ''
    return $text
}

function Get-RowsFromView {
    param($Issuer, [datetime] $NotAfterFrom)
    $null = $NotAfterFrom
    $script:ViewIncomplete = $false
    if (-not (Initialize-CaReader)) {
        throw "The CA database reader could not be compiled on this host."
    }
    $kept = [bool]$IncludeExpired
    $text = [CaLedgerReader034]::Collect([string]$Issuer.config, $kept)
    if (-not $text) { return @() }
    $script:KeptRows = 0
    $records = New-Object System.Collections.ArrayList
    foreach ($line in ($text -split "\r?\n")) {
        if (-not $line) { continue }
        if ($line -like 'WARN *') {
            if (-not $script:CertReject) { $script:CertReject = $line }
            continue
        }
        try {
            $f = @($line -split "`t")
            if ($f.Count -lt 9) { continue }
            $san = ''
            $revoked = ''
            if ($f.Count -gt 9) { $revoked = [string]$f[9] }
            if ($f.Count -gt 10) { $san = [string]$f[10] }
            $bag = @{
                'RequestID'            = [string]$f[0]
                'ParsedSerial'         = [string]$f[1]
                'ParsedCommonName'     = [string]$f[2]
                'ParsedSubject'        = [string]$f[3]
                'ParsedTemplate'       = [string]$f[4]
                'Request.RequesterName' = [string]$f[5]
                'ParsedNotBefore'      = [string]$f[6]
                'ParsedNotAfter'       = [string]$f[7]
                'Request.Disposition'  = [string]$f[8]
                'RevokedWhen'          = $revoked
                'ParsedSan'            = $san
                'Request.CommonName'   = [string]$f[2]
                'SerialNumber'         = [string]$f[1]
                'NotBefore'            = [string]$f[6]
                'NotAfter'             = [string]$f[7]
                'CertificateTemplate'  = [string]$f[4]
            }
            $record = ConvertFrom-CaBag -Issuer $Issuer -Bag $bag
            if ($null -ne $record) {
                [void]$records.Add($record)
                $script:KeptRows++
            }
        } catch {
            if (-not $script:RowReject) { $script:RowReject = $_.Exception.GetBaseException().Message }
        }
    }
    $script:CollectedRows = $records
    return
}

function New-InventoryCertificate {
    param($Raw)
    $bytes = ConvertTo-ByteArray $Raw
    if ($null -eq $bytes -or $bytes.Length -lt 16) { return $null }
    if ($bytes[0] -ne 0x30) {
        $asText = $null
        try { $asText = [Text.Encoding]::ASCII.GetString($bytes) } catch { $asText = $null }
        if ($asText) {
            $decoded = ConvertTo-ByteArray $asText
            if ($decoded -and $decoded.Length -gt 16 -and $decoded[0] -eq 0x30) { $bytes = $decoded }
        }
    }
    if ($null -eq $bytes -or $bytes.Length -lt 16 -or $bytes[0] -ne 0x30) { return $null }
    # Windows PowerShell binds X509Certificate2's constructors to the wrong overload
    # and throws "Argument types do not match" for a valid certificate. Import(path) does not.
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("ca-inv-" + [guid]::NewGuid().ToString("n") + ".cer")
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Stop"
    $cert = $null
    try {
        [System.IO.File]::WriteAllBytes($path, [byte[]]$bytes)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($path)
        return $cert
    } catch {
        if ($cert) {
            try { $cert.Dispose() } catch { }
        }
        return $null
    } finally {
        $ErrorActionPreference = $previous
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function ConvertFrom-CaBag {
    param($Issuer, $Bag)
    $disposition = ConvertTo-Disposition $Bag['Request.Disposition']
    if (-not $disposition) { $disposition = ConvertTo-Disposition $Bag['Disposition'] }
    if ($disposition -ne 'issued' -and $disposition -ne 'revoked') {
        if (-not $script:RowReject) { $script:RowReject = "Skipped a database row. Disposition '$($Bag['Request.Disposition'])' is not issued or revoked." }
        return $null
    }

    $requestId = 0
    if ($Bag.ContainsKey('RequestID') -and $Bag['RequestID']) {
        $idText = [string]$Bag['RequestID']
        if ($idText -match '(\d+)') { $requestId = [int]$Matches[1] }
    }
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
    $parsed = $false
    if ($Bag['ParsedCommonName'] -or $Bag['ParsedSerial'] -or $Bag['ParsedNotAfter']) {
        $parsed = $true
        if ($Bag['ParsedCommonName']) { $cn = [string]$Bag['ParsedCommonName'] }
        if ($Bag['ParsedSubject']) { $subject = [string]$Bag['ParsedSubject'] }
        if ($Bag['ParsedSerial']) { $serial = ConvertTo-NormalizedSerial ([string]$Bag['ParsedSerial']) }
        if ($Bag['ParsedNotBefore']) { $notBefore = [string]$Bag['ParsedNotBefore'] }
        if ($Bag['ParsedNotAfter']) { $notAfter = [string]$Bag['ParsedNotAfter'] }
        $templateText = [string]$Bag['ParsedTemplate']
        if ($templateText -match '\(([^)]+)\)') { $template = $Matches[1] }
        elseif ($templateText -match '=\s*(.+)$') { $template = $Matches[1].Trim() }
        elseif ($templateText) { $template = $templateText }
        if ($Bag['ParsedSan']) {
            try {
                $sans = @(Read-GeneralNames -Bytes ([Convert]::FromBase64String([string]$Bag['ParsedSan'])))
            } catch { $sans = @() }
        }
    } elseif ($Bag['RawCertificate']) {
        $payload = $Bag['RawCertificate']
        if ($payload -is [System.Array]) {
            $hex = New-Object System.Text.StringBuilder
            foreach ($b in @($payload)) {
                try { [void]$hex.Append(('{0:x2}' -f [byte]$b)) } catch { }
            }
            $payload = $hex.ToString()
        }
        $info = $null
        if ($payload -and (Initialize-CaReader)) {
            try { $info = [CaLedgerReader]::Describe([string]$payload) } catch {
                if (-not $script:CertReject) { $script:CertReject = $_.Exception.GetBaseException().Message }
            }
        }
        if ($info) {
            $parsed = $true
            if ($info['CommonName']) { $cn = [string]$info['CommonName'] }
            if ($info['Subject']) { $subject = [string]$info['Subject'] }
            if ($info['Serial']) { $serial = ConvertTo-NormalizedSerial ([string]$info['Serial']) }
            if ($info['NotBefore']) { $notBefore = [string]$info['NotBefore'] }
            if ($info['NotAfter']) { $notAfter = [string]$info['NotAfter'] }
            $templateText = [string]$info['Template']
            if ($templateText -match '\(([^)]+)\)') { $template = $Matches[1] }
            elseif ($templateText -match '=\s*(.+)$') { $template = $Matches[1].Trim() }
            elseif ($templateText) { $template = $templateText }
            if ($info['San']) {
                try { $sans = @(Read-GeneralNames -Bytes ([Convert]::FromBase64String([string]$info['San']))) } catch { $sans = @() }
            }
        } else {
            $script:CertUnreadable++
            if (-not $script:CertReject) { $script:CertReject = 'The certificate bytes are not a valid X.509 certificate.' }
        }
    }
    if (-not $cn -or -not $notBefore -or -not $notAfter) {
        if (-not $script:RowReject) { $script:RowReject = "Skipped request $requestId. Name or dates were empty." }
        return $null
    }
    if (-not $IncludeExpired) {
        try { $expiry = [datetimeoffset]::Parse([string]$notAfter) } catch {
            if (-not $script:RowReject) { $script:RowReject = "Skipped request $requestId. Could not read the expiration date '$notAfter'." }
            return $null
        }
        if ($expiry.UtcDateTime -le [datetime]::UtcNow) { return $null }
    }
    return New-InventoryRecord -Issuer $Issuer -RequestId $requestId -Serial $serial -CommonName $cn `
        -Subject $subject -Template $template -Requester $requester -NotBefore $notBefore -NotAfter $notAfter `
        -Disposition $disposition -RevokedWhen $revokedWhen -Sans $sans
}

function Get-HexDumpBytes {
    param([string] $Block)
    $list = New-Object System.Text.StringBuilder
    $started = $false
    foreach ($line in ($Block -split "\r?\n")) {
        if ($line -match "Binary Certificate|Raw Certificate|RawCertificate") { $started = $true; continue }
        if (-not $started) { continue }
        $trim = $line.Trim()
        if (-not $trim) {
            if ($list.Length -gt 0) { break }
            continue
        }
        if ($trim -match "^[A-Za-z]") { break }
        $body = $trim
        if ($body -match "^[0-9A-Fa-f]{4,8}\s{2,}(.+)$") { $body = $Matches[1].Trim() }
        if ($body -match "^(.*[0-9A-Fa-f]{2})\s{2,}[^0-9A-Fa-f\s].*$") { $body = $Matches[1].Trim() }
        $tokens = @($body -split "\s+" | Where-Object { $_ -match "^[0-9A-Fa-f]{2}$" })
        if ($tokens.Count -lt 1) { continue }
        foreach ($hex in $tokens) { [void]$list.Append($hex) }
    }
    if ($list.Length -lt 32) { return $null }
    return $list.ToString()
}

function Invoke-CertutilText {
    param([string[]] $ArgumentList)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $lines = @(& certutil.exe @ArgumentList 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    return [pscustomobject]@{ ExitCode = $code; Output = ($lines -join "`n") }
}

function Test-CertutilViewOk {
    param($Result)
    if (-not $Result -or -not $Result.Output) { return $false }
    if ($Result.Output -match 'ERROR_INVALID_FUNCTION|INCORRECT FUNCTION|0x80070001|-view command FAILED') { return $false }
    if ($Result.Output -match '(?m)^Row \d+:' -or $Result.Output -match 'Request ID:') { return $true }
    if ($Result.ExitCode -eq 0) { return $true }
    return $false
}

function Get-CertutilDecimal {
    param([string] $Text)
    if ($Text -match '\((\d+)\)') { return [int]$Matches[1] }
    if ($Text -match '0x([0-9A-Fa-f]+)') { return [Convert]::ToInt32($Matches[1], 16) }
    if ($Text -match '(\d+)') { return [int]$Matches[1] }
    return 0
}

function Get-CertutilViewOutput {
    param($Issuer, [string] $ViewName, [string] $Disposition, [string] $Columns)
    $config = [string]$Issuer.config
    $attempts = @(
        @('-config', $config, '-out', $Columns, '-view', $ViewName),
        @('-config', $config, '-restrict', "Disposition=$Disposition", '-out', $Columns, '-view'),
        @('-config', $config, '-view', $ViewName, '-out', $Columns),
        @('-config', $config, '-view', '-restrict', "Disposition=$Disposition", '-out', $Columns)
    )
    $last = $null
    foreach ($attempt in $attempts) {
        $last = Invoke-CertutilText -ArgumentList $attempt
        if ($last.Output -match 'ACCESS_DENIED|0x80070005') {
            throw "certutil was denied on $config. Read permission on the CA is required. $($last.Output)"
        }
        if (Test-CertutilViewOk $last) { return $last.Output }
    }
    throw "certutil failed for ${config}: $($last.Output)"
}

function Get-RowsFromCertutil {
    param($Issuer)
    $columns = 'RequestID,SerialNumber,Request.RequesterName,Request.CommonName,CertificateTemplate,NotBefore,NotAfter,Request.Disposition,RevokedWhen,RawCertificate'
    $blocks = @()
    $failedViews = 0
    $queries = @(
        @{ View = 'Log'; Disposition = '20' },
        @{ View = 'Revoked'; Disposition = '21' }
    )
    foreach ($query in $queries) {
        $output = $null
        try {
            try {
                $output = Get-CertutilViewOutput -Issuer $Issuer -ViewName $query.View -Disposition $query.Disposition -Columns $columns
            } catch {
                $plain = 'RequestID,SerialNumber,Request.RequesterName,Request.CommonName,CertificateTemplate,NotBefore,NotAfter,Request.Disposition,RevokedWhen'
                $output = Get-CertutilViewOutput -Issuer $Issuer -ViewName $query.View -Disposition $query.Disposition -Columns $plain
            }
        } catch {
            Write-Warning "certutil $($query.View) view failed on $($Issuer.config). $($_.Exception.Message)"
            $failedViews++
            continue
        }
        $parts = [regex]::Split($output, '(?m)^Row \d+:\s*$')
        foreach ($part in $parts) {
            if ($part -and $part -match 'Request ID:') { $blocks += $part }
        }
    }
    $records = New-Object System.Collections.ArrayList
    foreach ($block in $blocks) {
        try {
            $bag = @{}
            $idLine = if ($block -match '(?m)^.*Request ID:.*$') { $Matches[0] } else { '' }
            if ($idLine) { $bag['RequestID'] = Get-CertutilDecimal $idLine }
            if ($block -match '(?m)Requester Name:\s*(.+)$') { $bag['Request.RequesterName'] = Get-Unquoted $Matches[1] }
            if ($block -match '(?m)(?:Request Common Name|Common Name):\s*(.+)$') { $bag['Request.CommonName'] = Get-Unquoted $Matches[1] }
            if ($block -match '(?m)Certificate Template:\s*(.+)$') {
                $templateLine = Get-Unquoted $Matches[1]
                if ($templateLine -match '\(([^)]+)\)\s*$') { $bag['CertificateTemplate'] = $Matches[1] }
                else { $bag['CertificateTemplate'] = $templateLine }
            }
            if ($block -match '(?m)Serial Number:\s*"?([0-9A-Fa-f ]+)') { $bag['SerialNumber'] = (Get-Unquoted $Matches[1]) }
            if ($block -match '(?m)^.*Request Disposition:.*$') { $bag['Request.Disposition'] = Get-CertutilDecimal $Matches[0] }
            if ($block -match '(?m)Certificate Effective Date:\s*(.+)$') { $bag['NotBefore'] = $Matches[1].Trim() }
            if ($block -match '(?m)Certificate Expiration Date:\s*(.+)$') { $bag['NotAfter'] = $Matches[1].Trim() }
            if ($block -match '(?m)Revocation Date:\s*(.+)$') {
                $revoked = $Matches[1].Trim()
                if ($revoked -and $revoked -notmatch '^(EMPTY|n/?a)$') { $bag['RevokedWhen'] = $revoked }
            }
            $pem = [regex]::Match($block, '-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----')
            if ($pem.Success) {
                $bag['RawCertificate'] = $pem.Value
            } else {
                $bag['RawCertificate'] = Get-HexDumpBytes -Block $block
            }
            $record = ConvertFrom-CaBag -Issuer $Issuer -Bag $bag
            if ($null -ne $record) { [void]$records.Add($record) }
        } catch {
            if (-not $script:CertReject) { $script:CertReject = $_.Exception.GetBaseException().Message }
        }
    }
    if ($records.Count -eq 0 -and $failedViews -eq $queries.Count) {
        throw "certutil could not read issued or revoked certificates on $($Issuer.config)."
    }
    return @($records)
}

function Select-InventorySan {
    param($Cert)
    $dns = @($Cert.sans | Where-Object { $_.type -eq 'dns' })
    foreach ($san in $dns) {
        if ($san.value -like '*.*' -and $san.value.ToLowerInvariant() -ne $Cert.cn.ToLowerInvariant()) { return [string]$san.value }
    }
    foreach ($san in $dns) {
        if ($san.value.ToLowerInvariant() -eq $Cert.cn.ToLowerInvariant()) { return [string]$san.value }
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
    $findings = New-Object System.Collections.ArrayList
    foreach ($cert in $valid) {
        $san = Select-InventorySan -Cert $cert
        $key = ('{0}|{1}' -f $cert.cn.ToLowerInvariant(), $san.ToLowerInvariant())
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $cnCerts = @($valid | Where-Object { $_.cn.ToLowerInvariant() -eq $cert.cn.ToLowerInvariant() })
        $sanCerts = @($valid | Where-Object { @($_.sans | Where-Object { $_.value.ToLowerInvariant() -eq $san.ToLowerInvariant() }).Count -gt 0 })
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
        [void]$findings.Add([ordered]@{
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
    $rows = New-Object System.Collections.ArrayList
    foreach ($cert in $valid) {
        $name = [string]$cert.cn
        $via = 'cn'
        $key = ('cn|' + $name.ToLowerInvariant())
        $matched = @()
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $matched = @($valid | Where-Object { $_.cn.ToLowerInvariant() -eq $name.ToLowerInvariant() })
        }
        if ($matched.Count -eq 0) {
            $via = 'san'
            $name = Select-InventorySan -Cert $cert
            $key = ('san|' + $name.ToLowerInvariant())
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $matched = @($valid | Where-Object {
                @($_.sans | Where-Object { $_.value.ToLowerInvariant() -eq $name.ToLowerInvariant() }).Count -gt 0
            })
        }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $serials = @($matched | ForEach-Object { $_.serial } | Select-Object -Unique)
        [void]$rows.Add([ordered]@{
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
    $rows = New-Object System.Collections.ArrayList
    $seen = @{}
    $cn = [string]$Cert.cn
    if (-not [string]::IsNullOrWhiteSpace($cn)) {
        [void]$rows.Add([ordered]@{ client = $cn; via = 'cn' })
        $seen[$cn.ToLowerInvariant()] = $true
    }
    foreach ($san in @($Cert.sans)) {
        if ($san.type -ne 'dns' -and $san.type -ne 'ip') { continue }
        $value = [string]$san.value
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        if ($seen.ContainsKey($value.ToLowerInvariant())) { continue }
        $seen[$value.ToLowerInvariant()] = $true
        [void]$rows.Add([ordered]@{ client = $value; via = 'san' })
    }
    return @($rows)
}

function Test-UnicastIpv4 {
    param([string] $Name)
    $parts = @($Name -split '\.')
    if ($parts.Count -ne 4) { return $false }
    $octets = @()
    foreach ($part in $parts) {
        if ($part -notmatch '^\d+$') { return $false }
        if ($part.Length -gt 1 -and $part -like '0*') { return $false }
        $n = [int]$part
        if ($n -lt 0 -or $n -gt 255) { return $false }
        $octets += $n
    }
    if ($octets[0] -eq 0 -or $octets[0] -ge 224) { return $false }
    return $true
}

function Test-DnsClientName {
    param([string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 253) { return $false }
    if ($Name -like '.*' -or $Name -like '*.') { return $false }
    foreach ($label in ($Name -split '\.')) {
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
            $ok = $false
            $pong = @(Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue)
            if ($pong.Count -gt 0 -and $pong[0]) { $ok = $true }
            if ($ok) {
                $result.status = 'active'
            } elseif ($isIp) {
                $result.status = 'not-on-network'
            } else {
                $result.status = 'inactive'
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
    $rows = New-Object System.Collections.ArrayList
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
            [void]$rows.Add([ordered]@{
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
    $json = $Snapshot | ConvertTo-Json -Depth 8 -Compress
    if ($Path -match "[\r\n\x00]") { throw "Output path is not valid." }
    $full = [System.IO.Path]::GetFullPath($Path)
    [System.IO.File]::WriteAllText($full, [string]$json)
    return $full
}

function Start-OnPremDashboard {
    param([string] $JsonPath, [string] $Prefix)
    $htmlPath = Join-Path $PSScriptRoot 'dashboard\index.html'
    if (-not (Test-Path -LiteralPath $htmlPath)) {
        throw "On-prem dashboard is missing: $htmlPath. Keep the dashboard folder beside this script."
    }
    if ($Prefix -notmatch '/$') { $Prefix = $Prefix + '/' }
    if ($Prefix -match '[\r\n\x00]' -or $Prefix -notmatch '^http://(\+|\*|[A-Za-z0-9._-]+):\d+/$') {
        throw "Listen must be one http address with a port, such as http://127.0.0.1:8787/. A container uses http://+:8787/."
    }
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($Prefix)
    try {
        $listener.Start()
    } catch {
        throw "Could not listen on $Prefix. Loopback usually needs no reservation. For another address on the isolated network, reserve it once: netsh http add urlacl url=$Prefix user=$env:USERDOMAIN\$env:USERNAME. $($_.Exception.Message)"
    }
    Write-Host ''
    Write-Host ("On-prem dashboard  {0}" -f $Prefix)
    Write-Host 'This process serves only the console and cert-inventory.json. It does not open an outbound connection.'
    Write-Host 'Press Ctrl+C to stop.'
    $htmlBytes = [System.IO.File]::ReadAllBytes($htmlPath)
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            try {
                $response.Headers['X-Content-Type-Options'] = 'nosniff'
                $response.Headers['Cache-Control'] = 'no-store'
                $response.Headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'"
                if ($request.HttpMethod -ne 'GET' -and $request.HttpMethod -ne 'HEAD') {
                    $response.StatusCode = 405
                } else {
                    $route = $request.Url.AbsolutePath
                    $bytes = $null
                    if ($route -eq '/' -or $route -eq '/index.html') {
                        $response.ContentType = 'text/html; charset=utf-8'
                        $bytes = $htmlBytes
                    } elseif ($route -eq '/cert-inventory.json') {
                        $response.ContentType = 'application/json; charset=utf-8'
                        $bytes = [System.IO.File]::ReadAllBytes($JsonPath)
                    } else {
                        $response.StatusCode = 404
                    }
                    if ($null -ne $bytes) {
                        $response.ContentLength64 = $bytes.Length
                        if ($request.HttpMethod -ne 'HEAD') {
                            $response.OutputStream.Write($bytes, 0, $bytes.Length)
                        }
                    }
                }
            } catch {
                try { $response.StatusCode = 500 } catch { }
            } finally {
                try { $response.Close() } catch { }
            }
        }
    } finally {
        $listener.Stop()
        $listener.Close()
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Host') {
    $existing = [System.IO.Path]::GetFullPath($OutputPath)
    if (-not (Test-Path -LiteralPath $existing)) {
        Write-Host "No inventory at $existing. Collect first, or pass -Demo -Serve."
        exit 1
    }
    Start-OnPremDashboard -JsonPath $existing -Prefix $Listen
    exit 0
}

if ($PSCmdlet.ParameterSetName -eq 'Demo') {
    $snapshot = Get-DemoSnapshot
} else {
    if ($IssuingCa.Count -lt 2) {
        Write-Host "Collecting $($IssuingCa.Count) issuing CA (collector 0.3.7). One CA is enough; a two-tier PKI often has more."
    }
    $issuers = @()
    foreach ($config in $IssuingCa) { $issuers += Split-CaConfig -Config $config }
    $certs = @()
    $errors = @()
    $script:ViewIncomplete = $false
    foreach ($issuer in $issuers) {
        Write-Host ("Collecting {0}" -f $issuer.config)
        try {
            $rows = @()
            try {
                Get-RowsFromView -Issuer $issuer -NotAfterFrom ([datetime]::UtcNow) | Out-Null
            } catch {
                Write-Warning "Collection failed ($($_.Exception.Message))."
                if (-not $script:CertReject) { $script:CertReject = $_.Exception.Message }
            }
            foreach ($row in @($script:CollectedRows)) {
                if ($null -ne $row) { $certs += $row }
            }
            Write-Host ("  {0} rows" -f [int]$script:KeptRows)
        } catch {
            $message = $_.Exception.Message
            Write-Warning $message
            $errors += [ordered]@{ config = $issuer.config; message = $message }
        }
    }
    if ($script:CertUnreadable -gt 0) {
        Write-Warning ("{0} database rows had certificate bytes that could not be read. {1}" -f $script:CertUnreadable, $script:CertReject)
    }
    if ($certs.Count -eq 0) {
        Write-Host 'No issued certificates were collected.'
        if ($script:RowReject) { Write-Host ("  Row: {0}" -f $script:RowReject) }
        if ($script:CertReject) { Write-Host ("  Certificate decode: {0}" -f $script:CertReject) }
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
Write-Host 'ADCS Certificate Inventory collection'
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
if ($Serve) {
    $exitCode = 0
    if (@($snapshot.errors).Count -gt 0) { $exitCode = 2 }
    Start-OnPremDashboard -JsonPath $path -Prefix $Listen
    exit $exitCode
}
if (@($snapshot.errors).Count -gt 0) { exit 2 }
exit 0
