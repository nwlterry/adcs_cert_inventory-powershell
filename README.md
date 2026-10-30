# AD CS certificate inventory (PowerShell)

Collect issued certificates from a two-tier AD CS hierarchy (offline root, two or more issuing CAs). The CA inventory is the base. For each valid certificate, every common name and SAN is a client of that serial. Several clients may use the same certificate; that is not a conflict.

The collector then probes each client on the local network. The result is the last-5-minute status: active, inactive, not in DNS, or not on the network. Copy `cert-inventory.json` to the console host. The console does not use the internet.

Run this on a workstation that can reach every issuing CA and has the Certification Authority tools installed (`certadm.dll`, RSAT: AD CS). Windows PowerShell 5.1 or PowerShell 7.

The offline root is recorded by name only. End-entity rows come from the issuing CAs.

.NET 8 port: [adcs_cert_inventory_dotnet](https://github.com/nwlterry/adcs_cert_inventory_dotnet).

## Collect

```powershell
powershell -NoProfile -ExecutionPolicy RemoteSigned -File .\Invoke-CertInventory.ps1 `
  -IssuingCa @(
    'pki-ica01.corp.local\CORP-ISSUING-CA-01',
    'pki-ica02.corp.local\CORP-ISSUING-CA-02'
  ) `
  -RootCaName 'CORP-OFFLINE-ROOT-CA' `
  -OutputPath .\cert-inventory.json
```

| Parameter | Role |
|---|---|
| `-IssuingCa` | One or more `hostname\CA Name` config strings. Two or more expected. |
| `-RootCaName` | Offline root display name. Not contacted. |
| `-OutputPath` | JSON file. Default `.\cert-inventory.json`. |
| `-ExpiryWindowDays` | Console expiry window. Default 30. |
| `-IncludeExpired` | Also keep certificates that have already expired. Default is unexpired issued and revoked rows. |
| `-SkipDns` | Do not resolve CN and DNS SAN names. IP SANs are still recorded. |
| `-Demo` | Write a small file and do not contact a CA. |

Exit codes: `0` collected, `1` nothing collected, `2` collected but at least one issuing CA failed.

The script opens each CA with `CertificateAuthority.View`. If that COM object fails, it falls back to `certutil -view`. The certutil path expects English column labels. COM is the path to use on a non-English CA admin workstation.

`cert-inventory.json` contains host names, serials, and addresses. It is gitignored. Do not commit a live collection.

## Clients

A certificate is valid when disposition is issued, `NotBefore` has passed, and `NotAfter` is still in the future.

For each valid certificate the script:

1. Reads the certificate serial from the CA inventory.
2. Lists the common name, then each DNS or IP SAN, as a client of that serial.
3. Probes the client on this network (DNS, then one ICMP echo, 1 second).

| Status | Meaning |
|---|---|
| `active` | The name resolved, or it is an IP, and the probe answered. |
| `inactive` | DNS has the name, but the host did not answer. |
| `not-in-dns` | No DNS record. |
| `not-on-network` | The address is known, but the network path did not answer (unreachable). |

`clientChecks[]` is that list. `checkedAt` is the probe time. The console treats a check as the last 5 minutes when the file is newer than `statusWindowMinutes` (default 5). Re-run the collector on the isolated network to refresh it. The console host does not need a route to the public internet, and it does not resolve client names itself.

DNS names used for the system list are still resolved when the script runs, so the JSON carries an address for zones that are only visible inside the network.

## JSON

Schema `ca-ledger/1`.

```json
{
  "schema": "ca-ledger/1",
  "collectedAt": "2026-10-30T04:00:00.0000000Z",
  "collector": "Invoke-CertInventory.ps1",
  "rootName": "CORP-OFFLINE-ROOT-CA",
  "expiryWindowDays": 30,
  "statusWindowMinutes": 5,
  "issuing": [
    {
      "config": "pki-ica01.corp.local\\CORP-ISSUING-CA-01",
      "host": "pki-ica01.corp.local",
      "name": "CORP-ISSUING-CA-01"
    }
  ],
  "certificates": [],
  "clientChecks": [
    {
      "serial": "4f12a1000001",
      "client": "es-data-01.obs.corp.local",
      "via": "cn",
      "status": "active",
      "checkedAt": "2026-10-30T04:00:00.0000000Z",
      "address": "10.16.8.21"
    },
    {
      "serial": "11aa01000001",
      "client": "www.corp.local",
      "via": "san",
      "status": "active",
      "checkedAt": "2026-10-30T04:00:00.0000000Z",
      "address": "10.16.2.31"
    }
  ],
  "errors": []
```

`via` is `cn` or `san`. Disposition in the CA database is `20` issued or `21` revoked. The file stores `issued` or `revoked`.

Sibling certificate automation: [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation).
