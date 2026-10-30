# AD CS certificate inventory (PowerShell)

Collect issued certificates from a two-tier AD CS hierarchy (offline root, two or more issuing CAs). For each valid client certificate, look it up by common name, or by exactly one SAN when the common name is not on a valid certificate. The serial number on the certificate that lookup returns is the serial used for validation. When both the common name and that one SAN resolve, the two serials are compared.

The summary also lists certificates that expire within 30 days, with the system name and IP taken from the CN and SAN.

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

## Validation

A certificate is valid when disposition is issued, `NotBefore` has passed, and `NotAfter` is still in the future. Revoked rows stay in the file and are excluded from validation.

For each valid client certificate the script:

1. Looks the certificate up by common name.
2. If that common name is not on a valid issued certificate, looks it up by exactly one SAN: the first DNS name that differs from the CN, otherwise the CN itself, otherwise one IP SAN.
3. Reads the serial number on the certificate that lookup returns. That serial is the validation serial. `verified` is true only when the lookup returns one serial.
4. When both the common name and that one SAN resolve, compares the two serial sets.

| Kind | Meaning |
|---|---|
| `match` | CN and the one SAN resolve to the same single valid serial. |
| `duplicate` | The names agree, but more than one certificate is still valid. Revoke the superseded serial. |
| `divergent` | The SAN is covered by a different set of valid serials than the CN. |
| `mismatch` | The two lookups share no serial. |
| `cn-missing` / `san-missing` | No valid issued certificate for that name. |

`validations[]` is the CN-or-one-SAN lookup and the serial taken from it. `comparisons[]` is the cross-check, and only non-matches are kept.

DNS names are resolved when the script runs, so the JSON carries system name and IP even for zones that are not visible from elsewhere. An IP address in the SAN is kept even when DNS fails.

## JSON

Schema `ca-ledger/1`.

```json
{
  "schema": "ca-ledger/1",
  "collectedAt": "2026-10-30T04:00:00.0000000Z",
  "collector": "Invoke-CertInventory.ps1",
  "rootName": "CORP-OFFLINE-ROOT-CA",
  "expiryWindowDays": 30,
  "issuing": [
    {
      "config": "pki-ica01.corp.local\\CORP-ISSUING-CA-01",
      "host": "pki-ica01.corp.local",
      "name": "CORP-ISSUING-CA-01"
    }
  ],
  "certificates": [],
  "errors": [],
  "comparisons": [
    {
      "cn": "web-iis-01.corp.local",
      "san": "www.corp.local",
      "kind": "duplicate",
      "cnSerials": ["11aa01000001", "11aa01000002"],
      "sanSerials": ["11aa01000001", "11aa01000002"]
    }
  ],
  "validations": [
    {
      "name": "es-data-01.obs.corp.local",
      "via": "cn",
      "serials": ["4f12a1000001"],
      "verified": true
    }
  ]
}
```

`via` is `cn` or `san`. Disposition in the CA database is `20` issued or `21` revoked. The file stores `issued` or `revoked`.

Sibling certificate automation: [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation).
