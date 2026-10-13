# Implementation Guide — Azure Sheep Dip

Step-by-step setup for the secure file-transfer service described in [README.md](README.md). Everything runs in **one Azure subscription**; isolation is achieved through separate storage accounts, identities, networking and RBAC — not a separate subscription.

**Deliverable boundary:** a sanitised file lands in `save_blob`. The downstream process that reads `save_blob`, and the injection defences that belong with it, are out of scope here.

> Commands use the Azure CLI (`az`) and are written for **UK South**. Replace placeholder values before running. Treat this as a reviewed starting point, not a drop-in script.

---

## Pipeline at a glance

```
Internal analyst (Entra ID SSO) ┐
                                 ├─► Portal + API ─► quarantine ─► malware scan ─► CDR/sanitise ─► save_blob ─► (downstream, out of scope)
Partner (link + password, 48h) ──┘
```

## 1. Prerequisites

- Azure CLI 2.60+ (`az version`) and an account with **Owner** or **Security Admin** + **User Access Administrator** on the subscription.
- Microsoft Defender for Cloud available on the subscription.

```bash
az login
az account set --subscription "<subscription-id>"
az provider register --namespace Microsoft.Security
az provider register --namespace Microsoft.EventGrid
az provider register --namespace Microsoft.Storage
```

## 2. Variables

```bash
LOCATION="uksouth"
RG_QUARANTINE="rg-sheepdip-quarantine"
RG_APP="rg-sheepdip-app"
SA_QUARANTINE="sadipquar$RANDOM"     # globally unique, 3-24 lowercase alphanumeric
SA_SAFE="sadipsafe$RANDOM"           # holds save_blob (container name can't contain "_")
SA_STATE="sadipstate$RANDOM"
SAFE_CONTAINER="safe"                # logical target the downstream calls "save_blob"
STATE_TABLE="uploads"
EG_TOPIC="egt-sheepdip-scanresults"
FUNC_PORTAL="func-sheepdip-portal"
FUNC_ROUTER="func-sheepdip-router"
```

## 3. Resource groups

```bash
az group create -n "$RG_QUARANTINE" -l "$LOCATION"
az group create -n "$RG_APP" -l "$LOCATION"
```

## 4. Quarantine storage account (locked down)

Its own account — not a container in production. Public access off, shared-key auth off (Entra ID only), default-deny firewall, TLS 1.2.

```bash
az storage account create \
  -n "$SA_QUARANTINE" -g "$RG_QUARANTINE" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 \
  --allow-blob-public-access false \
  --allow-shared-key-access false \
  --min-tls-version TLS1_2 \
  --public-network-access Disabled \
  --default-action Deny

az storage container create --account-name "$SA_QUARANTINE" -n incoming --auth-mode login

# Soft delete so malicious files can be recovered for investigation
az storage account blob-service-properties update \
  --account-name "$SA_QUARANTINE" -g "$RG_QUARANTINE" \
  --enable-delete-retention true --delete-retention-days 7
```

## 5. Safe storage account (`save_blob`)

Separate account. The downstream process reads from here; nothing here can reach quarantine.

```bash
az storage account create \
  -n "$SA_SAFE" -g "$RG_APP" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 \
  --allow-blob-public-access false \
  --allow-shared-key-access false \
  --min-tls-version TLS1_2 \
  --public-network-access Disabled \
  --default-action Deny

az storage container create --account-name "$SA_SAFE" -n "$SAFE_CONTAINER" --auth-mode login
```

> Blob container names can't contain underscores, so the physical container is `safe`; `save_blob` is the logical name the downstream contract refers to.

## 6. State store (upload tracking + partner auth)

One record per upload link. For partner links this also holds the auth material.

| Field | Purpose |
| --- | --- |
| `uploadId` (PK) | GUID; names the quarantine blob |
| `createdBy` | Internal user who generated the link |
| `partnerEmail` | Where the link was sent |
| `passwordHash` | Hash of the partner password (never the password) |
| `expiresAt` | Creation + 48h |
| `attempts` | Failed-auth counter for lockout |
| `status` | `pending → uploaded → scanned → sanitised → delivered` / `blocked` |

```bash
az storage account create -n "$SA_STATE" -g "$RG_APP" -l "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 --allow-blob-public-access false
az storage table create --account-name "$SA_STATE" -n "$STATE_TABLE" --auth-mode login
```

## 7. Enable Defender for Storage malware scanning

Scan **at rest, on upload**. Current limits: **up to 50 GB per blob**, default cap **10,000 GB/month per account** (configurable; `-1` = unlimited), throughput up to **50 GB/min per account**.

**Account-scoped (recommended for a sheep dip)** — scans only the quarantine account, so production is neither scanned nor billed. Per-account enablement uses the `defenderForStorageSettings` resource (portal toggle, REST, or Bicep):

```bash
SA_QUAR_ID=$(az storage account show -n "$SA_QUARANTINE" -g "$RG_QUARANTINE" --query id -o tsv)

az rest --method put \
  --url "https://management.azure.com${SA_QUAR_ID}/providers/Microsoft.Security/defenderForStorageSettings/current?api-version=2022-12-01-preview" \
  --body '{
    "properties": {
      "isEnabled": true,
      "malwareScanning": {
        "onUpload": { "isEnabled": true, "capGBPerMonth": 5000 },
        "scanResultsEventGridTopicResourceId": "<set-after-step-8>"
      },
      "sensitiveDataDiscovery": { "isEnabled": false },
      "overrideSubscriptionLevelSettings": true
    }
  }'
```

**Subscription-scoped alternative** (protects every account, scans/bills production too):

```bash
az security pricing create \
  --name StorageAccounts --tier Standard --subplan DefenderForStorageV2 \
  --extensions name=OnUploadMalwareScanning isEnabled=True \
    additionalExtensionProperties='{"CapGBPerMonthPerStorageAccount":"5000","BlobScanResultsOptions":"BlobIndexTags"}'
```

Notes:
- Enabling malware scanning auto-creates an Event Grid **system** topic in the account's resource group and grants a scanner identity **Storage Blob Data Owner** — expected, separate from the custom topic below.
- Scan results are also written as blob **index tags** (`Malware Scanning scan result`, `Malware Scanning scan time UTC`).
- Defender detects known-bad files; it does **not** strip active content. That is the CDR step (step 10).

## 8. Event Grid custom topic for scan results

```bash
az eventgrid topic create \
  -g "$RG_APP" -n "$EG_TOPIC" -l "$LOCATION" \
  --input-schema eventgridschema --public-network-access enabled

EG_TOPIC_ID=$(az eventgrid topic show -g "$RG_APP" -n "$EG_TOPIC" --query id -o tsv)
```

> **Important:** the custom topic **must allow public network access** (Defender can't deliver to a private-only topic) and be in the **same region** as the storage account. Grant the Defender for Storage service principal the **EventGrid Data Sender** role on it, then set this topic's resource ID as `scanResultsEventGridTopicResourceId` in step 7 (or via the portal).

## 9. Portal + API (two front doors)

One Function/App Service app, two auth paths.

```bash
az functionapp create \
  -g "$RG_APP" -n "$FUNC_PORTAL" --consumption-plan-location "$LOCATION" \
  --runtime dotnet-isolated --functions-version 4 \
  --storage-account "$SA_STATE" --assign-identity

PORTAL_PID=$(az functionapp identity show -g "$RG_APP" -n "$FUNC_PORTAL" --query principalId -o tsv)

# Mint write-only user-delegation SAS on quarantine
az role assignment create --assignee "$PORTAL_PID" --role "Storage Blob Delegator" --scope "$SA_QUAR_ID"
az role assignment create --assignee "$PORTAL_PID" --role "Storage Blob Data Contributor" --scope "$SA_QUAR_ID"
```

**Internal analysts — Entra ID (SSO).** Protect the internal routes with App Service authentication (Easy Auth):

```bash
az webapp auth update -g "$RG_APP" -n "$FUNC_PORTAL" \
  --enabled true --action RedirectToLoginPage \
  --redirect-provider azureactivedirectory
```

**External partners — link + password gate.** Implemented in app code against the state store:

1. `POST /links` (internal, SSO-protected) → create a `uploadId` record: `partnerEmail`, `passwordHash`, `expiresAt = now + 48h`, status `pending`. Email the link; send the password out-of-band where possible.
2. `POST /u/{uploadId}` with the password → validate: record exists, `now < expiresAt`, unused, password matches `passwordHash`. Increment `attempts` and lock after N failures.
3. On success, mint a **user-delegation SAS**: write-only, single blob `incoming/{uploadId}`, short TTL (~15 min). The partner uploads directly to quarantine.

```bash
# Illustrative SAS mint (the app does this with the portal identity)
az storage blob generate-sas \
  --account-name "$SA_QUARANTINE" -c incoming -n "<uploadId>" \
  --permissions w --as-user --auth-mode login \
  --expiry "$(date -u -d '15 minutes' '+%Y-%m-%dT%H:%MZ')" \
  --https-only -o tsv
```

## 10. CDR / sanitise

Malware scanning removes known-bad files; **CDR** rebuilds a clean, flattened copy of each surviving file to strip macros, embedded scripts and other active content. The engine is a design decision (open item): a third-party CDR product, or a custom reconstruction step in a Function/container. It runs **after** a clean malware verdict and **before** delivery — so only reconstructed files reach `save_blob`. Give the CDR compute read access to quarantine and nothing else; it returns the rebuilt file to the router (or writes to a staging path the router reads).

## 11. Delivery router (Function App)

Triggered by each scan result; on clean, runs CDR then writes to `save_blob`.

```bash
az functionapp create \
  -g "$RG_APP" -n "$FUNC_ROUTER" --consumption-plan-location "$LOCATION" \
  --runtime dotnet-isolated --functions-version 4 \
  --storage-account "$SA_STATE" --assign-identity

ROUTER_PID=$(az functionapp identity show -g "$RG_APP" -n "$FUNC_ROUTER" --query principalId -o tsv)
SA_SAFE_ID=$(az storage account show -n "$SA_SAFE" -g "$RG_APP" --query id -o tsv)

az role assignment create --assignee "$ROUTER_PID" --role "Storage Blob Data Contributor" --scope "$SA_QUAR_ID"
az role assignment create --assignee "$ROUTER_PID" --role "Storage Blob Data Contributor" --scope "$SA_SAFE_ID"

az eventgrid event-subscription create \
  --name scanresults-to-router \
  --source-resource-id "$EG_TOPIC_ID" \
  --endpoint-type azurefunction \
  --endpoint "$(az functionapp show -g "$RG_APP" -n "$FUNC_ROUTER" --query id -o tsv)/functions/RouteScanResult" \
  --included-event-types Microsoft.Security.MalwareScanningResult
```

**Router logic** (verdict in `data.scanResultType`):

```
on event:
  blobUri  = event.data.blobUri
  verdict  = event.data.scanResultType     # "No threats found" | "Malicious" | "Not Scanned"
  uploadId = parse from blob name

  if verdict == "No threats found":
      cleanFile = CDR(quarantine/incoming/{uploadId})   # step 10
      write cleanFile -> safe/{SAFE_CONTAINER}/{uploadId}   # = save_blob
      delete original from quarantine
      state[uploadId].status = "delivered"
  elif verdict == "Malicious":
      # blob soft-deleted (built-in response) or delete here
      state[uploadId].status = "blocked"
      raise alert (event.data.scanResultDetails.malwareNamesFound, blobUri)
  else:   # "Not Scanned" (e.g. > 50 GB — see data.scanResultDetails.notScannedReason / SAM code)
      state[uploadId].status = "needs_review"
      raise alert
```

## 12. Networking

- Quarantine and safe accounts: `--public-network-access Disabled` (set above). Reach them from the Functions over **private endpoints**; Functions use **VNet integration** for outbound.
- Firewall: default-deny; allow only the private endpoints / trusted subnets. No route from the production VNet into quarantine.
- **Exception:** the Event Grid **custom topic** must keep public network access enabled.

```bash
az network private-endpoint create \
  -g "$RG_QUARANTINE" -n pe-quarantine-blob -l "$LOCATION" \
  --vnet-name <vnet> --subnet <subnet> \
  --private-connection-resource-id "$SA_QUAR_ID" \
  --group-id blob --connection-name quarantine-blob
```

## 13. RBAC summary (least privilege)

| Identity | Scope | Role | Why |
| --- | --- | --- | --- |
| Portal API | Quarantine account | Storage Blob Delegator + Storage Blob Data Contributor | Mint write-only user-delegation SAS |
| CDR engine | Quarantine account | Storage Blob Data Reader (+ write to staging if used) | Read file to reconstruct |
| Delivery router | Quarantine account | Storage Blob Data Contributor | Read + delete after verdict |
| Delivery router | Safe account | Storage Blob Data Contributor | Write `save_blob` |
| Defender for Storage SP | Custom Event Grid topic | EventGrid Data Sender | Publish scan results |
| (auto) Scanner identity | Quarantine account | Storage Blob Data Owner | Read blobs to scan |

No production identity holds any role on the quarantine account. Do not reuse a managed identity across the dirty and clean sides.

## 14. Monitoring and alerts

- Alert when the monthly scanning **cap** nears its limit (scanning silently halts once reached).
- Alert on **blocked-file** events and on `Not Scanned` results.
- Alert on uploads stuck in `pending`/`uploaded` beyond an expected window, and on partner-auth lockouts.
- Send Function App logs to **Application Insights**; send Defender alerts to your SIEM.

## 15. Test end to end

Use the EICAR test string (a harmless standard antivirus test file).

1. As an internal user, generate a partner link; open it, authenticate with the password, upload a small EICAR `.txt`.
2. Confirm a `Microsoft.Security.MalwareScanningResult` event with `scanResultType = "Malicious"`, the state becomes `blocked`, the blob is soft-deleted, and an alert fires.
3. Upload a clean file; confirm CDR runs, the reconstructed file lands in `save_blob`, and the state becomes `delivered`.
4. Confirm an expired (>48h) or reused link is rejected.

## 16. Teardown

```bash
az group delete -n "$RG_QUARANTINE" --yes --no-wait
az group delete -n "$RG_APP" --yes --no-wait
# If Defender was enabled at subscription level:
# az security pricing create --name StorageAccounts --tier Free
```

---

## References

- [Defender for Storage overview](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction)
- [On-upload malware scanning (limits, cap, throughput)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/on-upload-malware-scanning)
- [Malware scanning limits — 50 GB per blob, file types](https://learn.microsoft.com/en-us/azure/defender-for-cloud/introduction-malware-scanning)
- [Set up automated remediation + Event Grid (scan-result schema)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-configure-malware-scan)
- [Enable with PowerShell / CLI / REST / IaC](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-powershell-enablement)
- [App Service authentication (Entra ID / Easy Auth)](https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization)
