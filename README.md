# Azure Sheep Dip — Secure File Transfer Design

_Last updated: 13 October 2026_

> **Setting it up?** Step-by-step Azure CLI instructions are in [IMPLEMENTATION.md](IMPLEMENTATION.md).

## Purpose and scope

A secure file-ingestion service (a "sheep dip") with two front doors: internal analysts, authenticated with Entra ID, and external partners, authenticated with an emailed one-time link plus a password valid for 48 hours. Both upload through the same pipeline, where files are scanned and sanitised at rest, and only clean, reconstructed files are delivered to a shared safe blob (`save_blob`). A separate existing process reads from `save_blob` and processes the files — out of scope here. The deliverable boundary is simply: a sanitised file lands in `save_blob`.

In scope:

- A portal where an internal user can generate a scoped upload link to send to a partner.
- Two authentication paths: Entra ID for internal users; emailed one-time link plus password (48-hour expiry) for partners.
- Direct-to-storage upload into an isolated quarantine zone.
- Sanitisation at rest: malware scan, then Content Disarm and Reconstruction (CDR) to strip active content.
- Automated delivery of clean, reconstructed files to the shared safe blob (`save_blob`).

Out of scope: the downstream process that reads from `save_blob`, and the injection defences that belong with it (see "What sanitisation covers" below).

### What sanitisation covers

Sanitisation at this stage is file-level: malware scanning removes known-bad files, and CDR rebuilds a clean, flattened copy of each file to strip macros, embedded scripts and other active content. It does **not** address SQL injection or prompt injection — those are properties of how data is used, not of the file at rest. A malicious string in a CSV cell is inert in storage; it only becomes dangerous when the downstream process passes it into a query or an AI/LLM step. Those defences — parameterised queries, strict schema and type validation, and treating content as untrusted data at the LLM boundary — live with the downstream process that consumes `save_blob`.

## Architecture overview

![Architecture overview — two front doors, one sheep dip, delivering to save_blob](architecture.svg)

Both front doors feed one pipeline: a file is scanned and reconstructed in quarantine, and only the clean, sanitised copy is written to `save_blob`. A malicious verdict routes the file to quarantine or deletion and raises an alert. The downstream process reads from `save_blob` and is out of scope here.

## Components

| Component | Azure service | Role |
| --- | --- | --- |
| Portal + API | App Service / Static Web App + Azure Functions | Issues scoped upload links, authenticates users, mints upload SAS |
| Internal auth | Entra ID (SSO) | Authenticates internal analysts |
| Partner auth | Link + password gate (Functions + state store) | One-time link + password, 48-hour expiry, for external partners |
| State store | Table Storage or Cosmos DB | One record per upload: ID, partner email, password hash, expiry, status |
| Quarantine store | Storage account (Blob), isolated | Holds untrusted files at rest; no public access, no egress |
| Malware scan | Defender for Storage | Full malware scan on upload, writes a verdict |
| CDR / sanitise | CDR engine (Function/container or third party) | Rebuilds a clean, flattened copy; strips active content |
| Delivery router | Event Grid + Azure Function | Promotes clean, reconstructed files; quarantines or deletes the rest |
| Safe blob (`save_blob`) | Separate storage account (Blob) | Holds sanitised files for the downstream process; never reads quarantine |
| Downstream process | Existing, out of scope | Reads from `save_blob` |

## Authentication and access

Two entry points feed one pipeline.

### Internal analysts

Authenticated with Entra ID (SSO) and upload directly through the portal. Corporate identity is the control, so no link or password is needed.

### External partners

An internal user generates a link for a partner. The partner receives an emailed one-time link tied to a single `uploadId`, plus a password, and has 48 hours to use it.

- Deliver the password out-of-band from the link where possible (e.g. link by email, password by SMS), so one compromised mailbox is not enough.
- Store only a hash of the password; rate-limit attempts and lock after repeated failures.
- The link is single-use (or limited-use) and expires at 48 hours regardless of use.
- On success, the portal mints a short-lived, write-only SAS scoped to one blob; the partner uploads directly to quarantine.
- A one-time code (OTP) can replace the static password later if stronger assurance is wanted.

## Security and isolation

The design rests on a hard boundary between the dirty and clean sides.

- **Upload SAS** — write-only, scoped to a single blob, short time-to-live, tied to the upload ID. This is the trust boundary at upload: a leaked link cannot be used to list or read the container, only to write its one blob once.
- **Quarantine network lockdown** — public blob access disabled, reached only over private endpoints, with no outbound egress from the zone.
- **Separate storage accounts** — quarantine and `save_blob` live in different accounts with different managed identities and RBAC. The clean side has no read path into quarantine.
- **One-way promotion** — only the delivery router can copy a file from quarantine to `save_blob`, and only after a clean verdict and CDR. Blocked files are quarantined or deleted, never released.
- **End-to-end logging** — every upload, verdict and move is logged with its upload ID, giving a full audit trail from link issue to delivery.

### Why the same subscription is safe

A separate Azure subscription is not required for containment. The subscription is a billing and management boundary, not a security control — isolation comes from identity, network and resource separation, all of which work within one subscription.

- A malicious file in Blob storage is inert: Blob storage executes nothing, so the file cannot run or spread laterally on its own. The risk is the access paths to it, not the bytes at rest.
- Quarantine lives in its own storage account with its own keys, firewall and access policies — never just a container inside the production account.
- No production identity holds any role on the quarantine account, and the scanner and router identities are never shared with production.
- Quarantine has public access disabled, shared-key access disabled (Entra ID only), and is reached only over a private endpoint behind a default-deny firewall — no route from the production network.
- The compute that scans and sanitises quarantined files is the real lateral-movement risk, so it runs least-privilege with no outbound path to production.

A separate subscription is worth it only for hard management-plane blast-radius separation, distinct governance or billing, or an accreditation requirement — not for technical containment.

## Malware scanning: Defender for Storage vs custom engine

Two routes. [Defender for Storage](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-introduction) is the low-effort default: a configurable add-on that runs a full scan on upload in near real time, powered by Microsoft Defender Antivirus, with no infrastructure to manage. A custom engine (an AV engine in a Function or container) is the route when you need multiple engines, CDR, or scanning of files larger than Defender's per-blob limit — at the cost of building and running it.

> Note: Defender detects known-bad files; it does not strip active content. The **CDR** step is what rebuilds a clean copy — the two are complementary, not alternatives.

### Defender for Storage — current limits

| Limit | Value |
| --- | --- |
| Per-blob scan size | Up to 50 GB per blob |
| Default monthly cap | 10,000 GB (10 TB) scanned per storage account per month |
| Behaviour at cap | Scanning halts for the rest of the month (≈20 GB confidence interval); configurable via `CapGBPerMonthPerStorageAccount`, set to `-1` for unlimited |
| Scan throughput | Up to 50 GB per minute per storage account |
| Supported storage | Azure Blob Storage only |
| Trigger | On upload (near real time), or on-demand |

Sources: [malware scanning limits and cap](https://learn.microsoft.com/en-us/azure/defender-for-cloud/on-upload-malware-scanning), [cap configuration](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-storage-powershell-enablement), [50 GB per-blob limit and file-type support](https://learn.microsoft.com/en-us/azure/defender-for-cloud/introduction-malware-scanning).

### Pricing

Defender for Storage has two charges: a per-storage-account plan fee, plus malware scanning billed per GB scanned. Microsoft's [pricing page](https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/) does not render the figures as plain text, so the amounts below are approximate ballparks — confirm current rates for your region (UK South) in the [Azure pricing calculator](https://azure.microsoft.com/en-us/pricing/calculator/?service=defender-for-cloud) before budgeting.

| Charge | Approximate rate |
| --- | --- |
| Defender for Storage plan | ~$10 per storage account per month |
| Malware scanning | ~$0.15 per GB scanned |

Billing notes (sourced): malware scanning is **not** free during the first 30-day trial — it is charged from day one; it supports Azure Blob Storage only; and it is not available on Defender for Storage (classic). The monthly cap is the main cost control — set it per storage account to bound spend. ([pricing page](https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/))

Cost sketch: at ~$0.15/GB, scanning 1 TB of uploads in a month is roughly $150 in scanning, plus the ~$10 account fee. Large files are the cost driver — the per-blob 50 GB limit and the monthly cap both bound exposure.

## Operational considerations

- **Link lifecycle** — links are single-use and expire at 48 hours; the state store enforces one upload per ID and rejects reuse. Expired or unused records are cleaned up on a schedule.
- **Blocked files** — on a malicious verdict, the router quarantines or deletes the blob, marks the ID `blocked`, and raises an alert. Clean-up of quarantined malicious files follows a retention policy.
- **Large files** — files above Defender's 50 GB per-blob limit are not scanned; decide whether to reject them at upload (size filter on the SAS/portal) or route them to the custom-engine path.
- **Monitoring** — alert on the monthly scanning cap approaching its limit (scanning silently halts once reached), on blocked-file events, and on files stuck in `pending`/`uploaded` beyond an expected window.
- **Cost control** — set the per-account monthly cap deliberately; it is the primary guardrail against runaway scanning spend.

## Open decisions

- [ ] CDR engine choice (built in-house vs third party) and which file types it must handle.
- [ ] Partner auth: static password vs one-time code (OTP), and the password delivery channel (same email vs out-of-band).
- [ ] Maximum accepted file size, and how files over Defender's 50 GB per-blob limit are handled.
- [ ] Retention periods for quarantined (clean and malicious) files.
- [ ] Interface contract with the downstream process that reads `save_blob` (naming, trigger, metadata).
- [ ] Any accreditation or assurance constraints that limit which Azure components are permitted.

## Acronyms

| Acronym | Meaning |
| --- | --- |
| API | Application Programming Interface |
| AV | Antivirus |
| CDR | Content Disarm and Reconstruction |
| DB | Database |
| GB | Gigabyte |
| ID | Identifier |
| OTP | One-Time Password |
| RBAC | Role-Based Access Control |
| SAS | Shared Access Signature |
| SSO | Single Sign-On |
| TB | Terabyte |
