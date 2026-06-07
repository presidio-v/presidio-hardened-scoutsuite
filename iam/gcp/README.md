# GCP least-privilege audit identity

ScoutSuite audits GCP through a **service account** with read-only access at the
**organization** (or single-project) scope. Grant exactly that — never an
`Owner`/`Editor` primitive role, and never a downloadable service-account key if
you can avoid it.

## Recommended setup

1. **Create a dedicated service account** for the audit:

   ```bash
   gcloud iam service-accounts create presidio-scout-auditor \
     --display-name "Presidio Scout Auditor"
   SA=presidio-scout-auditor@REPLACE_PROJECT_ID.iam.gserviceaccount.com
   ```

2. **Grant read-only access.** The simplest least-privilege option uses the two
   Google-managed read roles at the org scope (covers the bulk of what ScoutSuite
   reads, no maintenance):

   ```bash
   ORG=organizations/REPLACE_ORG_ID
   gcloud organizations add-iam-policy-binding REPLACE_ORG_ID \
     --member "serviceAccount:$SA" --role roles/viewer
   gcloud organizations add-iam-policy-binding REPLACE_ORG_ID \
     --member "serviceAccount:$SA" --role roles/iam.securityReviewer
   ```

   Want a tighter, explicit permission set? Use the custom role in
   [`presidio-scout-auditor-role.yaml`](./presidio-scout-auditor-role.yaml),
   which lists only the `*.list`/`*.get`/`*.getIamPolicy` permissions ScoutSuite
   needs and nothing that returns secret payloads:

   ```bash
   gcloud iam roles create presidioScoutAuditor \
     --organization REPLACE_ORG_ID \
     --file presidio-scout-auditor-role.yaml
   gcloud organizations add-iam-policy-binding REPLACE_ORG_ID \
     --member "serviceAccount:$SA" \
     --role organizations/REPLACE_ORG_ID/roles/presidioScoutAuditor
   ```

3. **Authenticate without a long-lived key.** Prefer **service-account
   impersonation** over a downloaded JSON key:

   ```bash
   gcloud auth application-default login \
     --impersonate-service-account "$SA"
   ```

   The resulting ADC / `CLOUDSDK_*` / `GOOGLE_*` env vars reach ScoutSuite through
   the launcher's cloud-credential allowlist. If you must use a key file, mount it
   read-only and point `GOOGLE_APPLICATION_CREDENTIALS` at it.

Then run:

```bash
presidio-scout gcp
```

> The custom role deliberately omits `*.getIamPolicy` on resources whose policy
> ScoutSuite does not read, and every secret-bearing permission (e.g.
> `secretmanager.versions.access`, `cloudkms.cryptoKeyVersions.useToDecrypt`). If
> a future ScoutSuite version reads a new resource, add the specific
> `*.list`/`*.get` permission rather than swapping in a broader predefined role.
