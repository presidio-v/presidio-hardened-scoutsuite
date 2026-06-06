# Azure least-privilege audit identity

ScoutSuite audits Azure through an **Azure AD service principal** with broad
**read-only** access to the subscription, plus a small amount of **directory**
read for the Azure AD (Entra ID) coverage. Grant exactly that and nothing else.

## Recommended setup

1. **Create a dedicated service principal** for the audit (no client secret reuse
   with other tooling):

   ```bash
   az ad sp create-for-rbac --name presidio-scout-auditor --skip-assignment
   ```

   Record the `appId`, `password`, and `tenant` — ScoutSuite consumes them as
   `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID` (all reach the
   child via the launcher's `AZURE_` env allowlist).

2. **Assign read-only control-plane access.** Use the built-in roles — they are
   already least-privilege for reads and need no maintenance:

   ```bash
   SP=$(az ad sp list --display-name presidio-scout-auditor --query "[0].id" -o tsv)
   SUB=/subscriptions/REPLACE_SUBSCRIPTION_ID

   az role assignment create --assignee-object-id "$SP" \
     --assignee-principal-type ServicePrincipal \
     --role "Reader" --scope "$SUB"
   az role assignment create --assignee-object-id "$SP" \
     --assignee-principal-type ServicePrincipal \
     --role "Security Reader" --scope "$SUB"
   ```

   Prefer a **custom** role instead? Use
   [`presidio-scout-reader-role.json`](./presidio-scout-reader-role.json): it
   allows only `*/read`, omits every `dataAction` (so secret/key *values* in Key
   Vault and storage keys are never readable), and explicitly excludes the few
   read-shaped actions that return live credentials. Create and assign it:

   ```bash
   az role definition create --role-definition presidio-scout-reader-role.json
   az role assignment create --assignee-object-id "$SP" \
     --assignee-principal-type ServicePrincipal \
     --role "PresidioScoutAuditor" --scope "$SUB"
   ```

3. **Grant minimal directory read** for the Azure AD findings. Assign the
   **Global Reader** Entra role (read-only across the directory) to the service
   principal, or the narrower Microsoft Graph application permissions
   `Directory.Read.All` + `Policy.Read.All` with admin consent. Skip this only if
   you run with `--services` scoped to exclude `aad`.

Then run:

```bash
presidio-scout azure -- --user-account
```

> The custom role allows `*/read` rather than enumerating thousands of
> `Microsoft.*/read` actions, but **all `dataActions` are empty**, so it can read
> resource *configuration* and never resource *data* (blobs, secret values, keys).
> If a future ScoutSuite version needs a specific dataAction, add that one action
> deliberately rather than widening `DataActions` to `*`.
