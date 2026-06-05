# AWS least-privilege audit role

ScoutSuite needs broad **read-only** access. The least-privilege, AWS-supported
way to grant it is a dedicated role assumed from your auditor account, with
**no write/mutate permissions**.

## Recommended setup

1. **Attach the two AWS-managed read-only policies** (these cover the bulk of
   what ScoutSuite reads):
   - `arn:aws:iam::aws:policy/SecurityAudit`
   - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

2. **Attach the supplemental policy** in this directory
   ([`least-privilege-audit-policy.json`](./least-privilege-audit-policy.json))
   for the handful of read APIs the managed policies miss. It also carries an
   explicit **`Deny` on anything that isn't an allowlisted read/describe/list
   action**, so even if a broader policy is attached by mistake, this role can
   never mutate your account.

3. **Use the hardened trust policy**
   ([`trust-policy.json`](./trust-policy.json)): assumption requires **MFA** and
   a **random `ExternalId`** (defense against the confused-deputy problem).
   Replace `REPLACE_AUDITOR_ACCOUNT_ID` and `REPLACE_WITH_RANDOM_EXTERNAL_ID`.

```bash
aws iam create-role \
  --role-name PresidioScoutAuditor \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy --role-name PresidioScoutAuditor \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-role-policy --role-name PresidioScoutAuditor \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
aws iam put-role-policy --role-name PresidioScoutAuditor \
  --policy-name PresidioScoutSupplemental \
  --policy-document file://least-privilege-audit-policy.json
```

Then run:

```bash
presidio-scout aws -- --profile your-auditor-profile
```

> The `Deny` statement is deliberately conservative. If a future ScoutSuite
> version reads a new service, add the specific `Describe*/Get*/List*` action to
> the `NotAction` list rather than weakening the deny.
