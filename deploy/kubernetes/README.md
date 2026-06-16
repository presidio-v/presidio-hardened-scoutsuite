# Kubernetes deployment

Run the hardened audit in-cluster as a `Job` (one-shot) or `CronJob`
(scheduled), under a least-privilege **workload-identity** ServiceAccount — no
long-lived cloud keys, ever. These manifests pair the signed multi-arch image
(0.11), the keyless-credentials posture (0.12), and the findings gate (0.6).

```bash
kubectl create namespace presidio-scout
kubectl apply -f serviceaccount.yaml      # annotate for your cloud first
kubectl apply -f networkpolicy.yaml
kubectl apply -f job.yaml                  # or cronjob.yaml
```

## Hardening baked in

| Control | Setting |
|---|---|
| Non-root | `runAsNonRoot: true`, uid/gid `65532` (distroless `nonroot`) |
| Immutable rootfs | `readOnlyRootFilesystem: true` (+ `emptyDir` for `/tmp`, `/report`) |
| No escalation | `allowPrivilegeEscalation: false` |
| No capabilities | `capabilities.drop: ["ALL"]` |
| Seccomp | `seccompProfile.type: RuntimeDefault` |
| No K8s API token | `automountServiceAccountToken: false` |
| Network | default-deny ingress; egress only DNS + 443 |
| Credentials | workload identity (IRSA / GKE WI / Azure WI) + `--require-short-lived-creds` |
| Result gate | `--fail-on-finding danger` → a danger finding fails the Job |

Pin the image **by digest** in production (`…@sha256:…`) and verify it first
(see the repo README, *Verifying what you pull*).

## Per-cloud workload identity

Annotate `serviceaccount.yaml` for exactly one cloud (and grant that identity
the bundled least-privilege audit role from [`iam/`](../../iam/)):

- **AWS (IRSA)** — `eks.amazonaws.com/role-arn: arn:aws:iam::<acct>:role/presidio-scoutsuite-auditor`. The EKS webhook injects a projected `sts.amazonaws.com` token; set the container `args` provider to `aws`.
- **GCP (Workload Identity)** — `iam.gke.io/gcp-service-account: …@<proj>.iam.gserviceaccount.com`; provider `gcp`. GKE WI uses the metadata server, so the NetworkPolicy leaves it reachable.
- **Azure (Workload Identity)** — `azure.workload.identity/client-id: <client-id>` and keep the pod label `azure.workload.identity/use: "true"`; provider `azure`.

## Tightening the NetworkPolicy

The baseline allows egress to `0.0.0.0/0:443`. Narrow `cidr` to your provider's
published API ranges where practical. On **EKS/AKS** (projected-token identity),
additionally block the metadata IP by replacing the HTTPS rule's `ipBlock` with
an `except: ["169.254.169.254/32"]`. Do **not** block it on **GKE** — Workload
Identity needs the metadata server.

## Keeping the report

The manifests use an `emptyDir` for `/report` (ephemeral). To retain results,
mount a `PersistentVolumeClaim` at `/report`, or add an uploader sidecar that
ships the report (and its signed integrity manifest / run attestation) to object
storage.

## Helm

A chart is provided at [`../helm/presidio-scout`](../helm/presidio-scout) with
the same hardening exposed through `values.yaml` (provider, schedule, image
digest, serviceAccount annotations, gate severity, resources).
