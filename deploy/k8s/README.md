# Kubernetes deployment

Portable manifests for running the PrivX MCP server on Kubernetes. Tested target
is Amazon EKS, but nothing here is EKS-specific: the same manifests run on GKE,
AKS, or on-prem clusters by swapping the Ingress class/annotations.

> **Deploying on EKS?** See [EKS-DEPLOYMENT.md](./EKS-DEPLOYMENT.md) for the full
> AWS/ALB walkthrough with exact commands, Entra OAuth setup, and a
> troubleshooting log of every issue hit during a real bring-up (including the
> `prompt=consent` sign-in workaround).

## Contents

| File | Purpose |
| ---- | ------- |
| `namespace.yaml` | `privx-mcp` namespace |
| `configmap.yaml` | Non-secret configuration (server, PrivX, OAuth, permissions) |
| `secret.example.yaml` | Template for the RSA signing key + API secrets — **do not commit real values** |
| `deployment.yaml` | The server Deployment (non-root, read-only rootfs, TCP probes) |
| `service.yaml` | ClusterIP Service on port 8181 |
| `ingress.yaml` | TLS termination + host routing (nginx/cert-manager by default) |
| `ingress-alb.yaml` | AWS ALB variant (ACM TLS on 443) — used by the EKS guide |
| `EKS-DEPLOYMENT.md` | Full Amazon EKS + ALB deployment guide and troubleshooting log |

## How config flows

The server reads all configuration from environment variables (load order: TOML
file if set → built-in defaults → env vars → validation). In these manifests:

- **Non-secret** env comes from `configmap.yaml` via `envFrom`.
- **Secret** env (`PRIVX_API_*`, optional DCR stub secret) comes from the Secret via `envFrom`.
- The **RSA signing key** is mounted as a file from the Secret at
  `/etc/privx-mcp/private-key.pem`; `PRIVX_RSA_KEY_FILE` in the ConfigMap points there.
- **TLS** is terminated at the Ingress. The pod listens plain HTTP on `:8181`.

## Prerequisites

- A cluster and `kubectl` context pointing at it.
- An ingress controller (ingress-nginx assumed by default; ALB on EKS supported — see below).
- A DNS record for your public host pointing at the ingress load balancer.
- A container image pushed to a registry the cluster can pull from.

## 1. Build and push the image

```bash
# From the repo root. glibc image (see deploy/docker/Dockerfile.glibc):
task image:glibc                      # builds privx-mcp-server:dev

docker tag privx-mcp-server:dev <registry>/privx-mcp-server:<tag>
docker push <registry>/privx-mcp-server:<tag>
```

On EKS, `<registry>` is typically ECR, e.g.
`<account>.dkr.ecr.<region>.amazonaws.com/privx-mcp-server`. Create the repo and
`aws ecr get-login-password ... | docker login ...` first.

## 2. Fill in the placeholders

Every value marked `REPLACE_ME` must be set before applying. At minimum:

- `deployment.yaml` → `image:` → your `<registry>/privx-mcp-server:<tag>`
- `configmap.yaml` → `SERVER_PUBLIC_URL`, `PRIVX_PRIVX_BASE_URL`, `PRIVX_RSA_KEY_ID`,
  `PRIVX_AUDIENCE`, `OAUTH_ISSUER_URL`, `OAUTH_AUDIENCE`, `OAUTH_SCOPES`, etc.
- `ingress.yaml` → the host (both under `tls.hosts` and `rules.host`)

**The Ingress host, `SERVER_PUBLIC_URL`, and the OAuth resource/audience must all
agree.** The MCP OAuth discovery flow derives the resource identifier from
`SERVER_PUBLIC_URL`; a mismatch breaks client sign-in.

## 3. Create the Secret

Do **not** apply `secret.example.yaml` as-is. Either create the Secret
imperatively (keeps the key out of git):

```bash
kubectl -n privx-mcp create secret generic privx-mcp-secret \
  --from-file=private-key.pem=/path/to/private-key.pem \
  --from-literal=PRIVX_API_OAUTH_CLIENT_SECRET='...' \
  --from-literal=PRIVX_API_CLIENT_ID='...' \
  --from-literal=PRIVX_API_CLIENT_SECRET='...'
  # add --from-literal=OAUTH_DCR_STUB_CLIENT_SECRET='...' if you use the DCR stub
```

…or copy `secret.example.yaml` to `secret.yaml`, fill it in, and apply that.
`secret.yaml` should be gitignored — see the note at the end.

> The namespace must exist before the Secret. Apply `namespace.yaml` first
> (step 4 does this), or add `-n privx-mcp` after creating the namespace.

## 4. Apply the manifests

```bash
kubectl apply -f deploy/k8s/namespace.yaml
# create the Secret (step 3) now, then:
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/ingress.yaml
```

Or apply the whole directory at once (after the Secret exists):

```bash
kubectl apply -f deploy/k8s/
```

`secret.example.yaml` is a template; if you keep a real `secret.yaml`, applying
the directory will include it. `secret.example.yaml` has placeholder values and
applying it will not produce a working server.

## 5. Verify

```bash
kubectl -n privx-mcp rollout status deploy/privx-mcp-server
kubectl -n privx-mcp get pods,svc,ingress

# Once DNS + TLS are up, discovery should return your public URL as issuer:
curl -s https://<your-host>/.well-known/oauth-protected-resource
```

## Cloud-specific notes

### Amazon EKS (ALB)

Use the dedicated ALB manifest `ingress-alb.yaml` (already configured for the AWS
Load Balancer Controller: `ingressClassName: alb`, ACM TLS on 443, TCP-free health
check on the public metadata route). Set the `certificate-arn` and host, then
`kubectl apply -f deploy/k8s/ingress-alb.yaml`.

For the complete step-by-step (controller install, ECR build/push, ACM, Route 53
alias, Entra OAuth, and every issue hit with its fix), follow
**[EKS-DEPLOYMENT.md](./EKS-DEPLOYMENT.md)**.

Ensure the AWS Load Balancer Controller is installed and the nodes/pods have IAM
permission to pull from ECR.

### GKE / AKS / on-prem

Any ingress controller works. Set `ingressClassName` to match your controller and
provide TLS either via cert-manager (default here) or a pre-created TLS Secret
referenced under `spec.tls.secretName`.

## Health checks

The server has no HTTP health endpoint yet, so the probes use a **TCP socket**
check against port 8181. If a `/healthz` (or similar) route is added later,
switch the `tcpSocket` probes in `deployment.yaml` to `httpGet` for a more
accurate readiness signal.

## Security notes

- The container runs as non-root (uid/gid 65532, matching the image) with a
  read-only root filesystem, no privilege escalation, and all capabilities dropped.
- Never commit real secrets. Add a gitignore entry for `deploy/k8s/secret.yaml`:

  ```
  deploy/k8s/secret.yaml
  ```

  Consider External Secrets Operator or a sealed-secrets solution for production
  rather than plaintext Secret manifests.
