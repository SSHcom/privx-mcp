# PrivX MCP Server on Amazon EKS

End-to-end guide for deploying the PrivX MCP server to an EKS cluster behind an
AWS Application Load Balancer (ALB) with ACM TLS termination and Microsoft Entra
ID (Azure AD) OAuth. It includes the exact commands used and a
[Troubleshooting](#troubleshooting) section documenting every issue hit during a
real bring-up and how each was resolved.

The generic, cloud-agnostic manifests and their reference are in
[README.md](./README.md). This document is the AWS/ALB-specific path (Path A).

## Architecture

```
Kiro (MCP client)
   │  HTTPS
   ▼
Route 53  (privx-mcp.privxssh.com  ALIAS ─►  ALB)
   │
   ▼
AWS ALB  (TLS terminated with ACM cert, HTTPS:443)
   │  HTTP:8181  (plain, in-VPC)
   ▼
Service (ClusterIP :8181) ─► Deployment pod (privx-mcp-server)
   │
   ▼
PrivX API  (per-user, via minted JWT)

OAuth: Entra ID (tenant sshdemo.net) issues tokens; the MCP server proxies
OAuth discovery so Kiro can use DCR and reach Entra.
```

## Prerequisites

- An EKS cluster and `kubectl` context pointing at it.
- `aws`, `eksctl`, `helm`, `docker` (with buildx) installed.
- A registry (ECR) the cluster can pull from.
- A public DNS zone in Route 53 (here: `privxssh.com`).
- An Entra ID app registration for the MCP server (details in
  [Entra configuration](#entra-configuration)).

Set these once and reuse them in the commands below:

```bash
export AWS_REGION=eu-north-1
export CLUSTER=<your-cluster-name>
export ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export ECR=$ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com
export HOST=privx-mcp.privxssh.com
```

---

## Step 1 — Point kubectl at the cluster

```bash
aws eks update-kubeconfig --name $CLUSTER --region $AWS_REGION
kubectl get nodes -o wide
```

Note the node **architecture** (`ARCH` column). The Docker image must match it
(see Step 3). Nodes used here were `amd64`.

## Step 2 — Install the AWS Load Balancer Controller

A fresh cluster has no ingress controller; the ALB Ingress does nothing without
it.

```bash
# 2a. IAM OIDC provider (idempotent)
eksctl utils associate-iam-oidc-provider --cluster $CLUSTER --region $AWS_REGION --approve

# 2b. IAM policy for the controller.
# This policy is AWS-owned and versioned with the controller, so it is fetched
# fresh rather than vendored in the repo (it is gitignored — see .gitignore).
# Run this from /tmp or the repo root; the file is transient.
curl -o alb-iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json
aws iam create-policy --policy-name AWSLoadBalancerControllerIAMPolicy --policy-document file://alb-iam-policy.json

# 2c. IRSA service account
eksctl create iamserviceaccount \
  --cluster $CLUSTER --region $AWS_REGION \
  --namespace kube-system --name aws-load-balancer-controller \
  --attach-policy-arn arn:aws:iam::$ACCOUNT:policy/AWSLoadBalancerControllerIAMPolicy \
  --approve

# 2d. Install the controller (set vpcId + region explicitly — see Troubleshooting #1)
VPC_ID=$(aws eks describe-cluster --name $CLUSTER --region $AWS_REGION \
  --query 'cluster.resourcesVpcConfig.vpcId' --output text)

helm repo add eks https://aws.github.io/eks-charts && helm repo update
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=$CLUSTER \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set region=$AWS_REGION \
  --set vpcId=$VPC_ID

# 2e. Verify
kubectl -n kube-system rollout status deploy/aws-load-balancer-controller
```

Also confirm public subnets are tagged for ALB discovery: `kubernetes.io/role/elb=1`
and `kubernetes.io/cluster/<cluster-name>=shared|owned` (eksctl clusters usually
have these).

## Step 3 — Build and push the image to ECR

```bash
aws ecr create-repository --repository-name privx-mcp-server --region $AWS_REGION 2>/dev/null || true
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR

# Build for the node architecture. Nodes here are amd64; on an arm64 (Apple
# Silicon) workstation you MUST cross-build with buildx or the build fails (see
# Troubleshooting #3), and pushing an arm64 image to amd64 nodes CrashLoops.
docker buildx build --platform linux/amd64 \
  -f deploy/docker/Dockerfile.glibc \
  -t $ECR/privx-mcp-server:v1 . --load

docker push $ECR/privx-mcp-server:v1
```

Use a fresh tag on each rebuild (`v2`, `v3`, …). With `imagePullPolicy: IfNotPresent`,
reusing a tag can keep a stale cached image on the node.

## Step 4 — ACM certificate

Request (or confirm) a certificate in the **same region** as the cluster,
covering the host, and complete DNS validation before use (see Troubleshooting #4).

```bash
aws acm request-certificate --domain-name $HOST --validation-method DNS --region $AWS_REGION
# Complete DNS validation in ACM/Route 53, then grab the ARN once ISSUED:
aws acm list-certificates --region $AWS_REGION
```

## Step 5 — Fill in the manifests

Edit placeholders:

- `deploy/k8s/deployment.yaml` → `image:` → `$ECR/privx-mcp-server:v1`
- `deploy/k8s/configmap.yaml` → `SERVER_PUBLIC_URL`, `PRIVX_*`, `OAUTH_*` (see
  [ConfigMap values](#configmap-values-used) below)
- `deploy/k8s/ingress-alb.yaml` → `certificate-arn` (from Step 4) and the host

**The Ingress host, `SERVER_PUBLIC_URL`, and the Entra App ID URI / audience must
all match** or OAuth breaks. See Troubleshooting #6–#8.

### ConfigMap values used

```yaml
SERVER_PUBLIC_URL: "https://privx-mcp.privxssh.com"
SERVER_LISTEN_ADDR: ":8181"
OAUTH_ISSUER_URL: "https://sts.windows.net/<tenant-id>/"
# Comma-separated STRING, not a YAML list (see Troubleshooting #5). Must include
# the API scope so Entra gets a non-empty scope.
OAUTH_SCOPES: "openid,profile,offline_access,https://privx-mcp.privxssh.com/mcp/kk-privx-mcp-k8s-scope"
OAUTH_AUDIENCE: "https://privx-mcp.privxssh.com/mcp"
OAUTH_ID_CLAIM_FIELD: "upn"
OAUTH_ID_MAPPING_RULE: "as-is"
```

Note: no `:8181` in `OAUTH_AUDIENCE`/scope — TLS terminates on the ALB at 443 and
clients use the host with no port.

## Step 6 — Namespace and Secret

The Secret holds the RSA signing key (mounted as a file) plus the PrivX API
secrets and the OAuth DCR stub client id/secret (injected via `envFrom`).

```bash
kubectl apply -f deploy/k8s/namespace.yaml

kubectl -n privx-mcp create secret generic privx-mcp-secret \
  --from-file=private-key.pem=/path/to/private-key.pem \
  --from-literal=PRIVX_API_OAUTH_CLIENT_SECRET='...' \
  --from-literal=PRIVX_API_CLIENT_ID='...' \
  --from-literal=PRIVX_API_CLIENT_SECRET='...' \
  --from-literal=OAUTH_DCR_STUB_CLIENT_ID='<entra-client-id>' \
  --from-literal=OAUTH_DCR_STUB_CLIENT_SECRET='<entra-client-secret>'
```

`OAUTH_DCR_STUB_CLIENT_ID` being set is what enables the OAuth-metadata proxy and
the `/register` DCR stub on the server.

## Step 7 — Apply the workload

```bash
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/ingress-alb.yaml     # the ALB variant, not ingress.yaml
```

## Step 8 — Verify in layers

Test each layer so a failure is isolated to one place.

```bash
# Pod healthy
kubectl -n privx-mcp rollout status deploy/privx-mcp-server
kubectl -n privx-mcp logs deploy/privx-mcp-server

# App works INSIDE the cluster (bypasses ALB/DNS/TLS) — highest-value test
kubectl -n privx-mcp port-forward deploy/privx-mcp-server 8181:8181
# other shell:
curl -s http://localhost:8181/.well-known/oauth-protected-resource
# expect: {"resource":"https://privx-mcp.privxssh.com/mcp","authorization_servers":[...]}

# ALB provisioned (wait a few minutes for ADDRESS)
kubectl -n privx-mcp get ingress privx-mcp-server
kubectl -n privx-mcp describe ingress privx-mcp-server | grep -A5 Events
```

### DNS: point the host at the ALB

```bash
# ALB DNS name + its hosted zone id (for the alias)
aws elbv2 describe-load-balancers --region $AWS_REGION \
  --query "LoadBalancers[?contains(DNSName,'privxmcp')].{DNS:DNSName,ZoneId:CanonicalHostedZoneId}" \
  --output table
```

In Route 53 (`privxssh.com` zone) add an **A record (Alias)**:
`privx-mcp.privxssh.com` → the ALB DNS name.

```bash
# Verify DNS + public HTTPS
dig +short privx-mcp.privxssh.com
curl -s https://privx-mcp.privxssh.com/.well-known/oauth-protected-resource
```

### Target health

```bash
TG=$(aws elbv2 describe-target-groups --region $AWS_REGION \
  --query "TargetGroups[?contains(TargetGroupName,'privxmcp')].TargetGroupArn" --output text)
aws elbv2 describe-target-health --region $AWS_REGION --target-group-arn $TG
# expect: TargetHealth.State = healthy
```

The target group health check uses `/.well-known/oauth-protected-resource`
(a public GET returning 200), not `/` — see Troubleshooting #9.

### Verify the OAuth metadata the client will read

```bash
curl -s https://privx-mcp.privxssh.com/.well-known/oauth-authorization-server \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('issuer:', d['issuer']); print('scopes:', d['scopes_supported'])"
# expect:
#   issuer: https://privx-mcp.privxssh.com
#   scopes: [..., https://privx-mcp.privxssh.com/mcp/kk-privx-mcp-k8s-scope]
```

## Step 9 — Connect Kiro

`~/.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "privx-mcp": {
      "url": "https://privx-mcp.privxssh.com/mcp",
      "oauthScopes": [
        "openid",
        "profile",
        "offline_access",
        "https://privx-mcp.privxssh.com/mcp/kk-privx-mcp-k8s-scope"
      ],
      "disabled": false,
      "disabledTools": []
    }
  }
}
```

After changing OAuth-related config, fully **remove and re-add** the server (or
restart Kiro) so it re-runs discovery/registration instead of replaying a cached
authorize request (see Troubleshooting #10).

---

## Entra configuration

In the `sshdemo.net` tenant, on the MCP server app registration:

1. **Expose an API**
   - Application ID URI: `https://privx-mcp.privxssh.com/mcp`
     - Entra only accepts this if `privxssh.com` (or the subdomain) is a
       **verified domain** in the tenant. If it is not verified, either verify
       it (Entra ID → Custom domain names → add + TXT record in Route 53) or use
       the `api://<client-id>` form instead and set `OAUTH_AUDIENCE` /
       `OAUTH_SCOPES` to that (see Troubleshooting #7).
   - Add a scope, e.g. `kk-privx-mcp-k8s-scope` → full scope
     `https://privx-mcp.privxssh.com/mcp/kk-privx-mcp-k8s-scope`.
2. **API permissions** — the client app needs delegated permission to that scope,
   with **admin consent granted**.
3. **Authentication / redirect URIs** — allow the loopback callback Kiro uses
   (`http://localhost:<port>/oauth/callback`).

---

## Troubleshooting

Issues encountered during bring-up, in the order they appeared.

### 1. ALB controller CrashLoopBackOff — "failed to get VPC ID … ec2imds … context deadline exceeded"

The controller tried to discover the VPC via EC2 instance metadata (IMDS) and
timed out (Fargate has no IMDS; on EC2 the IMDS hop limit can block pods).

**Fix:** install the controller with `vpcId` and `region` set explicitly so it
never calls IMDS (Step 2d). Also verify the IRSA service account has the
`eks.amazonaws.com/role-arn` annotation.

### 2. `docker login` → "malformed HTTP Authorization header" against registry-1.docker.io

The `$ECR` variable was empty, so `docker login` defaulted to Docker Hub.

**Fix:** re-export `ACCOUNT`/`AWS_REGION`/`ECR` in the current shell, confirm
`echo $ECR` prints the ECR host, then log in.

### 3. Image build fails — `gcc: error: unrecognized command-line option '-m64'`

Building on an arm64 (Apple Silicon) Mac: the Dockerfile downloads the amd64 Go
toolchain, which emits x86 flags that the arm64 gcc rejects.

**Fix:** build explicitly for the node architecture with buildx:
`docker buildx build --platform linux/amd64 ...`. (Nodes here are amd64; never
push an arm64 image to amd64 nodes — it CrashLoops with "exec format error".)

### 4. Ingress stuck, no ADDRESS — "UnsupportedCertificate … must have a fully-qualified domain name, a supported signature, and a supported key size"

The ALB could not attach the ACM certificate — almost always because the cert was
not yet `ISSUED` (DNS validation incomplete), or the domain/key type was wrong.

**Fix:** ensure the ACM cert is `ISSUED`, covers `privx-mcp.privxssh.com`, is in
the cluster region, and uses a supported key (RSA-2048). The controller retries
automatically; once valid it creates the 443 listener and the Ingress gets an
ADDRESS.

### 5. `kubectl apply configmap` — "cannot unmarshal array into Go struct field ConfigMap.data of type string"

`OAUTH_SCOPES` had been written as a YAML list `["openid", ...]`. ConfigMap
`data` values must be strings.

**Fix:** make it a quoted comma-separated string:
`OAUTH_SCOPES: "openid,profile,offline_access,https://privx-mcp.privxssh.com/mcp/kk-privx-mcp-k8s-scope"`.
(Also removed a stray `:8181` from the audience/scope — TLS is on 443.)

### 6. Kiro connect fails — "Issuer mismatch in authorization server metadata (RFC 8414 §3.3): expected https://privx-mcp.privxssh.com, received https://login.microsoftonline.com/<tenant>/v2.0"

The server proxies Entra's OAuth metadata. Because the protected-resource
metadata advertises the server's own URL as the authorization server (to route
DCR through `/register`), RFC 8414 §3.3 requires the metadata `issuer` to equal
that URL — but the proxy was returning Entra's issuer verbatim.

**Fix (code):** the `/.well-known/oauth-authorization-server` handler rewrites
`issuer` to `SERVER_PUBLIC_URL`. Rebuild + roll the image, then confirm:
`curl … /.well-known/oauth-authorization-server` shows
`issuer: https://privx-mcp.privxssh.com`.

### 7. Entra — "Values of IdentifierUris property must use a verified domain of the organization or its subdomain: https://privx-mcp.privxssh.com/mcp"

Entra rejects an Application ID URI on an unverified domain. `privxssh.com` was
not (yet) verified in the `sshdemo.net` tenant.

**Fix options:**
- Verify `privxssh.com` (or subdomain) in Entra (Custom domain names + Route 53
  TXT), then the `https://privx-mcp.privxssh.com/mcp` App ID URI is accepted — this
  is what was ultimately done.
- Or use `api://<client-id>` as the App ID URI and set `OAUTH_AUDIENCE` /
  `OAUTH_SCOPES` to `api://<client-id>` and `api://<client-id>/<scope>`. The
  App ID URI does not have to equal the hosting URL; `SERVER_PUBLIC_URL` stays the
  real host either way.

### 8. Entra sign-in — "AADSTS900144: The request body must contain the following parameter: 'scope'"

The authorize request reached Entra with no `scope`. The server advertises scopes
via discovery `scopes_supported` and the DCR `/register` response — but the
metadata proxy was only filling `scopes_supported` as a *fallback* when the
upstream omitted it. Entra always sends generic scopes
(`openid profile email offline_access`), so the configured API scope was never
advertised.

**Fix (code):** when `OAUTH_SCOPES` is configured, the proxy **overrides**
`scopes_supported` (the configured list carries the API scope needed for the
right audience) rather than only filling when absent. Rebuild + roll, then confirm
the API scope appears in `scopes_supported` and in the `/register` response.

If the client still sends an empty scope, set `oauthScopes` in `mcp.json`
(Step 9) and fully re-add the server — this forces Kiro to request the scope
regardless of discovery/DCR.

### 9. ALB target-group health check

The app has no `/healthz`. The default ALB check hits `/` and expects 200, but
`/` returns 404/401, marking targets unhealthy → the ALB serves 503.

**Fix:** the ALB Ingress sets `healthcheck-path` to
`/.well-known/oauth-protected-resource` (public GET, returns 200) with
`success-codes: 200`.

### 10. "Need admin approval" / repeated consent, and the `prompt=consent` workaround

Kiro sends `prompt=consent` on the authorize request. With `prompt=consent`,
Entra re-runs consent every time and can hard-block with an admin-approval wall
even when consent was already granted.

**Proper fix:** grant **admin consent** for the app once
(Entra → App registrations → API permissions → *Grant admin consent for
\<tenant\>*). After that, sign-in succeeds without prompting.

**Immediate workaround (used during testing):** when the consent/admin-approval
page appears, copy the full authorize URL from the browser address bar, delete
the `prompt=consent&` (or `&prompt=consent`) parameter, and load the edited URL.
Because valid consent already exists, Entra completes the sign-in and returns the
authorization code to Kiro's loopback redirect. Example — change:

```
https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize?response_type=code&client_id=<id>&...&scope=openid%20profile%20offline_access%20https%3A%2F%2Fprivx-mcp.privxssh.com%2Fmcp%2Fkk-privx-mcp-k8s-scope&prompt=consent&resource=...
```

to (remove `prompt=consent&`):

```
https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize?response_type=code&client_id=<id>&...&scope=openid%20profile%20offline_access%20https%3A%2F%2Fprivx-mcp.privxssh.com%2Fmcp%2Fkk-privx-mcp-k8s-scope&resource=...
```

This is a per-login manual step; it does not persist. Prefer granting admin
consent so no URL editing is needed. `prompt=consent` is sent by the client and
is not configurable from `mcp.json`.

---

## Redeploy after a code or config change

```bash
# Rebuild with a new tag, push, and roll
docker buildx build --platform linux/amd64 -f deploy/docker/Dockerfile.glibc \
  -t $ECR/privx-mcp-server:v2 . --load
docker push $ECR/privx-mcp-server:v2

kubectl -n privx-mcp set image deploy/privx-mcp-server privx-mcp-server=$ECR/privx-mcp-server:v2
kubectl -n privx-mcp rollout status deploy/privx-mcp-server

# Config-only change:
kubectl apply -f deploy/k8s/configmap.yaml
kubectl -n privx-mcp rollout restart deploy/privx-mcp-server
```

## Teardown

```bash
kubectl delete -f deploy/k8s/ingress-alb.yaml   # deletes the ALB
kubectl delete -f deploy/k8s/service.yaml
kubectl delete -f deploy/k8s/deployment.yaml
kubectl delete -f deploy/k8s/configmap.yaml
kubectl -n privx-mcp delete secret privx-mcp-secret
kubectl delete -f deploy/k8s/namespace.yaml
# Optionally: uninstall the ALB controller, delete the ECR repo and ACM cert.
```
