# talos-audit-proxy

Transparent audit gateway in front of the Talos Machine API. It records who changed what on which Talos node, by name, without slowing changes down and without requiring a GitOps review cycle.

## Problem

The company needs to see which changes operators make to Talos node configuration, and who made each one. Talos itself cannot answer this: the API authenticates a client certificate, not a person, and `apid` logs are thin and per-node. Authorship has to be established one layer above the node.

## Covered clients

Interception sits at the Talos gRPC API layer, not around any one CLI. `talosctl`, `talm`, and any code built on `machinery` all speak the same `machine.MachineService` API over mTLS using the same `talosconfig`, so a single proxy covers every one of them with no tool-specific code. `talm apply`, for example, issues one `ApplyConfiguration` RPC per node with the composed config, exactly like `talosctl`, and is audited the same way.

## How it works

### Access issuance (once per short-lived session)

Identity is bound here, when the certificate is issued: the operator's email is taken from the certificate (an email SAN), put there from their Keycloak login. The Talos API has no native OIDC, so the person is encoded into the certificate rather than passed on each call.

```text
┌──────────────────┐   [1] OIDC login      ┌──────────────────┐
│ Operator         │───────────────────────│ Keycloak (IdP)   │
│ talosctl / talm  │   [2] ID-token        │ realm + client   │
└────────┬─────────┘                       └──────────────────┘
         │ [3] present ID-token
┌────────┴───────────────────────┐
│ Issuer: step-ca (= proxy CA)   │
│  [4] verify token, sign a      │
│      short-lived client cert:  │
│      subject = OIDC sub,       │
│      email in SAN, role in O,  │
│      TTL = minutes             │
└────────┬───────────────────────┘
         │ [5] cert written into operator talosconfig
         │     (endpoint already points at audit-proxy)
```

### Request path (every apply / reboot / etc.)

The proxy adds no delay: it records and forwards. The node reply travels back along the same path to the operator.

```text
┌──────────────────────────────┐
│ Operator: talosctl / talm     │
│ endpoint = audit-proxy        │
│ presents personal cert (mTLS) │
└───────────────┬──────────────┘
                │ [6]
┌───────────────┴───────────────────────────────────────────┐
│ AUDIT PROXY                                                │
│  [7] terminate mTLS, read email (who) and O (roles)        │
│  [8] classify method:                                      │
│        read-only            : forward, no record           │
│        mutating / sensitive : audit                        │
│        unknown              : audit (fail-safe)            │
│  [9] ApplyConfiguration: decode body, redact secrets,      │
│        hash config, read target nodes from metadata        │
│ [10] append record to logfile (fsync)                      │
└───────┬───────────────────────────────────┬───────────────┘
    [11]│ append                        [12]│ forward with
        │                                    │ proxy os:admin cert
┌───────┴────────┐              ┌────────────┴───────────────┐
│ Audit logfile  │              │ Talos control-plane apid    │
│ (JSON lines)   │              │ (real endpoint, port 50000) │
└────────────────┘              └────────────┬───────────────┘
                                         [13]│ apid routes to the
                                             │ target node by metadata
                              ┌──────────────┼──────────────┐
                        ┌─────┴─────┐  ┌──────┴────┐  ┌──────┴────┐
                        │   node1   │  │   node2   │  │   node3   │
                        └───────────┘  └───────────┘  └───────────┘
```

### What a record contains

One JSON line per audited call. The company reads who (`actor`), what (`method` plus `config` with secrets redacted), on which node (`nodes`), and when (`time`).

```json
{
  "time": "2026-10-20T10:15:04Z",
  "actor": "operator@example.com",
  "roles": ["os:admin"],
  "source": "10.0.0.5:51000",
  "method": "/machine.MachineService/ApplyConfiguration",
  "class": "mutating",
  "nodes": ["10.0.0.11"],
  "config_sha256": "9f2b1c…",
  "config": "version: v1alpha1\nmachine:\n  token: \"***REDACTED***\"\n  …",
  "dry_run": false
}
```

## Trust boundaries

| Subject | Holds | Lifetime | Revocation |
| --- | --- | --- | --- |
| Operator | personal client cert signed by the proxy CA, email in a SAN | minutes | CRL on the proxy, immediate |
| Audit proxy | the single Talos `os:admin` cert for the whole system | ordinary | proxy rotation |
| Issuer (step-ca) | the proxy CA key, not the Talos OS CA | long | its own CA |
| Nodes | port `50000` reachable only from the proxy (network policy) | permanent | firewall |

Two properties follow from this layout:

1. The Talos admin credential is never handed to people; it lives only in the proxy. A stolen operator laptop yields at most a minutes-long cert, revocable on the proxy without rotating the Talos CA.
2. The proxy cannot be bypassed. Nodes refuse a direct connection on `50000` from anywhere but the proxy, and the operator's cert is signed by the proxy CA rather than the Talos OS CA, so a node would not accept it even if reached directly.

### Why the operator cert is signed by the proxy CA, not the Talos OS CA

`apid` never sees the operator's certificate: the proxy terminates the connection and dials the node itself. So the operator-to-proxy leg can use a separate CA, which keeps the Talos OS CA key out of the issuer and makes revocation ours to control. Talos `apid` has no CRL; a short TTL plus a CRL on the proxy CA gives immediate revocation without rotating the Talos CA.

## Deployment

Status note: the proxy binary (`cmd/`), its container image, and the Kubernetes manifests are not implemented yet (see the checklist at the end). The steps below are the target runbook; the commands for Keycloak, step-ca, and talosctl are verified against upstream docs but have not been run in CI. Steps 1 to 4 (the issuer and Keycloak wiring) work today with off-the-shelf step-ca; steps 6 to 7 wait on the proxy image.

Six things get deployed. Keycloak you already run; the rest is new.

### Prerequisites

- Keycloak reachable over TLS (its discovery endpoint must be TLS-protected).
- A Kubernetes cluster to run step-ca and the proxy.
- The Talos control-plane endpoint, and the ability to mint one `os:admin` talosconfig.

### 1. Proxy CA and issuer (step-ca)

step-ca plays both roles: it is the proxy CA and the OIDC issuer. Deploy it (the `smallstep/step-certificates` Helm chart, or a container). Its CA becomes the proxy CA, so operator certificates are signed by it and never by the Talos OS CA.

### 2. Keycloak: an OIDC client for the issuer

In the realm your operators log into, create a client:

- Client ID: `step-ca`
- Access type: confidential (step-ca presents a client secret).
- Valid Redirect URIs: `http://127.0.0.1:10000`. `step` runs a local browser-login listener; pinning the port lets Keycloak match the redirect.
- Copy the generated client secret from the client's Credentials tab.

### 3. Wire the issuer to Keycloak

On step-ca, add the OIDC provisioner (the discovery path is `/realms/<realm>/.well-known/openid-configuration`; Keycloak older than v17 uses `/auth/realms/<realm>/...`):

```bash
step ca provisioner add keycloak \
  --type OIDC \
  --client-id step-ca \
  --client-secret <secret-from-keycloak> \
  --configuration-endpoint https://<keycloak-host>/realms/<realm>/.well-known/openid-configuration \
  --listen-address :10000
```

step-ca does not pick up the new provisioner until it is reloaded: send it SIGHUP or restart the process.

### 4. Operator gets a short-lived certificate

```bash
step ca certificate operator@example.com operator.crt operator.key --provisioner keycloak
```

`step` opens the browser, the operator logs into Keycloak, and `operator.crt` / `operator.key` are written. The certificate subject is the OIDC `sub` claim and the operator's email is an email SAN; the proxy reads that email SAN as the actor identity. Keep the TTL to minutes via the provisioner's claims. Confirm the cert is usable for client auth with `step certificate inspect operator.crt` (it needs the clientAuth extended key usage; set it with an x509 template on the provisioner if missing).

### 5. The proxy's Talos admin certificate

Mint the single `os:admin` talosconfig and store it as a Secret in the proxy namespace. This is the only Talos admin credential in the whole system.

```bash
talosctl config new proxy-admin.talosconfig --roles os:admin --crt-ttl 2160h
```

### 6. Deploy the proxy

The Deployment mounts:

- the `proxy-admin` talosconfig (Talos `os:admin`), used to authenticate upstream to `apid`;
- the proxy's own server certificate and key, signed by the proxy CA, that operators' `talosctl` / `talm` connect to over TLS;
- the proxy CA certificate, used as the clientCA to verify operator certificates;
- a path for the audit log (a PVC, or write to stdout and collect it in Loki).

It needs flags for the listen address, the upstream Talos control-plane endpoint (`<control-plane>:50000`), the audit log path, and the certificate and talosconfig paths above. Add a Service to expose it, and a NetworkPolicy so that the nodes' port `50000` is reachable only from the proxy pod. Without that lockdown the proxy can be bypassed and the audit trail is worthless.

### 7. Point operators at the proxy

In each operator's `talosconfig`, the endpoint becomes the proxy and the credentials are their personal cert from step 4:

```yaml
context: audited
contexts:
  audited:
    endpoints:
      - <proxy service address>
    ca: <proxy CA cert, base64>   # validates the proxy's server certificate
    crt: <operator.crt, base64>   # personal cert from step 4
    key: <operator.key, base64>
```

From here `talosctl` and `talm` work exactly as before; every mutating call is now recorded.

### 8. Drift detection (safety net)

A CronJob that snapshots `talosctl get machineconfig` per node and compares it to an expected baseline, alerting on any difference. It catches changes that reached a node without going through the proxy, and is the check that the path stayed sealed.

## Method classification

`internal/audit` classifies each MachineService method so the proxy records state-changing and credential/data-egress calls while forwarding plain diagnostics silently. The method table is taken verbatim from `siderolabs/talos/pkg/machinery` v1.14.0. An unknown method from a newer Talos version is audited, never dropped.

## Non-goals

- Not a review/approval gate: changes apply immediately.
- Not a replacement for drift detection: periodically snapshotting `talosctl get machineconfig` against an expected baseline still catches any change that bypassed the proxy, and remains the check that the path is sealed.

## Status

Early scaffolding.

- [x] `internal/audit`: method classifier + tests
- [x] audit record schema + file sink + tests
- [x] secret redaction for machine config (`internal/redact`)
- [x] deployment and Keycloak runbook (this README)
- [ ] mTLS termination and identity (email SAN) extraction
- [ ] gRPC transparent director to upstream `apid`
- [ ] `ApplyConfiguration` body capture into audit records
- [ ] `cmd/` entrypoint, `Containerfile`, and Kubernetes manifests
