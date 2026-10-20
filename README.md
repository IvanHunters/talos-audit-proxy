# talos-audit-proxy

Transparent audit gateway in front of the Talos Machine API. It records who changed what on which Talos node, by name, without slowing changes down and without requiring a GitOps review cycle.

## Problem

The company needs to see which changes operators make to Talos node configuration, and who made each one. Talos itself cannot answer this: the API authenticates a client certificate, not a person, and `apid` logs are thin and per-node. Authorship has to be established one layer above the node.

## Covered clients

Interception sits at the Talos gRPC API layer, not around any one CLI. `talosctl`, `talm`, and any code built on `machinery` all speak the same `machine.MachineService` API over mTLS using the same `talosconfig`, so a single proxy covers every one of them with no tool-specific code. `talm apply`, for example, issues one `ApplyConfiguration` RPC per node with the composed config, exactly like `talosctl`, and is audited the same way.

## How it works

### Access issuance (once per short-lived session)

Identity is bound here, when the certificate is issued: the operator's `CN` is their Keycloak identity. The Talos API has no native OIDC, so the person is encoded into the certificate rather than passed on each call.

```text
┌──────────────────┐   [1] OIDC login      ┌──────────────────┐
│ Operator         │───────────────────────│ Keycloak (IdP)   │
│ talosctl / talm  │   [2] ID-token        │                  │
└────────┬─────────┘                       └──────────────────┘
         │ [3] present ID-token
┌────────┴───────────────────────┐
│ Issuer: step-ca (proxy CA)     │
│  [4] verify token, sign cert:  │
│      CN=email, O=os:admin,     │
│      TTL=minutes               │
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
│  [7] terminate mTLS, read CN (who) and O (roles)           │
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
| Operator | personal client cert signed by the proxy CA, `CN=email` | minutes | CRL on the proxy, immediate |
| Audit proxy | the single Talos `os:admin` cert for the whole system | ordinary | proxy rotation |
| Issuer (step-ca) | the proxy CA key, not the Talos OS CA | long | its own CA |
| Nodes | port `50000` reachable only from the proxy (network policy) | permanent | firewall |

Two properties follow from this layout:

1. The Talos admin credential is never handed to people; it lives only in the proxy. A stolen operator laptop yields at most a minutes-long cert, revocable on the proxy without rotating the Talos CA.
2. The proxy cannot be bypassed. Nodes refuse a direct connection on `50000` from anywhere but the proxy, and the operator's cert is signed by the proxy CA rather than the Talos OS CA, so a node would not accept it even if reached directly.

### Why the operator cert is signed by the proxy CA, not the Talos OS CA

`apid` never sees the operator's certificate: the proxy terminates the connection and dials the node itself. So the operator-to-proxy leg can use a separate CA, which keeps the Talos OS CA key out of the issuer and makes revocation ours to control. Talos `apid` has no CRL; a short TTL plus a CRL on the proxy CA gives immediate revocation without rotating the Talos CA.

## Method classification

`internal/audit` classifies each MachineService method so the proxy records state-changing and credential/data-egress calls while forwarding plain diagnostics silently. The method table is taken verbatim from `siderolabs/talos/pkg/machinery` v1.14.0. An unknown method from a newer Talos version is audited, never dropped.

## Non-goals

- Not a review/approval gate: changes apply immediately.
- Not a replacement for drift detection: periodically snapshotting `talosctl get machineconfig` against an expected baseline still catches any change that bypassed the proxy, and remains the check that the path is sealed.

## Status

Early scaffolding.

- [x] `internal/audit`: method classifier + tests
- [x] audit record schema + file sink + tests
- [ ] mTLS termination and `CN` extraction
- [ ] gRPC transparent director to upstream `apid`
- [ ] `ApplyConfiguration` body capture and secret redaction
- [ ] deployment manifests
