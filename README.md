# talos-audit-proxy

Transparent audit gateway in front of the Talos Machine API. It records who changed what on Talos nodes, by name, without slowing changes down and without requiring a GitOps review cycle.

## Problem

The company needs to see which changes operators make to Talos node configuration, and who made each one. Talos itself cannot answer this: the API authenticates a client certificate, not a person, and `apid` logs are thin and per-node. Authorship has to be established one layer above the node.

## Approach

Interception sits at the Talos gRPC API layer, not around any one CLI. Because `talosctl`, `talm`, and any code built on `machinery` all speak the same `machine.MachineService` API over mTLS using the same `talosconfig`, a single proxy covers every one of them with no tool-specific code. `talm apply`, for example, issues one `ApplyConfiguration` RPC per node with the composed config, exactly like `talosctl`, so it is audited the same way.

### Components

1. **Issuer** (off-the-shelf: step-ca with an OIDC provisioner, or an equivalent). An operator logs in through the IdP and receives a short-lived client certificate whose `CN` is their identity. There is no native OIDC in the Talos API, so identity is bound at certificate-issue time, not per call.
2. **Audit proxy** (this repo). Terminates the operator's mTLS, reads the `CN` (the "who"), inspects the `machine.MachineService` method and, for `ApplyConfiguration`, the machine config in the request body (the "what"), writes an audit record, and forwards the call to the real `apid` using its own service `os:admin` certificate.
3. **The one admin credential** lives only in the proxy. Operators never hold a Talos admin cert.

### Why the operator cert is signed by the proxy CA, not the Talos OS CA

`apid` never sees the operator's certificate: the proxy terminates the connection and dials the node itself. So the operator-to-proxy leg can use a separate CA, which keeps the Talos OS CA key out of the issuer and makes revocation ours to control. Talos `apid` has no CRL; a short TTL plus a CRL on the proxy CA gives immediate revocation without rotating the Talos CA.

### Non-goals

- Not a review/approval gate: changes apply immediately.
- Not a replacement for drift detection: periodically snapshotting `talosctl get machineconfig` against an expected baseline still catches any change that bypassed the proxy, and remains the check that the path is sealed.

## Method classification

`internal/audit` classifies each MachineService method so the proxy records state-changing and credential/data-egress calls while forwarding plain diagnostics silently. The method table is taken verbatim from `siderolabs/talos/pkg/machinery` v1.14.0. An unknown method (e.g. from a newer Talos version) is audited, never dropped.

## Status

Early scaffolding.

- [x] `internal/audit`: method classifier + tests
- [ ] mTLS termination and `CN` extraction
- [ ] gRPC transparent director to upstream `apid`
- [ ] `ApplyConfiguration` body capture into audit records
- [ ] audit sink (log/stream) and record schema
- [ ] deployment manifests
