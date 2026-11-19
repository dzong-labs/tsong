---
title: A replica leaves the load balancer by deregistration or by failing readiness
type: note
summary: On SIGTERM, Tsong fails readiness for health.drain, then stops accepting and finishes in-flight requests. A load balancer stops sending to a replica when the orchestrator deregisters it, or when its health check polls /health/ready.
status: evolving
created: 2026-11-16
---

# A replica leaves the load balancer by deregistration or by failing readiness

A replica that is stopping must leave the load balancer's rotation before its listeners close, or requests routed to it fail. Two mechanisms take it out: the orchestrator deregistering it, and the load balancer's health check. Tsong's drain serves the second.

## What Tsong does on SIGTERM

`tsong serve` stops on SIGTERM, which container runtimes send, or on Ctrl+C (`shutdown_signal` in `crates/tsong/src/lib.rs`). With a `[health]` listener in the bootstrap file:

1. `GET /health/ready` starts answering 503. `GET /health/live` keeps answering 200.
2. Tsong keeps serving for `health.drain`, `"00:00:05"` (5 seconds) by default.
3. The listeners stop accepting connections. Requests in flight finish, and idle keep-alive connections close.
4. The process exits with status 0 and prints `stopped`.

A second signal during the drain ends it at once. Without a `[health]` listener there is no drain, and the listeners stop at once. A request or stream that outlives the runtime's stop timeout is cut when the runtime kills the process.

## How a load balancer stops sending

**Deregistration.** Some orchestrators remove a replica from the load balancer's targets before they send SIGTERM. ECS behind a load balancer does this for a deploy, a scale-in or a replaced task. The target is deregistered first, and in-flight requests get the deregistration delay to finish. Only then does the task get SIGTERM. The health check plays no part. By the time Tsong drains, no new requests arrive.

**The health check.** Other stops reach Tsong without deregistration. Kubernetes removes the endpoint and sends SIGTERM at the same time. A container stopped by hand is never deregistered. Then only the health check moves traffic. A health check on `/health/ready` sees 503 as the drain starts, while the replica still serves. A health check on `/health/live` sees nothing until the process has exited. Until the load balancer's unhealthy threshold is reached, requests routed to the stopped replica fail.

So point the load balancer's health check at `/health/ready`. Both endpoints are cheap: each reads one flag in memory and calls no dependency.

## Settings that must line up

- `health.drain` must last at least the health check's interval times its unhealthy threshold, plus a margin. With a 10-second interval and a threshold of 2, a 5-second drain ends before the load balancer has noticed. A 25-second drain, `"00:00:25"`, covers it.
- The runtime's stop timeout must exceed `health.drain`, or the runtime kills Tsong mid-drain. `deploy/podman/run.sh` stops with a 15-second timeout against the stub's 5-second drain.
- Where the orchestrator deregisters first, its deregistration delay covers the in-flight requests. The drain then only guards against a stop that skipped deregistration.

## The two endpoints

- `/health/live`: 200 while the process runs. It is for whatever restarts a stuck process. Failing it during the drain would invite that restart mid-drain.
- `/health/ready`: 200 from the moment every listener is bound until shutdown begins, 503 otherwise. It is for whatever decides where traffic goes.

The endpoints and their listener are described in [[observability]].
