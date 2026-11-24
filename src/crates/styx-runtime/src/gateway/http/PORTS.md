# Streamable HTTP ownership and admission

Rust owns the Gateway HTTP adapter and uses the pinned rmcp, hyper and tower
implementations. Authentication binds an SDK session to its original verified
principal; transports never create new execution authority by themselves.

Styx does not impose counts on connections, conversations, pending calls, paired
devices, Host tasks, Browser contexts or retained operation history. No owner is
evicted to make space for another owner. The capacity figures and semaphore
partitions documented here on 2026-10-29 are obsolete; Git retains that history.
The confirmed product boundary is [REFACTOR-PLAN.md](../../../../../docs/rust-core-rewrite/REFACTOR-PLAN.md).

A conversation owns its transport and observation references. Exec tasks and
Browser sessions belong to the Host and survive conversation closure. Host Quit,
capability changes and explicit resource closure follow their existing lifecycle
owners. Session expiry/DELETE must not claim an unrelated Host resource ended.
The original supervised backend job retains its owner and lifecycle until it
actually finishes, even if its request waiter disappears.

Transport frame validation, request deadlines and the mature transport's existing
backpressure remain. A full relay channel waits for its original send reservation
within the original deadline; it does not reject by task count or resend a call.
The Host's existing lifecycle lock also waits within that deadline during physical
collection. Lock contention is not evidence of capacity exhaustion. Recheck
owner, policy and operation state before the original dispatch; never replay an
unknown operation or convert a lost reply into a known refusal.

Verify two independent conversation owners on the same Host: overlap native
window-list/tree reads, close A, then continue with B. Also verify independent
Browser contexts and a Host Exec task surviving its originating chat. One chat
using two Hosts does not establish this boundary. Native Windows/Linux checks are
required for their conditional consumers; fixture success is not device proof.
