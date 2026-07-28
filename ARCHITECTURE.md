# ethos-engine architecture

A real daemon and thin CLI. In the currently wired legacy topology, typed
requests traverse state-bearing Signal → Nexus → SEMA Kameo actors. Nexus
performs the golden-bridge TypeSchema ingestion, while SEMA persists through
the central daemon's typed binary socket.

The approved target is a stateful Ethos daemon whose own embedded sema
database stores its documents. A separate small translator daemon owns only
shared naming and encodedID allocation. The current socket path remains in
place until a separately designed storage migration lands; it is not the
target storage contract.

## Revisable leans

Legacy ingestion is an explicit edge adapter for the witness. Native
`TextualSchema` authoring may replace it, but new work must not treat the
central Core storage socket as a durable architectural boundary.
