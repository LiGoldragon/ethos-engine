# Agent guidance

This repository is under fast development and constantly breaking.

The Signal → Nexus → SEMA flow and central typed storage socket are wired
legacy behavior, not the target architecture. The approved target makes this
daemon stateful, with its own embedded sema database. A separate small
translator daemon is authoritative only for shared naming and encodedID
allocation.

Do not extend the stateless-client pattern or imply that the storage migration
has landed. Preserve isolated defaults and never use production Spirit paths.
