`repl_reset` restarts the active backend REPL session.

Behavior:
- Clears in-memory session state (objects, variables, loaded runtime state tied to the process).
- Starts a fresh worker session and returns the new-session status output.
- Any already-disclosed oversized-output spill paths remain valid for the server lifetime. `repl_reset` does not delete server-owned spill files or bundle directories.
- Prefer this when the intent is explicit lifecycle control or memory cleanup after large one-off work.

Arguments:
- none
