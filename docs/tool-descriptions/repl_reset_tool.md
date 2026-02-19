`repl_reset` restarts the active backend REPL session.

Behavior:
- Clears in-memory session state (objects, variables, loaded runtime state tied to the process).
- Starts a fresh worker session and returns the new-session status output.

Arguments:
- none
