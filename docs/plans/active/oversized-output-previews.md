# Oversized Output Previews

## Summary

- Replace the remaining default pager-era large-output behavior with non-modal oversized text previews plus stable full-output transcripts.
- Keep `PendingOutputTape` as the always-on raw event collector.
- Use seal-time formatting only for the current implementation phase. It is a bounded transitional design, not the long-term identity of the feature.
- Scope v1 to text-only oversized replies. Replies containing any image content remain unchanged.

## Status

- State: active
- Last updated: 2026-03-21
- Current phase: planning

## Current Direction

- The preferred design is server-owned stable segment transcripts plus oversized text previews.
- Polling remains the primary agent workflow. The transcript path is a fallback when the inline preview is not enough.
- In the current phase, the formatter should run only after the server has produced the exact visible reply text. That is a deliberate simplification for iteration, not the final architecture target.
- This phase accepts a worse memory profile in exchange for simpler implementation and faster design iteration while the public behavior is still being refined.

## Long-Term Direction

- The likely long-term direction is a more eager, state-machine-driven consumer of tape output rather than a pure seal-time formatter.
- The long-term design should preserve the same public behavior contract while reducing memory footprint and making output handling more incremental.
- The current seal-time phase exists to validate the public UX and transcript model first. It should not be treated as proof that the long-term implementation must remain seal-time.

## Phase Status

- Phase 0: completed. Default-path pager behavior was mostly removed, simplified, and isolated behind a feature flag. `PendingOutputTape` became the main default collector.
- Phase 1: completed. Multiple design rounds narrowed the space: no modal pager, no default read tool, no live reader-thread formatting, and no worker-owned transcript files.
- Phase 2: active. Lock the public text format, segment lifecycle, and server/worker responsibilities for text-only v1.
- Phase 3: pending. Implement server-owned transcript storage, segment coordination, and the seal-time formatter as the first bounded implementation step.
- Phase 4: pending. Revisit the implementation architecture after the public behavior is validated and move toward a more eager/state-machine-driven design.
- Phase 5: pending. Update tool descriptions and replace pager-oriented tests and snapshots for the default public surface.

## Locked Decisions

- The tape always exists and always collects output, including output that arrives between tool calls.
- For the current phase, oversized-output logic happens only at reply finalization time after the tape snapshot is drained.
- Polling is the primary interaction model. Agents should keep using bounded `repl` replies and only inspect transcript files when needed.
- Transcript files are owned by the server, not the worker. They must survive worker death, segfault, restart, or reset within the same logical `repl()` request.
- The server maintains one current logical segment at a time:
  - a request segment for an accepted non-empty `repl(input=...)`
  - otherwise a background segment for output that arrives while idle
- Empty-input polls for a still-running request keep appending to the same request segment.
- The current segment path is stable while that segment is active and append-only within that segment.
- The inline reply uses one middle truncation marker line only. No separate metadata block.
- Line-based preview is the default public behavior. Char-based preview is fallback only when a clean line-aligned preview cannot fit the internal budget.
- In line mode and char mode, the marker should report what is already shown, not emit extra helper metadata lines.
- No default transcript-read tool in v1.
- V1 only compacts text-only replies. Mixed text+image replies remain unchanged so current text/image ordering is preserved.

## Rejected Options

- Reviving or depending on modal pager behavior for the default public surface.
- One new artifact file per sealed reply or per poll. The path should stay stable across polls for the same logical segment.
- Worker-owned transcript files tied to the worker tempdir lifetime.
- Adding a default output-read MCP tool before validating the simpler “show the path in reply text” workflow.
- Performing head/tail compaction in reader threads or in the tape itself.
- Treating the current seal-time implementation strategy as the long-term architecture.

## Open Questions

- How should the server behave when background output is pending and a new non-empty request arrives?
  - conservative option: reject the new input until background output is drained
  - alternative: merge or prefix the background output into the next request reply
- What exact inline budget and head/tail split should v1 use?
  - current working default from planning: `3500` visible chars with a `2/3` head and `1/3` tail split before line alignment
  - this should remain an internal default, not a public contract
- Should line-mode fallback be triggered only by newline-poor output, or more generally whenever line snapping becomes misleading or wasteful?
- When this work lands, what follow-up should happen first:
  - transcript retention/quota
  - mixed text+image compaction
  - optional gated transcript-read tool

## Next Safe Slice

- Add a server-owned transcript root and segment coordinator without changing public reply text.
- Thread the current segment kind/path through the worker-to-server reply boundary so the response layer can append text to the correct transcript.
- Implement a pure seal-time formatter for text-only replies after server-side normalization and image collapsing.
- Add focused tests for:
  - stable request-segment reuse across timeout replies and empty-input polls
  - line-mode vs char-mode marker formatting
  - unchanged behavior for mixed text+image replies
- Leave tape growth, quotas, transcript garbage collection, and the later eager/state-machine consumption model out of the initial implementation slice.

## Stop Conditions

- Stop if transcript append still happens before the final visible reply text is known. The transcript must match what the client actually saw.
- Stop if the implementation requires worker protocol changes or pushes formatting logic into reader threads.
- Stop if mixed text+image replies cannot stay unchanged without hidden reordering; keep them out of v1.
- Stop if background-segment behavior remains ambiguous after implementation starts; update the plan and get a decision before proceeding.
- Stop if the implementation starts hard-coding seal-time mechanics into the public contract. Seal-time is a phase tactic, not the product definition.
- Stop if the current phase starts accumulating complexity whose only purpose is to preserve the seal-time tactic. If the tactic is getting in the way, record the issue and revisit the phased rollout.

## Decision Log

- 2026-03-21: Ignore the pager for the new design. Treat it as feature-gated legacy behavior that will go away.
- 2026-03-21: Prefer full omitted-output retrieval over permanent middle-drop, but do it through visible transcript paths rather than a default read tool.
- 2026-03-21: Default retrieval path is “show the file path in normal reply text.” A dedicated read tool, if ever needed, is future work and should be opt-in.
- 2026-03-21: Polling is the primary workflow. Agents are expected to keep polling with bounded replies and use filesystem tools only when the preview is not enough.
- 2026-03-21: A stable path per logical request/segment is better than one file per `repl()` seal because path churn makes `tail`, `grep`, and `read_file` less useful across polls.
- 2026-03-21: The tape is always-on and always collecting, including output that arrives between requests.
- 2026-03-21: For the current implementation phase, oversized-output handling should happen only at seal time after draining the tape and rendering the full would-be reply.
- 2026-03-21: Prefer line-first preview and metadata. Fall back to char mode only when clean line-aligned preview would not fit the budget.
- 2026-03-21: Keep the reply plain: one middle marker line with shown ranges and the transcript path, not multiple metadata lines.
- 2026-03-21: The formatter must live on the server side because the exact visible text is finalized there after image collapsing and prompt/error normalization.
- 2026-03-21: Transcript files must be server-owned and tied to server lifetime, not worker lifetime. A single `repl()` call may span worker death, dump, or restart and still needs one stable segment path.
- 2026-03-21: Scope v1 to text-only oversized replies and leave mixed text+image replies unchanged.
- 2026-03-21: The current seal-time phase is a bounded implementation step chosen to keep iteration simple while the public behavior is still moving.
- 2026-03-21: The likely long-term direction is a more eager/state-machine-driven consumer of tape output with a better memory profile. Do not let the current seal-time phase rename or redefine the broader initiative.
