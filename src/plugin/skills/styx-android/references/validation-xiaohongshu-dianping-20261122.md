# Compact UI + page readiness: two real Android apps (2026-11-22)

Status: **read-only validation, no shipped feature**. Device: paired Pixel 7
Pro, Android 17, using existing Styx Public MCP and its native Android Host.
Apps: `com.xingin.xhs` (Xiaohongshu) and `com.dianping.v1` (Dianping).

## Method

Each full `android_observe(include_tree=true, max_nodes=500)` was used to
calculate JSON byte length and a **client-side simulated compact projection**.
It retained `observation_id`, package/window, truncation, and every *visible*
node with a label or action flag, including **unlabeled clickable nodes**.
For retained nodes, it kept the node ID, first 120 label characters, resource
ID when available, bounds, and click/edit/scroll flags. It intentionally omitted
unseen text and other node metadata. Projection occurred *after* the full MCP
response and therefore **cannot demonstrate reduced transport latency**.
No persistent delta history, API change or model-token-cost A/B was deployed.

| App / screen | Full JSON | Simulated compact | Reduction |
| --- | ---: | ---: | ---: |
| Xiaohongshu search results | 17,019 B | 3,200 B | 81% |
| Xiaohongshu note detail | 25,901 B | 1,609 B | 94% |
| Dianping home | 72,504 B | 9,224 B | 87% |
| Dianping search editor | 21,074 B | 5,865 B | 72% |
| Dianping search results | 47,819 B | 7,890 B | 84% |
| Dianping merchant detail | 135,963 B | 6,676 B | 95% |

Representative counts: Dianping home 249 nodes, 67 unlabeled clickable nodes
retained; its merchant detail contained 490 total nodes and **249 offscreen
labeled nodes**. Xiaohongshu note detail contained **25 offscreen labeled
nodes**. Full content mode remains mandatory for deep review/comment reading,
accessibility debugging, and anything where truncated labels omit meaning.

## Real target selection

- Xiaohongshu: the search-result `searchNoteCard` had **no text label but
  was clickable**. The static `noteTitle` child carried the title. The
  compact projection retained the card and its node ID, and a click using that
  current `observation_id` opened the note.
- Dianping: home search button, existing-query label, subsequent editable
  `search_edit_text`, and search submit were located and acted on using
  observed nodes. Search results had merchant titles in static children and
  an **unlabeled clickable image/card**. A generic clickable row returned
  `performed=true` but subsequent observation was unchanged. Targeting
  the observed clickable image inside that merchant result opened details.
- In both apps, `clickable=true` means Android accepted the action; it does
  **not** prove the intended navigation completed. Compact presentation must
  preserve enough geometry and semantics to choose the narrow actionable
  node, while confirming the actual postcondition.

## Actual page-readiness observations

| Transition | Same-call `observe_after` | Following observe |
| --- | --- | --- |
| Xiaohongshu search card -> note | Click accepted, **1 node**, target body absent; 2,675 ms | **81 nodes** and body present; +1,657 ms |
| Dianping merchant image -> detail | Click accepted, **1 node**, detail absent; 3,159 ms | **300 nodes** and detail markers present; +1,927 ms |

These are single observed attempts per transition, not failure-rate estimates.
They show extra MCP round trips to obtain a usable page. Exact app readiness
time inside the gap is unknown; a bounded wait might reduce calls but is not
yet proven to reduce end-to-end latency.

**Important counterexample:** entering Dianping search from Home initially
showed a previous *search-results page*, with a static search keyword, no
editable field. Four further observations (~1.4–2.0 s each) did not produce
an editable field. Clicking the **static search keyword** deliberately
navigated to an editor, which then exposed `search_edit_text`. A generic
`wait until EditText exists` would merely time out on the valid results
page. Readiness must be a caller-selected condition appropriate to the
expected screen, not a guess at how every app transitions.

## Decision and acceptance gates

1. **Prototype optional compact observation as *presentation* only**.
   Preserve the existing private full-tree observation and node identity;
   use no persistent text+coordinate-based node ID reuse or automatic
   re-targeting. Keep a full-mode fallback and a way to request offscreen
   content. Check at least 10 varied real transitions, duplicates, scroll
   and custom-rendered UI before exposing it by default. Target >=60%
   output reduction without loss of actionable targets. Measure model tokens
   independently from host time and MCP latency.
2. **Prototype optional read-only bounded predicate wait only after the
   expected screen is known** (e.g. package/window plus view ID/text;
   event-assisted polling, explicit timeout/not-ready). Never repeat actions
   on timeout. Compare against the extra MCP observe call; don't promise
   latency gains until measured on both apps.
3. **Do not build a generic flow/DSL runner or import another ADB backend**.
   Styx already has native `android_run_steps`, action identity constraints,
   and Android instrumentation tests. Capture app-specific cues as optional
   references; do not hard-code these transient IDs/positions.

No credentials, private messages, complete screenshot, or private review text
were checked into this report. Testing only performed searches and navigation:
no posts, ratings, purchases, bookmarks, or external mutations. See
[upstream source comparison](external-android-agent-patterns.md) and the
[Xiaohongshu reference](xiaohongshu.md).
