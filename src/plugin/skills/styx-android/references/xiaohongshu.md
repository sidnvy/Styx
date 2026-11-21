# Xiaohongshu / rednote — observed UI behavior

Package: `com.xingin.xhs`. Verified on paired Pixel 7 Pro, Android 17
(API 37), 2026-11-22. These are **observed patterns**, not stable private APIs.

## Search -> results -> note workflow

1. From Home, click the accessible **Search** node, then observe the search page.
2. The editable search field used resource ID
   `com.xingin.xhs:id/mSearchToolBarEt`. `set_text` successfully entered
   Chinese phrases directly. Search-button resource ID was
   `com.xingin.xhs:id/mSearchToolBarSearchBtn`.
3. Results appeared in clickable containers with ID
   `com.xingin.xhs:id/searchNoteCard`; `noteTitle` is usually a static child.
   Click the *freshly observed card container*, not an old title node.
4. The first `observe_after` following a card click sometimes returned an
   empty tree or the old page. A new `android_observe` showed the detail
   after it loaded. Do not assume a click was ineffective; check state.
5. On image-note details, the full text frequently appeared in
   `com.xingin.xhs:id/imageNoteTextView`; a separate title was in
   `noteTitleTV`. Comments appeared in `tv_content`, sometimes in an
   off-screen accessibility subtree (with `visible=false`).
6. Back navigation restored the result list. Observe again because the list
   layout, card positions and node IDs may have changed.

In the 2026-11-22 real-world hostel-review search, Chinese text entry,
multiple search queries, card navigation and note/comment extraction worked.
A search click once returned an uncertain result; the agent observed the
current screen before trying again. Multiple first detail observations were
empty and needed an additional observation.

## Boundaries

- For researching reviews: read only. Do not like, follow, comment, save or
  publish unless the user explicitly requests it.
- A note author's claim, business self-promotion and replies are distinct
  sources. Report dates, branch/location and disagreement; don't treat
  one review as a verified fact about the whole business.
- No saved coordinates, `observation_id`, screenshots of personal content,
  account tokens, or copied user search history belong in this file.
- If the App changes its hierarchy, inspect it afresh and update this
  reference from a real successful task; do not fall back to shell-driven
  input or ADB when the native Styx Android tool reports a failure.
