# Session journal

This folder exists so that a claim can be checked instead of believed.

`handoff.csv` records how this project is built: one session per row, one increment
per session, a **fresh chat every time**. No session inherits the previous chat; the
only thing that carries over is this repository.

## The rules

1. One session = one accepted increment = one commit.
2. Every session starts in a **new chat**, with the same single message:

   ```
   Read README.md, CHANGELOG.md and journal/README.md.
   Report: the last decision and its date, the next three steps, and one
   rejected idea. Wait for my go-ahead.
   ```

3. Zero minutes of re-explaining the project. If the session needs a summary of its
   own history, that is a **failure** — recorded in the row, not smoothed over.
4. A row is written **on the day**, not reconstructed later.
5. Failures are recorded with the same detail as successes. A journal with no
   failures is a journal that was edited.

## Columns

| column | meaning |
|---|---|
| `session_date` | the day the session happened |
| `chat` | `new` — always a new chat; anything else is a rule violation |
| `model` | the model used, as named by the provider |
| `read_context` | did the session answer the three questions from the files alone? `yes` / `no` / `partial` |
| `re_explained_minutes` | minutes spent telling the session its own history. Target: 0 |
| `increment_accepted` | did the session produce a merged, tested increment? `yes` / `no` |
| `failed_what` | what went wrong, in one sentence. `-` if nothing did |
| `note` | anything a reader needs to interpret the row |

## Honest gap at the start

Row 1 is marked `pre-journal`: the repository was prepared in one long session
before this rule existed. It is recorded as it happened, so nobody mistakes the
journal for a clean story written after the fact.
