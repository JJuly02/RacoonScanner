# Agent instructions — RacoonScanner

<!-- AIRABOARD:TASKS-PROTOCOL -->
## Agent ⇄ board tasks (AIraBoard)

This repo publishes agent work to a board via a `TASKS/` directory — one JSON file
per task. The board (AIraBoard) renders them as a kanban and writes control back
into the same files.

**As an agent working in this repo:**

1. **Publish your work.** When you start a non-trivial piece of work, create a task
   and keep its `status` / `progress` current:
   ```bash
   python3 <AIRABOARD>/tasks_proto.py --repo . --add "What I'm doing" --status running
   python3 <AIRABOARD>/tasks_proto.py --repo . --set T-0001 --progress "ran tests" --status review
   ```
   `status` is one of `backlog | running | review | done`.

2. **Check for directives every cycle.** At the start of each work cycle, read
   `TASKS/*.json` and look for a `directive` with `ack: false` — that's a human
   instruction from the board (`approve` / `answer` / `revise` / `stop` + a message).
   Act on it, then acknowledge:
   ```bash
   python3 <AIRABOARD>/tasks_proto.py --repo . --ack T-0001
   ```

**Field ownership — never write the other side's fields:**

| Field | Owner |
|-------|-------|
| `status`, `progress`, `agent`, `blocked`, `updated_at` | the agent |
| `directive.action/message/by/at` | the human/board |
| `directive.ack` | the agent (set `true` once consumed) |

`TASKS/*.json` is git-ignored (ephemeral state); `TASKS/.gitkeep` is tracked.
Full spec: `AIraBoard/TASKS-PROTOCOL.md`.
