# The `-o json` output contract

`-o json` is the reason this port exists over the Ruby original: because the
transport carries PSRP *objects*, a command's result is real typed data, not a
console table a consumer has to scrape. This document is the contract for that
output, what a program parsing the stream can rely on. The code is
`internal/output/output.go`; the interactive/one-shot/batch callers are in
`internal/shell`.

## The stream is NDJSON

Every line of stdout is one self-contained JSON object, terminated by `\n`
(newline-delimited JSON). A consumer reads a line, parses it, acts on it, and
never has to track position or buffer across lines. This holds in all three
modes:

- **one-shot** (`-x <cmd>`): exactly one object.
- **batch** (`-x -`): one object per input command, in order, streamed as each
  command completes.
- **interactive** with stdout piped: one object per command entered.

Diagnostics never pollute stdout in json mode: the connection banner and any
warning go to **stderr**, and the prompt is suppressed. So a parse failure on a
stdout line means a real defect, which is why `scripts/batch-test.py` asserts
exactly that (every non-empty stdout line must parse).

## The `type` discriminator

Every object carries a `type` field naming its kind, so a single line is
self-describing without the consumer tracking which command it asked for:

| `type` | Meaning | Shape |
| --- | --- | --- |
| `result` | One command's output and streams | `JSONResult` (below) |
| `error` | A failure not tied to a rendered command, a connect failure, a transport fault, a rejected built-in | `JSONResult` with `output: []`, the message in `errors`, `had_errors: true` |
| `event` | A session-level notice, not a command's output | `JSONEvent` (below) |

Only batch mode currently emits all three on one stream; one-shot emits a single
`result` or `error`. The field is present in every mode regardless, so parsing
logic is uniform.

## `type: "result"`, the command envelope

```json
{
  "type": "result",
  "command": "whoami",
  "output": ["htb\\svc-alfresco"],
  "errors": [],
  "warnings": [],
  "verbose": [],
  "information": [],
  "had_errors": false,
  "duration_ms": 41
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `type` | string | Always `"result"`. |
| `id` | any | Present only when the command arrived as a JSON request carrying an `id` (see the request protocol below); echoes it verbatim for correlation. Omitted for a bare-line command. |
| `command` | string | The command as dispatched. For a built-in it is the friendly name (`services`), not the script it expands to. |
| `output` | array | The success stream, one element per pipeline object, **normalized** (see below). Always present (may be empty). |
| `errors` | array | The error stream. Omitted when empty. |
| `warnings`, `verbose`, `information` | array | The other PowerShell streams. Omitted when empty. `information` is where PowerShell 5.1 files `Write-Host`, which many post-ex scripts use as their only output. |
| `had_errors` | bool | The command's own verdict. **This is the failure signal**, not the exit code, a PowerShell error record is a failure that still produces normal-looking `output`. Always present. |
| `duration_ms` | int | Wall-clock milliseconds for the command. |

### Object normalisation

Elements of `output` (and the other streams) are PSRP objects flattened to plain
JSON:

- A **primitive** (string, number, bool) is emitted as itself.
- A **DateTime**, enum, or other value-wrapping object is emitted as its value
  (a timestamp stays a timestamp), not as its presentation metadata.
- A **structured object** becomes a JSON object of its properties; adapted
  members are merged over base properties, matching what PowerShell surfaces. Its
  type name is kept under `__type` and its string form under `__string`, so a
  consumer can still tell a `Process` from a `FileInfo`.
- An **ErrorRecord** is compacted to the useful fields (`message`, `exception`,
  `category`, `fully_qualified_error_id`, `position`, …) rather than the ~25
  `InvocationInfo_*` bookkeeping properties it serialises as verbatim.

## `type: "event"`, session-level notices

```json
{
  "type": "event",
  "event": "shell_recovered",
  "message": "the target no longer had this shell ...; a new one was opened. Session state was LOST ...",
  "state_lost": true
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `type` | string | Always `"event"`. |
| `event` | string | A stable machine key. Current values: `shell_recovered`, `shell_recovery_failed`, `input_error`. |
| `message` | string | Human-readable detail. |
| `state_lost` | bool | Present and `true` when the runspace's accumulated state (cwd, variables, functions, `-s` scripts, any AMSI patch) was discarded and must be re-established. Omitted when false. |

The event a batch consumer must handle is `shell_recovered`: the target forgot
the shell (WinRM restart, idle timeout, an admin removing it), so a fresh shell
was opened and **everything the batch had set up is gone**. It arrives in-stream
on stdout, before the results of any subsequent commands, so a consumer sees it
in order and can re-establish state before relying on it.

## The request protocol (batch input)

In batch mode (`-x -`) an input line may be a **JSON request object** instead of
a bare command, so an agent can pipeline many commands and match each response
to the request that produced it:

```json
{"id": "req-1", "command": "whoami"}
{"id": 2, "command": "Get-Process -Name lsass"}
```

The response echoes the `id`:

```json
{"type": "result", "id": "req-1", "command": "whoami", "output": ["htb\\svc-alfresco"], ...}
{"type": "result", "id": 2, "command": "Get-Process -Name lsass", "output": [ ... ], ...}
```

- `command` (string, required) is the command to run, anything typeable at the
  prompt, built-ins included.
- `id` (any JSON value, optional) is the correlation token, echoed verbatim on
  every object the command produces (`result`, `error`, or a transfer summary).

**Detection is strict and non-breaking.** A line is treated as a request only
when it starts with `{`, parses as a JSON object, and has a non-empty string
`command`. Everything else is a bare command line run verbatim with no `id`: an
ordinary command, a PowerShell scriptblock `{ ... }` (not valid JSON), or a JSON
object without a usable `command`. So bare-line batch and the request protocol
mix freely on one stream, and an ordinary command is never mistaken for a
request.

Commands still execute **in order** on the single runspace, the id is for
correlating a pipelined stream, not for out-of-order or concurrent execution,
which one runspace cannot do.

## Exit code

Independent of the stream, the process exit code is `0` if every command
succeeded and `1` if any failed (including a `had_errors` command that produced
normal output). For a batch it is the aggregate over all commands. A consumer
parsing the stream should key on `had_errors` per command; the exit code is for
a shell caller that reads only `$?`.

## Stability

Fields are **added, not renamed or removed** within a major version. A consumer
should ignore unknown fields and unknown `type`/`event` values rather than fail
on them. New `event` keys in particular are expected over time. The reserved
object keys are the double-underscore ones (`__type`, `__string`); a target
property colliding with them is the one case where a raw name is shadowed.
