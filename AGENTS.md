# AGENTS.md

This file provides guidance to coding agents working in this repository.

## What this is

`netflume` is a Python library that collects and parses NetFlow v5, NetFlow
v9 and IPFIX. It is a library, not an application: it decodes, tracks
templates, and surfaces what an exporter says about itself. It does not
render, aggregate, store or alert, and nothing in it prints.

## Layout

```
netflume/      the package (parse, decoder, collector, flow, events,
               sampling, sequence, values, ie)
tests/         unittest suite, plus tests/packets.py which assembles
               synthetic datagrams byte by byte
tools/fuzz.py  adversarial check that Decoder.decode never raises
.github/       CI, fuzz and release workflows
```

`README.md` is the API reference and it is long; it documents the public
surface, the counters, the ceilings and the roadmap. Read the relevant
section of it before changing behaviour, and keep it in step when the
public surface moves.

## Checks

All four run from the repository root and need no fixture or service.

```bash
python -m unittest discover      # 273 tests, about a second
python -m ruff check .
python -m mypy netflume
python tools/fuzz.py --seconds 60
```

Only ruff and mypy are external tools, and they are development tools,
never runtime dependencies. Install them with `pip install ruff mypy` if
they are missing.

CI also builds and checks the distributions, which needs two more tools
that are not present by default. To reproduce that job locally:

```bash
pip install build twine
python -m build
twine check dist/*
```

Narrowing the suite works at every level:

```bash
python -m unittest tests.test_parse
python -m unittest tests.test_values.AddressKind
python -m unittest tests.test_parse.ParseV5.test_header_fields
python -m unittest discover -v
```

The fuzzer defaults to ten seconds and a random seed, prints the seed it
chose, and reproduces a reported failure with `--seed N`. It exits
non-zero and prints a hex reproducer if a datagram makes `decode` raise.

## Constraints that must not be broken

**Zero dependencies.** `pyproject.toml` declares `dependencies = []` and
that is a design decision, not an accident: the package has to be
droppable onto a router, a jump host or a bare container, and it must
never be the reason a security update is blocked. The tests are standard
library only for the same reason. Do not add a runtime or test
dependency; solve it with the standard library or leave it out.

**Python 3.9 is the floor.** `requires-python = ">=3.9"` and ruff targets
`py39`. So no `X | None`, no builtin generics such as `list[int]` in
annotations, and nothing else added after 3.9. Use `typing.Optional`,
`typing.List` and friends, as the existing modules do. The ruff lint
selection is `E, F, W, I, B` on purpose: the pyupgrade rules are left out
because they would ask for exactly the syntax 3.9 cannot take.

**`Decoder.decode` never raises.** Whatever arrives on the socket was
chosen by whoever can reach it, and a decoder that dies on one bad packet
is useless on a real network. A datagram that will not parse is counted
and queued as a `DecodeError` event instead. `tools/fuzz.py` exists to
attack that promise, so run it after touching anything in the parse path.

**Nothing prints.** Diagnostics are event objects from `take_events()`,
and are also written to the `netflume` logger, which carries only a
`NullHandler`. Never add a `print`, and never configure a real handler
inside the package.

**Every table keyed by an exporter has a ceiling.** A UDP source address
is whatever the sender typed, so an unbounded table keyed by one is a
memory leak anybody able to reach the socket can pull on. Templates,
sequence streams, sampling streams, pending events and the service-name
cache each have a documented limit and an eviction rule. A new
per-exporter table needs the same treatment.

## Architecture

Two layers, and either works without the other.

**Parsing** (`parse.py`, with `ie.py` and `values.py`) turns bytes into
dicts. No socket, no threads, no clock the caller cannot control. The
entry points are `parse_v5`, `parse_v9_or_ipfix` and the
version-dispatching `parse_message`, and all three return
`(header, flow_records, option_records)`. Option records stay separate
from flows because they describe the exporter rather than traffic, and
mixed in they would inflate every count downstream.

**Collection** (`collector.py` over `decoder.py`) binds a UDP socket and
hands back what arrives. `Decoder` is the parsing layer with the state
that has to outlive a single datagram attached to it: the template store,
the sequence watch and the sampling watch. `Collector` adds the socket
and three ways to read it, an iterator of `(record, header)` pairs, an
iterator of typed `Flow` objects, and a `poll` for a caller who owns the
event loop.

Points that are easy to get wrong and are settled deliberately:

- Templates are keyed by `(exporter address, observation domain,
  template ID)`. Different exporters reuse the same IDs for different
  layouts, so all three parts are needed.
- `__iter__` yields `(record, header)` rather than a bare record because
  a v5 or v9 record cannot be timestamped without its header.
- `Flow` is an opt-in typed view over the dict, not a replacement for it.
  The dict is lossless and costs nothing when an exporter sends a field
  nobody anticipated. What `Flow` is really for is resolving the field
  aliases that differ between exporters, in one place instead of at every
  call site.
- An element the `ie.py` table does not know is still decoded and still
  delivered, under `ie<id>` or `e<pen>.<id>`. An unrecognised field is
  never a lost field.
- A truncated template is refused rather than stored short. Storing it
  short would cut every later record for that ID into one real flow plus
  fabricated ones, which reach the caller looking like genuine traffic.

`tests/test_hardening.py` is the home for the failure class the fuzzer
cannot see: input that decodes without raising and returns something
untrue. New bounds checks and normalisations belong there.

## CI and branch rules

`gate` is the single check the ruleset on `main` requires. It depends on
the lint, test and build jobs and runs `if: always()`, so an upstream
failure surfaces there rather than leaving the gate skipped and the
requirement satisfied by default. Do not require the matrix jobs
individually; renaming one would quietly stop protecting anything.

CI runs on pull requests, on pushes to `main`, and on demand. Changes
reach `main` through a pull request, so a dispatched run is a convenience
and never the gate: its checks attach to the commit but do not enter the
pull request's status rollup, and the rollup is what the ruleset
evaluates.

The test matrix is Python 3.9 through 3.13 on Ubuntu and Windows, minus
the 3.9 on Windows cell, which was dropped because fetching that
interpreter cost more than the suite it ran. Fuzzing runs after a merge
and on demand, deliberately not as part of the gate: it is exploratory,
and a required check that fails for a novel reason is one people learn to
click past.

Releases are tag driven. The workflow refuses to publish unless the tag,
the version in `pyproject.toml` and `netflume.__version__` all agree, so
a version bump touches both files.

## Writing conventions

- Python lines wrap at 88 columns, which is the ruff setting.
- Markdown prose wraps at 80 columns. Tables, links and literal commands
  may run over.
- Never write an em dash, and never write two hyphens in a row as a
  stand-in for one. Use a comma, a colon, a semicolon, brackets, or two
  sentences. An en dash is discouraged for the same reason. Hyphens
  inside words are ordinary spelling and are fine, and a long
  command-line option keeps the two hyphens the tool spells it with.
- Comments here explain why a choice was made, especially where the
  obvious alternative is wrong. Match that. A comment restating what the
  line does is not wanted.
- Commit subjects are short, with no body.
