# Changelog

Notable changes to netflume. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the public API may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

The public API is what [the README](README.md) documents, which is everything
reachable from `netflume.__all__` plus the module-level names listed under
*Everything else exported*. Internals not named there may move without notice.

## [Unreleased]

### Changed

- **`netflume.__all__` narrowed from 45 names to 33.** Three groups left it:
  the parser's internal steps (`parse_data_record`, `read_template_fields`,
  `record_min_length`, `decode_value`), the `struct.Struct` wire layouts
  (`V5_HDR`, `V5_REC`, `V9_HDR`, `IPFIX_HDR`), and the sequence watcher's
  tuning thresholds (`SEQ_MODULUS`, `MAX_PLAUSIBLE_GAP`, `MAX_REORDER`,
  `RESYNC_AFTER`). All twelve are how the parsing and sequence code is built
  rather than how it is used, and they are also out of
  `netflume.parse.__all__` and `netflume.sequence.__all__`, so they are now
  internal and may move without notice. `from netflume import V5_HDR` no
  longer works; the names are still reachable as `netflume.parse.V5_HDR` and
  the like for anyone caught by this.

  The rule the surface now follows: `netflume.__all__` is what a consumer of
  flows needs, a module's `__all__` is what a caller tuning or extending that
  module needs, and anything in neither is internal.

### Added

- `MAX_TEMPLATES` and `MAX_SERVICE_CACHE` to `netflume.parse.__all__` and
  `netflume.values.__all__`. Both were already documented in the README's
  Ceilings table as public tuning knobs and both were missing from the export
  list that defines the public API. `ADDR_KINDS` was the same fault from the
  other side, exported by the package but absent from `netflume.values`, and
  is now in both.
- `netflume.values.EPHEMERAL_FLOOR`, the port at which `service_name` stops
  naming. The number was written inline, so a consumer drawing the same line
  had to copy it and then watch it for drift.
- `netflume.ie.__all__`. It was the only module without one, and so the only
  module making no statement about what it considers public.
- `tests/test_exports.py`, which holds the README and the export lists against
  each other in both directions. The audit rounds before 0.1.0 checked only
  that a documented name resolves, never that it is exported, which is why the
  two ceilings above went unnoticed.

## [0.1.0] - 2026-08-24

First release. NetFlow v5, NetFlow v9 and IPFIX decoding, a UDP collector, an
optional typed layer over the records, and the two things an exporter says
about itself that change what its numbers mean: the sampling rate, and gaps in
the export sequence. Standard library only, no dependencies, Python 3.9 and up.

Hostname resolution is deliberately not here. It is
[lanname](https://github.com/mjaksn/lanname), a separate package that nothing
in this one depends on.

[Unreleased]: https://github.com/mjaksn/netflume/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mjaksn/netflume/releases/tag/v0.1.0
