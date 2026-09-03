# Changelog

Notable changes to netflume. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the public API may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

The public API is what [the README](README.md) documents, which is everything
reachable from `netflume.__all__` plus the module-level names listed under
*Everything else exported*. Internals not named there may move without notice.

## [0.3.0] - 2026-09-03

### Added

- **`TemplateLearned`, so that learning a template is something a caller can
  hear about.** v9 and IPFIX exporters describe their records before they send
  any, and every field decoded afterwards is read through that description.
  Until now the fact never left the library: `stats["templates_new"]` counted
  the templates and said nothing about which, and a consumer wanting to show
  or log a layout had to reach into `decoder.templates` and work out for
  itself what had changed since it last looked.

  The event carries the exporter, the observation domain, the template ID, the
  fields as (name, kind, length) triples in record order, whether it is an
  options template, and `previous`: the layout it replaced, or None when the
  template is new. A template that changes under an ID already in use is the
  case worth acting on, since every record decoded for that ID afterwards
  means something different from the ones before it, and `previous` is the
  only place the old layout still exists by the time a caller sees the event.

  Only new and changed templates raise one, exactly as only changed rates
  raise a `SamplingChange`. Exporters resend every template they hold every
  few minutes, and an event per resend would be an event per datagram from the
  exporters that prepend their templates to everything.

  `decoder.templates.take_events()` is the source, and `Decoder.decode` folds
  it into its own events on every datagram. It does so on the way out of a
  datagram that failed to parse as well: a template set can be sound and the
  set behind it be what raised, and a layout learned from the first is true
  either way.

- **`netflume.parse.MAX_PENDING_TEMPLATES`**, the ceiling on events awaiting
  `TemplateStore.take_events()`, with drops counted in `store.dropped` and the
  limit settable as the store's `max_pending`. A `Decoder` drains on every
  datagram and never reaches it. It is there for a caller driving
  `parse_message` without one, since an exporter alternating two layouts under
  a single template ID raises an event every time it switches, and an unbounded
  list behind that is a memory leak reachable from the socket.

### Changed

- **`take_events()` is no longer empty on a healthy stream that is still
  starting up.** The first datagram carrying each of an exporter's templates
  now raises a `TemplateLearned`. Steady state is unchanged and still quiet, so
  a caller draining in a loop sees what it always did, but one that reads any
  event at all as a fault will be wrong about the first minute of a run. Test
  what an event is before treating it as trouble.

## [0.2.1] - 2026-08-28

### Documentation

- The README now carries the PyPI badge. Released so that it appears on the
  PyPI project page, which is rendered from the README inside the uploaded
  distribution and cannot be edited in place.

Nothing about the library changed since 0.2.0. The only code in this release is
the version number itself, in `pyproject.toml` and `netflume.__version__`.
`netflume.__all__` and every module's exports are exactly what 0.2.0 published.

0.2.0 was withdrawn, though, and cannot be installed, so 0.2.1 is the first
release that carries what it published. Coming from 0.1.0, this release brings
everything listed under 0.2.0 below with it, the narrowing of `netflume.__all__`
from 45 names to 33 included, and that narrowing is the one change a consumer
can be broken by.

## 0.2.0 - 2026-08-25

**Withdrawn.** The tag, the GitHub release and the files on PyPI have all been
deleted, so this version is no longer installable and this heading is
deliberately not a link: there is nowhere left for it to point. What it
published went out as 0.2.1 instead, unchanged apart from the version number
and the README's PyPI badge. The entry stays because the changes below are
real, and anyone upgrading from 0.1.0 meets them.

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

[0.3.0]: https://github.com/mjaksn/netflume/releases/tag/v0.3.0
[0.2.1]: https://github.com/mjaksn/netflume/releases/tag/v0.2.1
[0.1.0]: https://github.com/mjaksn/netflume/releases/tag/v0.1.0
