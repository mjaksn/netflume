# Changelog

Notable changes to netflume. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the public API may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

The public API is what [the README](README.md) documents, which is everything
reachable from `netflume.__all__` plus the module-level names listed under
*Everything else exported*. Internals not named there may move without notice.

## [0.1.0] - 2026-08-24

First release. NetFlow v5, NetFlow v9 and IPFIX decoding, a UDP collector, an
optional typed layer over the records, and the two things an exporter says
about itself that change what its numbers mean: the sampling rate, and gaps in
the export sequence. Standard library only, no dependencies, Python 3.9 and up.

Hostname resolution is deliberately not here. It is
[lanname](https://github.com/mjaksn/lanname), a separate package that nothing
in this one depends on.

[0.1.0]: https://github.com/mjaksn/netflume/releases/tag/v0.1.0
