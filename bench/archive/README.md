# Historical benchmark and design archive

These files preserve benchmark results and design records for provenance.
They are not current runtime guidance or performance baselines.

`pre-baffle-40/` contains results from earlier runtime and session benchmarks.
Those measurements include comparisons with a runtime that Baffle no longer
supports and tests that used the former loopback TCP ingress path. They do not
describe the current Unix-socket ingress.

`benchmark-report-2026-09-26.md` contains the original detailed report. It
includes a later Unix-socket characterization and earlier comparisons. Use
[`docs/benchmarking.md`](../../docs/benchmarking.md) for current benchmark
commands and procedures.

The files in this directory are excluded from release documentation.
