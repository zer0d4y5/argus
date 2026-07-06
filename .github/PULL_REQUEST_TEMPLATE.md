<!-- Thanks for contributing to Bulwark. See CONTRIBUTING.md for the ethos. -->

### What & why

What this changes and the motivation.

### Checklist

- [ ] New behavior has a test that would fail without it
- [ ] `gofmt` + `go vet ./...` clean; relevant tests pass (`go test ./...`)
- [ ] Touched a deterministic contract (severity / compliance / fingerprint / correlation / an authz row / a threat row)? Its **doc is updated in this PR**
- [ ] Coverage claim (language / scanner / framework)? Backed by a **labeled fixture**; honest gaps documented, not hidden
- [ ] Touched the SARIF writer? Re-validated against the 2.1.0 schema
- [ ] Touched the console UI? Rebuilt `ui/dist` (embedded in the binary)
- [ ] Security-relevant? Consistent with `SECURITY.md` and `docs/console-ops.md`

### Notes for the reviewer

Anything non-obvious, or a demo of the change working end-to-end.
