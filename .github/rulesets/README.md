# Branch protection ruleset

`protect-main.json` is the branch protection for `main`, kept as code so it is
reviewable and reproducible. It enforces the "only a maintainer approves what
lands" policy:

- No direct pushes to `main`: changes come through a pull request.
- Every PR needs an approving review, and because of
  [`../CODEOWNERS`](../CODEOWNERS), that review must come from the repo owner
  (`require_code_owner_review`).
- The approval is re-required after any new push (`require_last_push_approval`),
  and stale approvals are dismissed when the branch changes.
- The `argus` CI check must pass, on an up-to-date branch, before merge.
- Review threads must be resolved; force-pushes and branch deletion are blocked.
- The repository **Admin** role bypasses the ruleset (`bypass_actors`), so the
  maintainer can still push directly during solo development. Remove that bypass
  entry to hold admins to the same PR flow as everyone else.

## Why it is not applied yet

GitHub gates branch protection and rulesets behind **GitHub Pro or a public
repository** for *private* repos. This repo is currently private on the free
plan, so neither can be enabled through the API or UI until one of those is
true.

## How to apply it

Once the repo is public (recommended, and consistent with the Apache-2.0,
open-by-default plan in the README) or on a paid plan:

```bash
# Via the API:
gh api -X POST repos/leaky-hub/argus/rulesets --input .github/rulesets/protect-main.json

# Or in the UI: Settings > Rules > Rulesets > New ruleset > Import a ruleset,
# and pick this file.
```

If the import objects to the `bypass_actors` entry, the built-in Admin role id
can differ; drop the `bypass_actors` array (admins then follow the same flow) or
re-add the Admin role from the UI's actor picker.
