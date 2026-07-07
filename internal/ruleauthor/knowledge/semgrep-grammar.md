Semgrep rule grammar (the subset this tool supports). A rule file is YAML with
a top-level `rules:` list. Each rule is one object with these fields.

REQUIRED on every rule:
- id: a short kebab-case identifier, e.g. no-eval-user-input.
- languages: a list, e.g. [python], [javascript, typescript], [go], [java].
- message: one or two sentences telling a developer what is wrong and how to fix it.
- severity: one of ERROR, WARNING, INFO.
- exactly one matching field: `pattern`, `patterns`, or `pattern-either`.

MATCHING FIELDS:
- pattern: a single code pattern. `$X` is a metavariable (matches one
  expression and binds it). `...` is an ellipsis (matches any sequence of
  arguments, statements, or elements). Example: `eval(...)`.
- pattern-either: a list of alternative sub-patterns; the rule matches if ANY
  matches. Each item is itself `{pattern: ...}` or `{patterns: [...]}`.
- patterns: a list of sub-patterns that ALL must hold (logical AND). Use it to
  combine a positive pattern with exclusions. Common members:
    - pattern / pattern-either: what to match.
    - pattern-not: a shape that, if it matches, cancels the finding (use it to
      exclude the safe form, e.g. a bound parameter).
    - pattern-inside: only match when nested inside this larger shape.
    - metavariable-pattern: constrain a metavariable to also match a sub-pattern.
    - metavariable-regex: constrain a metavariable's text to a regex, given as
      {metavariable: $X, regex: "..."}.

METAVARIABLES AND ELLIPSES:
- A metavariable used twice must match the SAME code both times: `$X == $X`.
- Ellipsis `...` inside a call matches any arguments; inside a block matches any
  statements. `<... $X ...>` is a deep expression ellipsis (match $X anywhere
  inside).

STYLE RULES FOR THIS TOOL:
- Be SPECIFIC. A pattern must describe the weakness, not "any code". A rule
  whose only pattern is a bare metavariable or a bare ellipsis matches
  everything and is rejected.
- When a class has a safe form (parameterized query, constant argument, strong
  hash), exclude it with `pattern-not` so the rule does not fire on safe code.
- Keep any regex simple and anchored. Never write a regex with a quantified
  group inside another quantifier (for example `(a+)+` or `(.*)*`): these cause
  catastrophic backtracking and are rejected.
- One rule per request unless the user clearly asks for several.

FEW-SHOT EXAMPLES (these are correct, vetted rules):

Example 1 - Python eval on a variable, excluding a constant string:
```yaml
rules:
  - id: python-eval-non-constant
    languages: [python]
    severity: ERROR
    message: eval() on a non-constant value executes arbitrary code. Avoid eval; use ast.literal_eval for data, or a dispatch table.
    patterns:
      - pattern: eval($X)
      - pattern-not: eval("...")
```

Example 2 - JavaScript document.write of a request value (reflected XSS):
```yaml
rules:
  - id: js-document-write-tainted
    languages: [javascript, typescript]
    severity: ERROR
    message: Writing request-derived data into the DOM with document.write enables reflected XSS. Escape the value or use textContent.
    pattern: document.write(<... req.$PROP ...>)
```

Example 3 - Go MD5 for hashing (weak crypto):
```yaml
rules:
  - id: go-weak-hash-md5
    languages: [go]
    severity: WARNING
    message: MD5 is cryptographically broken. Use crypto/sha256 or a password hash (bcrypt, argon2) as appropriate.
    pattern-either:
      - pattern: md5.Sum(...)
      - pattern: md5.New()
```

Example 4 - Java hardcoded password field, constrained by a regex:
```yaml
rules:
  - id: java-hardcoded-password
    languages: [java]
    severity: ERROR
    message: A hardcoded credential ships with the binary and leaks with the repo. Read it from configuration or a secret store.
    patterns:
      - pattern: String $VAR = "$VAL";
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i).*(password|passwd|pwd|secret).*
```
