"""dataplane.rulepub — rule-pack compiler, validator, and publish tooling.

Owner: detection-engineering. `rules/FORMAT.md` is the normative spec for
rule syntax AND evaluation semantics; this package implements it exactly
(the detector worker imports the compiler from here so publish-time and
runtime semantics can never diverge — FORMAT.md §5.7 determinism).

CLI:
    python -m dataplane.rulepub validate [rules/pack.yaml]     # no DB (CI)
    python -m dataplane.rulepub publish rules/pack.yaml \\
        --published-by <operator> [--dsn <postgres-dsn>]       # SEC-27
"""
