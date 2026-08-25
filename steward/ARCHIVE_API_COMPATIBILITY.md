# Archive convenience export compatibility

## Purpose and limitations

This report inventories the four module-level convenience wrappers around
`TaskArchive` without changing archive implementation, tests, exports, package
metadata, or runtime behavior. It combines source, package-export, dynamic-name,
documentation, test, and `git log --all --oneline -S` searches with definition
inspection and history classification.

Repository evidence can establish canonical replacements, package versus
module-only exposure, repository callers, and historical changes. It cannot
observe downstream imports, installed copies, private forks, generated
consumers, or runtime strings outside the tracked tree. Therefore an absence of
repository callers is not deletion authority.

## Classification criteria

- `supported-export` means the wrapper is re-exported by the public
  `coquic_steward.execution` package facade as well as defined by the archive
  module.
- `internal-cleanup-candidate` means the wrapper has no package re-export and
  no repository caller, while its canonical instance method is used. This is a
  bounded follow-up classification only; the module-level `__all__` still
  makes downstream ownership unresolved.
- `external-ownership-unresolved` means repository evidence cannot establish a
  safe ownership decision even after separating public exports from internal
  implementation names.

No wrapper has independent behavior: each only constructs `TaskArchive` and
forwards to its canonical constructor or instance method.

## Compatibility matrix

| Wrapper | Definition and canonical replacement | Export reach | Repository callers, docs, and tests | History | Classification | Recommendation |
|---|---|---|---|---|---|---|
| `archive_for` | Wrapper at `execution/task_archive.py:3488-3489`; replace with `TaskArchive(config_or_root, epoch_id=epoch_id)` (`:1138-1147`). | Listed in module `__all__` (`:3596`) and imported/re-exported by `execution/__init__.py:30-40,74-78`. It is not exported by the top-level package, whose `__all__` contains only `__version__` (`coquic_steward/__init__.py:3-5`). | No repository caller, dotted reference, documentation mention, or direct wrapper test. Tests construct `TaskArchive` directly. | Introduced with the wrapper and package export in `21c39bc1` (`feat(steward): add task execution ledger and archive`). The targeted wrapper-definition and export history has no later ownership change. | `supported-export` | Preserve the package facade. Any future narrowing must prove downstream imports and approve `TaskArchive(...)` as the compatibility replacement. |
| `ensure_epoch` | Wrapper at `execution/task_archive.py:3492-3493`; replace with `TaskArchive(config_or_root, epoch_id=epoch_id).ensure_epoch()`; canonical method is `:1664-1711`. | Listed in module `__all__` (`:3597`) and imported/re-exported by `execution/__init__.py:30-40,76-77`. | No wrapper caller. Canonical `TaskArchive.ensure_epoch` is used by archive internals (`task_archive.py:1749,2708,2787,3138`), storage (`storage/sqlite.py:1763,2489`), execution/orchestration, and tests. Other `ensure_epoch` hits in `core/config.py:964` and `control_loop/archive.py:195` are different methods; injected test attributes are not wrapper imports. No docs mention the wrapper. | The wrapper was introduced in `21c39bc1`. The broad required history scan also finds later archive, configuration, control-loop, storage, and call-site changes (`b6b9210d`, `62411cad`, `b1e11550`, `30cc7e05`, `a5cd979f`, `eb10f3b1`, `f8b4c04d`, `f94be7b0`, `a9d25c24`, `777b239a`, `d327f173`, `84500362`, `0be9e475`, `7a4ba686`, `5e325fc8`); targeted wrapper searches show no later ownership or export change. | `supported-export` | Preserve the package facade. Do not confuse active instance-method use with evidence that the convenience wrapper itself is safe to remove. |
| `verify_archive` | Wrapper at `execution/task_archive.py:3496-3497`; replace with `TaskArchive(config_or_root).verify(task_id)`; canonical method is `:2794-2802`. | Listed in module `__all__` (`:3598`) and imported/re-exported by `execution/__init__.py:30-40,78`. | No wrapper caller, dotted reference, documentation mention, or direct wrapper test. Tests and daemon code exercise `archive.verify(...)` (`tests/test_task_archive.py:493,756,761`; `orchestration/daemon.py:2219`). | Introduced with the wrapper and package export in `21c39bc1`. The targeted wrapper-definition and export history has no later ownership change. | `supported-export` | Preserve the package facade. Any removal requires explicit import compatibility evidence and a separately approved transition to `TaskArchive.verify`. |
| `collect_invocation_evidence` | Wrapper at `execution/task_archive.py:3500-3517`; replace with `TaskArchive(config_or_root).collect_invocation_evidence(...)`; canonical method is `:1180-1492`. | Listed in module `__all__` (`:3606`) but never imported or re-exported by `execution/__init__.py`; this is module-only exposure. | No module-wrapper caller, dotted reference, or documentation mention. Internal code calls the canonical instance method (`task_archive.py:1505,2390,3275`), and tests exercise that method at `tests/test_task_archive.py:248-429`. | Added with the collector and module export in `777b239a` (`feat(steward): preserve retry telemetry evidence`). Later hits in `cf140a53` and `52da2afa` change collector validation/telemetry behavior; `4d21f7ab` removes neighboring class synonyms while retaining this canonical method and wrapper. None changes package ownership. | `internal-cleanup-candidate` (module-only; downstream ownership unresolved) | Ask Grill to confirm module-import ownership before any deletion or deprecation. If approved, scope the change to this wrapper and require direct-import evidence plus the class method as the replacement; do not infer safety from missing repository callers. |

## Package and module reach

All four names are importable attributes of
`coquic_steward.execution.task_archive` and appear in that module's `__all__`
(`task_archive.py:3589-3608`). Only `archive_for`, `ensure_epoch`, and
`verify_archive` cross the package boundary through
`coquic_steward.execution.__init__`. None is re-exported by the top-level
`coquic_steward` package. `steward/pyproject.toml:29-32` uses normal `src`
package discovery, so module-only exposure remains observable to installed
consumers.

## Dynamic and namespace scan

The required dotted/string scan found no dynamically constructed wrapper name
and no qualified wrapper path. Its unrelated matches are false positives:
`import_module` calls in `tests/test_publication_pipeline.py:119,159,175,204`,
`__import__` calls for standard-library modules, and generic `__getattr__`
methods in `orchestration/transport.py:426,453`. The exact-name ownership scan
found only canonical `TaskArchive`/`TaskArchiveWriter` methods and the
`collect_invocation_evidence` instance-method tests; none is a module-wrapper
caller. `ensure_epoch` matches in configuration and control-loop classes are
separate APIs.

## Documentation and compatibility comments

No README, pipeline document, source comment, or other Steward documentation
mentions any of the four wrapper names as a supported compatibility promise.
The module-level collector docstring describes bounded evidence collection but
does not establish package-level ownership. This absence does not disprove
external imports.

## Bounded follow-up

1. Preserve the three package-facade wrappers while their downstream import
   surface is unknown; any cleanup must name the direct class replacement and
   pass an explicit compatibility decision.
2. Treat `collect_invocation_evidence` as the only repository-local cleanup
   candidate, not as deletion authority. Grill must resolve whether direct
   imports from `coquic_steward.execution.task_archive` are supported before a
   transition is considered.
3. Do not change source, tests, exports, aliases, warnings, package versioning,
   or release policy as part of this evidence report.

## Verification record

- The drift check against `caf8c9dc` for the assigned archive implementation,
  tests, README, storage report, and package metadata paths was clean.
- The required ownership, dynamic/dotted, and four-name history scans were run;
  all hits above are either wrapper evidence, canonical instance-method use,
  or an explicitly classified namespace/history false positive.
- No implementation, test, export, packaging, or versioning file changed.
- The report content includes all four names, canonical replacements, package
  versus module-only exposure, caller/docs/tests/history reach, classifications,
  and recommendation gates.
