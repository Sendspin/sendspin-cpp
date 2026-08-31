# Contributing to sendspin-cpp

Thanks for your interest in contributing! Bug reports, fixes, and features
are all welcome.

## Building and testing

Host build:

```bash
cmake -B build && cmake --build build
```

Unit tests (AddressSanitizer and UndefinedBehaviorSanitizer enabled, matching CI):

```bash
cmake -B build-tests -DSENDSPIN_BUILD_TESTS=ON -DENABLE_SANITIZERS=ON -DBUILD_EXAMPLES=OFF .
cmake --build build-tests --target sendspin_tests
ctest --test-dir build-tests --output-on-failure
```

On ESP-IDF the library is consumed as a component via `idf_component.yml`; the
source lists live in `cmake/sources.cmake`.

## Before opening a PR

- Install the pre-commit hooks (`pre-commit install`); they run clang-format,
  markdownlint, and whitespace fixers.
- CI is the quality gate: it treats warnings as errors, runs clang-tidy
  (`./script/clang-tidy.sh`), and runs the unit tests under sanitizers.
  Running these locally first saves a review round trip.
- Keep each PR scoped to one logical change, with a concise description of
  what the change is now.
- Update documentation in the same PR: docs and comments track the code (see
  the Documentation section of `docs/conventions.md` for what must stay in
  sync).
- Answer review findings explicitly: fix them, or push back with a concrete
  technical argument.

## Design conventions

The design standards (threading and Inbox rules, validation posture, platform
abstraction boundaries, embedded resource discipline, public API shape) are
stated normatively in `docs/conventions.md`. `docs/internals.md` describes how
the current code works together. Review checklists that apply the standards to
a diff live in `.claude/skills/`:

- `docs-sync`: documentation and comment drift review
- `embedded-review`: suitability for embedded targets (stack, heap, flash)
- `house-patterns`: consistency with the library's design conventions
- `test-standards`: test quality expectations

They are written for use with AI coding agents, but each one reads as a plain
checklist and can be applied by hand.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0. All source files carry the license header.
