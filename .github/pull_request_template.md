<!-- Thanks for contributing! See CONTRIBUTING.md for the full expectations. -->

## What and why

<!-- What does this change, and why? Link the issue it closes, e.g. "Closes #123". -->

## Checklist

- [ ] `flake8 openbadgeslib tests`, `mypy`, and `pytest` pass locally — with the
      `[ldp]` / `[eudi]` extras installed if this touches those tracks (otherwise
      their tests silently skip).
- [ ] Commit messages follow the Conventional Commits convention
      (`type(scope): …`, imperative, ≤ 80 chars); the `gitlint` check passes.
- [ ] A user-facing change (`feat` / `fix` / `security` / `perf`) adds its
      `Changelog.txt` entry under a `* vX.Y.Z - unreleased` header.
- [ ] Docs / wiki updated if behaviour or the public API changed.
