# Contributing

Ideally create a topic branch for every separate change you make. Each
logical change should be its own separate pull request. For example:

1. Fork the repository.
2. Create a branch (`git checkout -b feature/my-new-feature`,
   `git checkout -b fix/my-fix`)
3. Add and commit your changes to your fork
   (`git commit -m 'Added some feature'`)
4. Push to your fork (`git push origin feature/my-new-feature`)
5. Create new Pull Request from your fork onto the tokendito repo
6. Assign the PR to a team member.

See [GitHub Flow](https://guides.github.com/introduction/flow/)

## Git commit messages

- Separate subject from body with a blank line
- Limit the subject line to 50 characters
- Capitalize the subject line
- Do not end the subject line with a period
- Use the imperative mood in the subject line
- Wrap the body at 72 characters
- Use the body to explain what and why vs. how

See best practices on [commit messages](https://chris.beams.io/posts/git-commit/)

## Release process

Releases are driven entirely by git tags: pushing a tag matching a version
pattern triggers the Docker ([docker.yml](../.github/workflows/docker.yml))
and PyPI ([pypi.yml](../.github/workflows/pypi.yml)) publish workflows. Image
and package builds themselves are automatic; the steps below call out where a
person has to act.

### 1. Start a release branch (manual)

```bash
git checkout main && git pull
git checkout -b release/2.6.0
git push -u origin release/2.6.0
```

Choosing the version number and cutting the branch is a human decision.

### 2. Prepare the release (manual commits, automatic checks)

- Land fixes, changelog updates, and dependency bumps on the release
  branch, directly or via PRs targeting it.
- Every PR targeting `main` or a release branch automatically builds and
  publishes a test package to [TestPyPI](https://test.pypi.org/) via the
  `testpypipublish` job, so a PR's packaging can be sanity-checked before
  anything is tagged.

### 3. Publish a prerelease/beta (manual tag push)

Before tagging, manually bump `__version__` in
[tokendito/\_\_init\_\_.py](../tokendito/__init__.py) to match the tag you are
about to push (for example `2.6.0-rc1`) — the published package version comes
from this file, not from the tag name.

```bash
git tag 2.6.0-rc1
git push origin 2.6.0-rc1
```

Pushing a tag like `X.Y.Z-suffix` triggers both workflows:

- Docker pushes a signed, multi-arch image tagged `2.6.0-rc1` without
  touching the `latest` tag.
- PyPI publishes `tokendito==2.6.0-rc1` to the real index. Because it's a
  prerelease version, `pip install tokendito` ignores it by default; only
  `pip install --pre tokendito` picks it up. PyPI releases are immutable,
  so double-check the version bump before pushing the tag.

Repeat with `2.6.0-rc2`, etc. as needed, validating each build manually, for
example:

```bash
docker pull tokendito/tokendito:2.6.0-rc1
docker run --rm tokendito/tokendito:2.6.0-rc1 --version
```

### 4. Graduate to a stable release (manual merge + manual tag)

- Merge the release branch into `main` (PR review, as usual).
- Bump `__version__` in
  [tokendito/\_\_init\_\_.py](../tokendito/__init__.py) to the final
  version if it isn't already, then tag the merged commit on `main`:

  ```bash
  git checkout main && git pull
  git tag 2.6.0
  git push origin 2.6.0
  ```

- This tag triggers a real PyPI publish and a Docker image publish that
  moves the `latest` tag to `2.6.0`, since it's now the highest stable
  version.
- Optionally create a GitHub Release for the tag. The monthly
  [docker-refresh.yml](../.github/workflows/docker-refresh.yml) workflow
  reads the latest GitHub Release to decide what to rebuild, so this keeps
  that job targeting the right version.
