# Publishing from Windows

Two batch scripts are included in the repository root. They use your existing
Git/GitHub credentials and never store an access token in the repository.

## Push changes and open a pull request

From Command Prompt in the repository directory, run:

```bat
publish_changes_to_github.bat "Describe the changes"
```

The script initializes submodules, runs the Python tests, stages all changed
files, creates a commit when needed, pushes the current branch, and uses GitHub
CLI to create or open its pull request. If `gh` is unavailable, the branch is
still pushed and the script prints the command needed to create the PR.

The script intentionally does not force-push or place passwords/tokens in files.
Install and authenticate the required tools with:

```bat
winget install --id Git.Git
winget install --id GitHub.cli
gh auth login
```

## Publish the Python package

First merge the version-bump pull request. Then update local `main` and run:

```bat
git switch main
git pull --ff-only origin main
publish_pypi_release.bat
```

The release script requires a clean `main` branch, runs tests, builds the wheel
and source archive, rejects an existing local or remote version tag, and asks
you to type the exact tag before pushing it. Pushing that tag starts the
repository's `Publish to PyPI` GitHub Actions workflow; the script does not
handle or store a PyPI API token.

For version `0.1.4`, the confirmation text is:

```text
v0.1.4
```

PyPI Trusted Publishing must identify the workflow as
`.github/workflows/publish-to-pypi.yml` and the GitHub environment as `pypi`.
