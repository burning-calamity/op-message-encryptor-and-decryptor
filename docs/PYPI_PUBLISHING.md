# Publishing `ars-occultandarum-litterarum` to PyPI

This repository publishes with PyPI Trusted Publishing through GitHub Actions. The
workflow is `.github/workflows/publish-to-pypi.yml` and the package name in
`pyproject.toml` is `ars-occultandarum-litterarum`.

## Fixing `invalid-publisher`

If GitHub Actions fails with:

```text
Trusted publishing exchange failure: invalid-publisher: valid token, but no corresponding publisher
```

PyPI does not have a trusted publisher entry matching the identity claims from
GitHub Actions. Create or edit the PyPI trusted publisher so it exactly matches
these values:

| PyPI trusted publisher field | Value |
| --- | --- |
| Publisher | GitHub Actions |
| PyPI project name | `ars-occultandarum-litterarum` |
| Owner | `burning-calamity` |
| Repository name | `op-message-encryptor-and-decryptor` |
| Workflow filename | `publish-to-pypi.yml` |
| Environment name | `pypi` |

The error log in GitHub Actions should show the same important claims:

```text
repository: burning-calamity/op-message-encryptor-and-decryptor
workflow_ref: burning-calamity/op-message-encryptor-and-decryptor/.github/workflows/publish-to-pypi.yml@refs/heads/main
environment: pypi
```

A mismatch in any of those fields can cause `invalid-publisher`.

## Common mismatch shown by the current screenshots

If the PyPI trusted publisher page shows:

```text
Workflow: python-tests.yml
Environment name: pypi
```

but the GitHub Actions error log shows:

```text
workflow_ref: burning-calamity/op-message-encryptor-and-decryptor/.github/workflows/publish-to-pypi.yml@refs/heads/main
environment: pypi
```

then PyPI is trusting the **test** workflow while GitHub is trying to publish
from the **publish** workflow. Edit the PyPI trusted publisher and change the
workflow filename from `python-tests.yml` to `publish-to-pypi.yml`, or remove the
old trusted publisher entry and create a new one with `publish-to-pypi.yml`.

## First-time PyPI setup

1. Log in to PyPI.
2. Open the project page for `ars-occultandarum-litterarum`. If the project does
   not exist yet, create a pending publisher for that project name from your PyPI
   account's publishing settings.
3. Add a GitHub Actions trusted publisher with the exact values in the table
   above.
4. Confirm the GitHub repository has an environment named `pypi` if you use
   environment protection rules. The workflow declares `environment: pypi`.

## Publishing a release

Before publishing, bump `version` in `pyproject.toml`. PyPI never allows reusing
an already-uploaded version filename.

Then publish one of two ways:

### Manual publish

1. Merge the workflow to the default branch.
2. Go to **GitHub → Actions → Publish to PyPI**.
3. Click **Run workflow**.

### Tag publish

```bash
git tag v0.1.2
git push origin v0.1.2
```

The tag must match `v*.*.*`.

## Why this workflow does not use a PyPI token

The publish workflow uses GitHub OIDC / PyPI Trusted Publishing, so it should not
need `PYPI_API_TOKEN` or a long-lived password. If you prefer API-token based
publishing instead, add a PyPI API token as a GitHub secret and update the
publish action to pass it as `password`, but Trusted Publishing is the preferred
configuration for this repository.
