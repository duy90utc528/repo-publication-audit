# Repo Publication Audit

![A shield and magnifying glass protecting a source repository](assets/social-preview.png)

A small, dependency-free preflight checker for repositories about to become
public. It catches common accidental disclosures and reports whether a project
has the basic community files expected of an open-source repository.

It is intentionally conservative: findings are prompts for review, not proof
that a secret is valid or that a repository is safe to publish.

## Quick start

```bash
git clone https://github.com/duy90utc528/repo-publication-audit.git
cd repo-publication-audit
python -m repo_publication_audit /path/to/repository
```

After installation, the equivalent command is:

```bash
repo-publication-audit /path/to/repository
```

For automation, emit machine-readable results:

```bash
python -m repo_publication_audit . --format json
```

Exclude intentionally committed test data or an exported directory with a
repeatable relative path:

```bash
repo-publication-audit . --exclude examples --exclude fixtures
```

Respect Git's `.gitignore` rules, including nested files and negation rules,
when Git is installed:

```bash
repo-publication-audit . --respect-gitignore
```

## CI with GitHub Actions

Create `.github/workflows/publication-audit.yml` in the repository you want to
check:

```yaml
name: publication audit
on: [pull_request, push]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: duy90utc528/repo-publication-audit@v0.4.0
        with:
          fail-on: high
          respect-gitignore: true
```

Pin to a commit SHA in security-sensitive environments. The action installs the
package locally in the GitHub runner; it does not upload repository content.

### GitHub Code Scanning (SARIF)

SARIF is GitHub's standard format for surfacing third-party security findings in
Code Scanning. Generate a report, keep the audit non-blocking while it collects
findings, then upload it:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: duy90utc528/repo-publication-audit@v0.4.0
    with:
      format: sarif
      output: repo-publication-audit.sarif
      fail-on: never
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: repo-publication-audit.sarif
      category: repo-publication-audit
```

## Configuration

Copy [`.repo-publication-audit.toml.example`](.repo-publication-audit.toml.example)
to `.repo-publication-audit.toml` in a repository being audited:

```toml
[audit]
exclude = ["fixtures"]
fail_on = "high"
respect_gitignore = true
```

`fail_on = "medium"` also makes absent community files fail CI; `"never"`
reports findings without returning a nonzero exit status.

The process exits with status `1` when it finds a high-severity finding.

## Checks

- tracked or unignored `.env` files, private keys, and common credential files;
- token-shaped strings such as GitHub, OpenAI, and AWS access keys;
- absent `LICENSE`, `README`, `CONTRIBUTING`, or `SECURITY` documents;
- repository-local git configuration and build artifacts that often should not
  be published.

## Development

This project supports Python 3.11+ and uses only the standard library.

```bash
python -m unittest discover -s tests -v
python -m pip install .
repo-publication-audit --version
```

## Limitations

Do not rely on this tool as a substitute for a full secret-management review.
It does not send files or findings anywhere, and it skips `.git`, virtual
environments, dependency directories, and files larger than 1 MiB.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security reports belong in the private
channel described in [SECURITY.md](SECURITY.md).

## Adoption and feedback

Using the action or CLI in a public repository? Share what worked, what did
not, and—only if you consent—your public repository URL through the
[adoption issue template](https://github.com/duy90utc528/repo-publication-audit/issues/new?template=adopter.yml).
This feedback determines the v0.4 roadmap.

## Roadmap

- v0.3: SARIF output for GitHub Code Scanning and stable rule IDs.
- v0.4: full Git `.gitignore` semantics for opt-in scans.
- Next: opt-in repository policy packs and reviewed-finding baselines.

## License

[MIT](LICENSE)
