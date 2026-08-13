# Repo Publication Audit

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

For automation, emit machine-readable results:

```bash
python -m repo_publication_audit . --format json
```

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
```

## Limitations

Do not rely on this tool as a substitute for a full secret-management review.
It does not send files or findings anywhere, and it skips `.git`, virtual
environments, dependency directories, and files larger than 1 MiB.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Security reports belong in the private
channel described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
