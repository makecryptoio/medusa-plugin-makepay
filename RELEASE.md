# Release Policy

Releases are performed only by MakePay by MakeCrypto maintainers.

- Public repositories accept issues and pull requests, but maintainers control release approval, versioning, tagging, and package publishing.
- Package-manager credentials, signing keys, and publish tokens must live only in private release repositories or private CI workflows.
- Public repositories must not store npm, PyPI, Maven Central, Packagist, RubyGems, GitHub release, or other publish secrets.
- Protected branch and tag rules must remain enabled for `main` and release tags.
- Version bumps should be made only when maintainers intend to publish a new package or release artifact.
