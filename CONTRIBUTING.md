# Contributing to awesome-node-auth

Thank you for your interest in contributing! This guide explains how to get started.

## Development setup

```bash
git clone https://github.com/nik2208/awesome-node-auth
cd awesome-node-auth
npm install
npm test          # run the full test suite
npm run build     # compile TypeScript
```

## Project structure

```
src/          Library source (TypeScript)
tests/        Vitest test suite
wiki/         Docusaurus documentation site
demo/         Collection of demo applications (express-vanilla, nestjs, nextjs, etc.)
examples/     Integration examples
```

## How to contribute

1. **Fork** the repository and create a branch from `main`.
2. Make your changes following the style guide below.
3. Add or update tests to cover your change.
4. Run `npm test` — all tests must pass.
5. Open a **Pull Request** against `main`.

## Style guide

- TypeScript strict mode — no `any` unless absolutely necessary.
- No new runtime dependencies without discussion in an issue first.
- Public APIs must be documented with JSDoc.
- Existing tests must not be removed or weakened.
- Each commit should be a single logical change.

## Reporting bugs & requesting features

Use the [issue templates](.github/ISSUE_TEMPLATE/) provided. Search for existing issues before opening a new one.

## Security issues

Do **not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your work will be licensed under the [MIT License](LICENSE) that covers this project.
