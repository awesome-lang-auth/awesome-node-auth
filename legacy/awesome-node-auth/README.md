# awesome-node-auth → @awesome-lang-auth/node

**This package was renamed.** Starting with 1.10.1 the library is published as [`@awesome-lang-auth/node`](https://www.npmjs.com/package/@awesome-lang-auth/node). The code and the API are the same; only the package name changed. New releases are published only under the new name.

`awesome-node-auth@1.10.1` is a compatibility bridge. It depends on `@awesome-lang-auth/node@^1.10.1` and re-exports it, so existing code keeps working while you migrate.

## Migrate

1. Swap the dependency:

   ```sh
   npm uninstall awesome-node-auth
   npm install @awesome-lang-auth/node
   ```

2. Change the import specifier, in `import` and `require` alike:

   ```ts
   // before
   import { AuthConfigurator } from 'awesome-node-auth';
   // after
   import { AuthConfigurator } from '@awesome-lang-auth/node';
   ```

## What the bridge covers

- The package root: `require('awesome-node-auth')`, ESM `import` and the TypeScript types.
- **Not** deep imports such as `awesome-node-auth/dist/...`. Point them at `@awesome-lang-auth/node/dist/...`, or import from the package root: the framework adapters `expressAdapter` and `fastifyAdapter` are exported there.

## Links

- Repository: https://github.com/awesome-lang-auth/awesome-node-auth
- Changelog: https://github.com/awesome-lang-auth/awesome-node-auth/blob/main/CHANGELOG.md
- Issues: https://github.com/awesome-lang-auth/awesome-node-auth/issues

## License

MIT
