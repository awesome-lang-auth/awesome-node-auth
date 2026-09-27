// awesome-node-auth was renamed to @awesome-lang-auth/node: this bridge re-exports it unchanged.
// Keep the single `module.exports = require(...)` statement: Node's ESM loader recognises
// that exact form and exposes the named exports to `import { ... } from 'awesome-node-auth'`.
module.exports = require("@awesome-lang-auth/node");
