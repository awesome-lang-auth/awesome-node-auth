/**
 * Type-level guard for BASE_USER_FIELD_CLASS (issue #40, acceptance criterion 10).
 *
 * Vitest strips types and `tsc -p .` covers `src/` only, so a `@ts-expect-error`
 * in this file would prove nothing.  The fixtures in
 * `tests/fixtures/register-field-class/` are compiled with the TypeScript API,
 * using the compiler options of the repository's tsconfig.json:
 *
 * - `classified.ts` compiles clean and checks that BASE_USER_FIELD_CLASS has
 *   exactly the keys of BaseUser;
 * - `unclassified-field.ts` adds `isSuperAdmin` to BaseUser through declaration
 *   merging, so the `satisfies Record<keyof BaseUser, ...>` clause in
 *   `src/router/register-sanitize.ts` itself must fail.
 */
import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import * as ts from 'typescript';

const repoRoot = path.resolve(__dirname, '..');
const fixturesDir = path.join(__dirname, 'fixtures', 'register-field-class');
const sanitizeFile = path.join(repoRoot, 'src', 'router', 'register-sanitize.ts');

function compilerOptions(): ts.CompilerOptions {
  const configPath = path.join(repoRoot, 'tsconfig.json');
  const read = ts.readConfigFile(configPath, ts.sys.readFile);
  if (read.error) throw new Error(ts.flattenDiagnosticMessageText(read.error.messageText, '\n'));
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, repoRoot);
  // The fixtures live outside rootDir; nothing is emitted anyway.
  return { ...parsed.options, noEmit: true, rootDir: undefined, outDir: undefined, declaration: false, declarationMap: false, sourceMap: false };
}

function diagnosticsFor(fixture: string): ts.Diagnostic[] {
  const program = ts.createProgram([path.join(fixturesDir, fixture)], compilerOptions());
  return [...ts.getPreEmitDiagnostics(program)];
}

function format(diags: readonly ts.Diagnostic[]): string {
  return diags
    .map((d) => `${d.file ? path.relative(repoRoot, d.file.fileName) : '<global>'}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`)
    .join('\n');
}

describe('BASE_USER_FIELD_CLASS type-level classification', () => {
  it('compiles clean and covers exactly the keys of BaseUser', () => {
    const diags = diagnosticsFor('classified.ts');
    expect(format(diags)).toBe('');
  }, 60_000);

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: a BaseUser key missing from BASE_USER_FIELD_CLASS fails to compile', () => {
    const diags = diagnosticsFor('unclassified-field.ts');
    expect(diags.length).toBeGreaterThan(0);
    // The error is reported in register-sanitize.ts (the satisfies clause), and names the field.
    const inSanitize = diags.filter((d) => d.file && path.resolve(d.file.fileName) === sanitizeFile);
    expect(inSanitize.length, format(diags)).toBeGreaterThan(0);
    expect(format(inSanitize)).toContain('isSuperAdmin');
  }, 60_000);
});
