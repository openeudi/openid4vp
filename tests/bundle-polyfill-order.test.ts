import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * Regression guard for the reflect-metadata load order in the *published
 * bundles* (GHSA-adjacent footgun; see CHANGELOG 0.9.3).
 *
 * `src/index.ts` importing 'reflect-metadata' first is not enough: the bundler
 * hoists external named imports (`@peculiar/x509`) above bare side-effect
 * imports, so tsyringe evaluated before the polyfill was installed and
 * importing the package threw "tsyringe requires a reflect polyfill" unless the
 * consumer preloaded it themselves.
 *
 * These assertions deliberately exercise the built artefacts at runtime rather
 * than grepping them: with treeshaking and esbuild's lazy module wrappers, the
 * textual order of imports in the bundle does not reliably reflect evaluation
 * order. Each case runs in a fresh child process with NO preload, which is what
 * a consumer's `import '@openeudi/openid4vp'` actually does.
 */
const repoRoot = resolve(__dirname, '..');
const esmBundle = resolve(repoRoot, 'dist/index.js');
const cjsBundle = resolve(repoRoot, 'dist/index.cjs');

/** Runs `code` in a clean node process. Returns stderr on failure, null on success. */
function runInCleanProcess(code: string, type: 'module' | 'commonjs'): string | null {
    const args = type === 'module' ? ['--input-type=module', '-e', code] : ['-e', code];
    try {
        execFileSync(process.execPath, args, {
            cwd: repoRoot,
            stdio: 'pipe',
            // Make sure nothing in the ambient environment preloads the polyfill
            // for us and masks the very failure we are testing for.
            env: { ...process.env, NODE_OPTIONS: '' },
        });
        return null;
    } catch (err) {
        const e = err as { stderr?: Buffer; message?: string };
        return e.stderr?.toString() || e.message || 'unknown failure';
    }
}

describe('published bundles install the reflect-metadata polyfill themselves', () => {
    beforeAll(() => {
        // Always build: the Test and Build jobs are separate in CI, so dist/ may
        // be absent here, and a stale local dist/ would make this test lie.
        execFileSync('npm', ['run', 'build'], { cwd: repoRoot, stdio: 'pipe' });
        expect(existsSync(esmBundle)).toBe(true);
        expect(existsSync(cjsBundle)).toBe(true);
    }, 180_000);

    it('ESM bundle imports with no consumer-side preload', () => {
        const failure = runInCleanProcess(`await import('${esmBundle}');`, 'module');
        expect(failure, `importing dist/index.js without a preload failed:\n${failure}`).toBeNull();
    });

    it('CJS bundle requires with no consumer-side preload', () => {
        const failure = runInCleanProcess(`require('${cjsBundle}');`, 'commonjs');
        expect(failure, `requiring dist/index.cjs without a preload failed:\n${failure}`).toBeNull();
    });

    it('polyfill is installed, not merely bundled', () => {
        const failure = runInCleanProcess(
            `await import('${esmBundle}');
             if (typeof Reflect.getMetadata !== 'function') {
                 throw new Error('Reflect.getMetadata missing after import');
             }`,
            'module',
        );
        expect(failure, `${failure}`).toBeNull();
    });

    it('a real @peculiar/x509 code path works after importing the bundle', () => {
        // tsyringe's throw happens at module-evaluation time, so the two cases
        // above already cover it. This additionally proves decorator metadata is
        // actually usable, not just that the module loaded.
        const failure = runInCleanProcess(
            `const { X509Certificate } = await import('${esmBundle}').then(() => import('@peculiar/x509'));
             if (typeof X509Certificate !== 'function') throw new Error('X509Certificate not constructible');`,
            'module',
        );
        expect(failure, `${failure}`).toBeNull();
    });

    it('CJS bundle keeps "use strict" as its directive prologue', () => {
        // Guards the rejected `banner:` fix, which prepended the require() above
        // the prologue and silently demoted the bundle to sloppy mode.
        const firstStatement = execFileSync(
            'head',
            ['-c', '64', cjsBundle],
            { cwd: repoRoot },
        )
            .toString()
            .trimStart();
        expect(firstStatement).toMatch(/^['"]use strict['"];/);
    });
});
