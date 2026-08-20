import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { VERSION } from '../src/index.js';

/**
 * The exported `VERSION` constant is maintained by hand and silently went stale
 * once already (it still read `0.8.0` at the 0.9.1 release; fixed in 0.9.2).
 * Nothing else in the suite compares it against the real package version, so a
 * release could ship a wrong `VERSION` again without any test noticing.
 */
describe('VERSION export', () => {
    it('matches the version in package.json', () => {
        const pkg = JSON.parse(
            readFileSync(resolve(__dirname, '../package.json'), 'utf8'),
        ) as { version: string };

        expect(VERSION).toBe(pkg.version);
    });
});
