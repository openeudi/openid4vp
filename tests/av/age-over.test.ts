/**
 * EU Age Verification profile — answering a threshold from the disclosed
 * `age_over_NN` elements (ISO/IEC 18013-5 §7.2.5 nearest attestation).
 */
import { describe, expect, it } from 'vitest';

import { decideAvAgeOver, type AvAgeOverElement } from '../../src/av/age-over.js';

function elements(values: Record<string, boolean>): AvAgeOverElement[] {
    return Object.entries(values).map(([identifier, value]) => ({ identifier, value }));
}

/** A random integer in [min, max]. */
function between(min: number, max: number): number {
    return min + Math.floor(Math.random() * (max - min + 1));
}

function attr(nn: number): string {
    return `age_over_${String(nn).padStart(2, '0')}`;
}

describe('decideAvAgeOver', () => {
    it.each([
        // [threshold, disclosed, ageOver, decidedBy]
        [16, { age_over_16: true }, true, 'age_over_16'],
        [16, { age_over_16: false }, false, 'age_over_16'],
        [16, { age_over_18: true }, true, 'age_over_18'],
        [16, { age_over_16: false, age_over_18: false }, false, 'age_over_16'],
        [16, { age_over_16: true, age_over_18: true }, true, 'age_over_16'],
        [16, { age_over_16: true, age_over_18: false }, true, 'age_over_16'],
        [16, { age_over_14: false }, false, 'age_over_14'],
        [21, { age_over_25: true }, true, 'age_over_25'],
        [21, { age_over_18: false }, false, 'age_over_18'],
        [21, { age_over_18: true, age_over_21: false }, false, 'age_over_21'],
        [21, { age_over_18: true, age_over_25: true }, true, 'age_over_25'],
        [18, { age_over_18: true }, true, 'age_over_18'],
        [18, { age_over_18: false }, false, 'age_over_18'],
    ] as const)('NN=%i with %o → ageOver %s (decided by %s)', (threshold, disclosed, ageOver, decidedBy) => {
        expect(decideAvAgeOver(elements(disclosed), threshold)).toEqual({ ageOver, decidedBy });
    });

    it.each([
        [16, { age_over_18: false }],
        [21, { age_over_18: true }],
        [21, { age_over_18: true, age_over_25: false }],
        [16, { age_over_12: true, age_over_18: false }],
        [18, {}],
    ] as const)('NN=%i with %o makes no statement → missing_attribute, never ageOver false', (threshold, disclosed) => {
        const decision = decideAvAgeOver(elements(disclosed), threshold);
        expect(decision).toMatchObject({ failure: 'missing_attribute' });
        expect(decision).not.toHaveProperty('ageOver');
        expect((decision as { error: string }).error).toContain(attr(threshold));
    });

    it('picks the nearest deciding element on either side', () => {
        const threshold = between(30, 60);
        const above = elements({ [attr(threshold + 9)]: true, [attr(threshold + 2)]: true, [attr(threshold - 20)]: true });
        expect(decideAvAgeOver(above, threshold)).toEqual({ ageOver: true, decidedBy: attr(threshold + 2) });

        const below = elements({ [attr(threshold - 9)]: false, [attr(threshold - 2)]: false, [attr(threshold + 20)]: false });
        expect(decideAvAgeOver(below, threshold)).toEqual({ ageOver: false, decidedBy: attr(threshold - 2) });
    });

    it.each([
        [16, { age_over_18: true, age_over_16: false }],
        [16, { age_over_21: true, age_over_18: false }],
        [21, { age_over_18: true, age_over_16: false }],
        [21, { age_over_25: true, age_over_21: false }],
    ] as const)('NN=%i with contradictory %o → inconsistent_attributes', (threshold, disclosed) => {
        const decision = decideAvAgeOver(elements(disclosed), threshold);
        expect(decision).toMatchObject({ failure: 'inconsistent_attributes' });
        expect(decision).not.toHaveProperty('ageOver');
    });

    it('checks consistency across every element, even ones that do not decide the threshold', () => {
        const threshold = between(10, 17);
        // age_over_18 true would decide; age_over_65 true with age_over_50 false contradicts.
        const decision = decideAvAgeOver(elements({ age_over_18: true, age_over_65: true, age_over_50: false }), threshold);
        expect(decision).toEqual({ failure: 'inconsistent_attributes', error: 'age_over_65 is true but age_over_50 is false' });
    });

    it('treats the same identifier disclosed twice with different values as inconsistent', () => {
        const threshold = between(10, 99);
        const decision = decideAvAgeOver(
            [
                { identifier: attr(threshold), value: true },
                { identifier: attr(threshold), value: false },
            ],
            threshold,
        );
        expect(decision).toMatchObject({ failure: 'inconsistent_attributes' });
    });

    it('accepts a true above and a false further above (age between them)', () => {
        const decision = decideAvAgeOver(elements({ age_over_16: true, age_over_18: false }), 14);
        expect(decision).toEqual({ ageOver: true, decidedBy: 'age_over_16' });
    });
});
