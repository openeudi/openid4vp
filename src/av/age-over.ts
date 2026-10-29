import { avAgeOverAttribute, avAgeOverThreshold } from './constants.js';

/** One disclosed `age_over_NN` element of a Proof of Age attestation. */
export interface AvAgeOverElement {
    identifier: string;
    value: boolean;
}

export type AvAgeOverDecision =
    | { ageOver: boolean; decidedBy: string }
    | { failure: 'missing_attribute' | 'inconsistent_attributes'; error: string };

/**
 * Answer "is the holder at least `threshold`?" from the disclosed `age_over_NN`
 * elements, following the nearest-attestation rule of ISO/IEC 18013-5 §7.2.5:
 * `age_over_MM: true` proves every threshold up to MM, `age_over_MM: false`
 * disproves every threshold from MM up.
 *
 * 1. A `true` at MM together with a `false` at MM' <= MM is contradictory →
 *    `inconsistent_attributes`. This also catches the same identifier
 *    disclosed twice with different values.
 * 2. `age_over_NN` disclosed → its value.
 * 3. The nearest `true` above NN → `true`.
 * 4. The nearest `false` below NN → `false`.
 * 5. Otherwise no statement can be made → `missing_attribute`. A `false`
 *    above NN or a `true` below NN never decides: "no statement" is not
 *    "under age".
 *
 * Elements that are not `age_over_NN` identifiers are ignored; the AV
 * structure check rejects them before this runs.
 */
export function decideAvAgeOver(elements: readonly AvAgeOverElement[], threshold: number): AvAgeOverDecision {
    const requested = avAgeOverAttribute(threshold);
    let highestTrue: number | undefined;
    let lowestFalse: number | undefined;
    let exact: boolean | undefined;
    let nearestTrueAbove: number | undefined;
    let nearestFalseBelow: number | undefined;

    for (const { identifier, value } of elements) {
        const nn = avAgeOverThreshold(identifier);
        if (nn === undefined) continue;
        if (value) {
            if (highestTrue === undefined || nn > highestTrue) highestTrue = nn;
            if (nn > threshold && (nearestTrueAbove === undefined || nn < nearestTrueAbove)) nearestTrueAbove = nn;
        } else {
            if (lowestFalse === undefined || nn < lowestFalse) lowestFalse = nn;
            if (nn < threshold && (nearestFalseBelow === undefined || nn > nearestFalseBelow)) nearestFalseBelow = nn;
        }
        if (nn === threshold) exact = value;
    }

    if (highestTrue !== undefined && lowestFalse !== undefined && lowestFalse <= highestTrue) {
        return {
            failure: 'inconsistent_attributes',
            error: `${avAgeOverAttribute(highestTrue)} is true but ${avAgeOverAttribute(lowestFalse)} is false`,
        };
    }
    if (exact !== undefined) return { ageOver: exact, decidedBy: requested };
    if (nearestTrueAbove !== undefined) return { ageOver: true, decidedBy: avAgeOverAttribute(nearestTrueAbove) };
    if (nearestFalseBelow !== undefined) return { ageOver: false, decidedBy: avAgeOverAttribute(nearestFalseBelow) };

    const disclosed = elements.map(({ identifier, value }) => `${identifier}: ${String(value)}`).join(', ');
    return {
        failure: 'missing_attribute',
        error:
            `the presentation does not disclose ${requested}` +
            (disclosed ? `, and no disclosed element decides it (${disclosed})` : ''),
    };
}
