import type { DcqlMatchResult, DcqlSubmission } from '@openeudi/dcql';
import type { ParseOptions } from '../parsers/parser.interface.js';
import type { PresentationResult } from './presentation.js';

export type VerifyOptions = ParseOptions;

export interface VerifyResult {
    parsed: PresentationResult;
    match: DcqlMatchResult;
    submission: DcqlSubmission | null;
    valid: boolean;
}
