#!/usr/bin/env node
/**
 * Smoke-tests the PACKED, INSTALLED package — not the source tree.
 *
 * 0.9.2 is the reason this exists. A fix was written, unit-tested, reviewed,
 * released and changelogged, and was completely inert in the published bundle:
 * the bundler hoisted `@peculiar/x509` above the bare `import 'reflect-metadata'`,
 * so importing the package threw `tsyringe requires a reflect polyfill`. 405
 * source tests passed while the shipped artefact was broken on import.
 *
 * So this runs against a real `npm pack` tarball installed into a scratch
 * directory, with NO reflect-metadata preload, and exercises the dependency
 * chain that actually broke (@peculiar/x509 -> tsyringe -> decorator metadata)
 * rather than just checking that the module resolves.
 *
 * Usage: node scripts/smoke-package.mjs <install-dir>
 */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import process from 'node:process';

const installDir = process.argv[2];
if (!installDir) {
    console.error('usage: node scripts/smoke-package.mjs <install-dir>');
    process.exit(2);
}

const require = createRequire(resolve(installDir, 'noop.cjs'));
const pkgRoot = resolve(installDir, 'node_modules/@openeudi/openid4vp');
const failures = [];

async function check(name, fn) {
    try {
        await fn();
        console.log(`  ok    ${name}`);
    } catch (err) {
        failures.push({ name, err });
        console.log(`  FAIL  ${name}\n        ${err?.message ?? err}`);
    }
}

function assert(cond, msg) {
    if (!cond) throw new Error(msg);
}

console.log(`smoke-testing installed package at ${pkgRoot}`);

// Loading the entries is itself the first assertion — the 0.9.2 failure mode is
// a throw during module evaluation, before any exported function is called. Wrap
// it so that failure reports the likely cause instead of a bare tsyringe stack.
let esm;
let cjs;
let installedPkg;
try {
    // Imported by URL from the install dir so this goes through the published
    // package, not a relative path into the repo's dist/.
    esm = await import(
        new URL('node_modules/@openeudi/openid4vp/dist/index.js', `file://${installDir}/`).href
    );
    cjs = require('@openeudi/openid4vp');
    installedPkg = JSON.parse(readFileSync(resolve(pkgRoot, 'package.json'), 'utf8'));
} catch (err) {
    console.error('\nFAIL: the packed package threw while being loaded.\n');
    console.error(String(err?.message ?? err));
    if (/reflect polyfill|getMetadata/i.test(String(err?.message ?? err))) {
        console.error(
            '\nThis is the 0.9.2 regression: the bundler hoisted @peculiar/x509 above the\n' +
                "bare `import 'reflect-metadata'`, so tsyringe evaluated before the polyfill was\n" +
                'installed. Check that `inject` is still set in tsup.config.ts.',
        );
    }
    console.error(`\nFull stack:\n${err?.stack ?? '(none)'}`);
    process.exit(1);
}

await check('ESM entry imports with no reflect-metadata preload', async () => {
    assert(typeof esm.createAuthorizationRequest === 'function', 'missing createAuthorizationRequest');
});

await check('CJS entry requires with no reflect-metadata preload', async () => {
    assert(typeof cjs.createAuthorizationRequest === 'function', 'missing createAuthorizationRequest');
});

await check('the polyfill is actually installed, not merely bundled', async () => {
    assert(typeof Reflect.getMetadata === 'function', 'Reflect.getMetadata absent after import');
});

await check('VERSION matches the packed package.json', async () => {
    assert(
        esm.VERSION === installedPkg.version,
        `VERSION ${esm.VERSION} != packed ${installedPkg.version}`,
    );
});

await check('buildHaipQuery / validateHaipQuery round-trip', async () => {
    const query = esm.buildHaipQuery({
        credentialId: 'pid',
        format: 'dc+sd-jwt',
        vctValues: ['urn:eudi:pid:1'],
        claims: ['age_over_18'],
    });
    esm.validateHaipQuery(query);
    assert(query.credentials?.[0]?.id === 'pid', 'unexpected query shape');
});

await check('createAuthorizationRequest emits a wallet URI', async () => {
    const query = esm.buildHaipQuery({
        credentialId: 'pid',
        format: 'dc+sd-jwt',
        vctValues: ['urn:eudi:pid:1'],
        claims: ['age_over_18'],
    });
    const req = esm.createAuthorizationRequest(
        {
            clientId: 'x509_san_dns:verifier.example.com',
            responseUri: 'https://verifier.example.com/cb',
            nonce: 'smoke-nonce',
        },
        query,
    );
    assert(req.uri.startsWith('openid4vp://authorize?'), `unexpected uri: ${req.uri}`);
});

// This is the important one: createSignedAuthorizationRequest is what drags in
// @peculiar/x509 -> tsyringe. If the polyfill ordering regresses, this throws
// even when a bare import happens to survive.
await check('createSignedAuthorizationRequest exercises @peculiar/x509 + tsyringe', async () => {
    const x509 = require('@peculiar/x509');
    const hostname = 'verifier.example.com';

    const signer = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify'],
    );
    // A CA-issued leaf, not self-signed: the builder rejects self-signed verifier
    // certificates by default (HAIP 1.0 Final), so a self-signed fixture here
    // would only ever exercise the error path.
    const caKeys = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify'],
    );
    const notBefore = new Date(Date.now() - 60_000);
    const notAfter = new Date(Date.now() + 3_600_000);
    const caCert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: '01',
        name: 'CN=smoke-test-ca',
        notBefore,
        notAfter,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        keys: caKeys,
        extensions: [new x509.BasicConstraintsExtension(true, 1, true)],
    });
    const cert = await x509.X509CertificateGenerator.create({
        serialNumber: '02',
        subject: `CN=${hostname}`,
        issuer: caCert.subject,
        notBefore,
        notAfter,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        publicKey: signer.publicKey,
        signingKey: caKeys.privateKey,
        extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: hostname }])],
    });

    const encKeys = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits', 'deriveKey'],
    );
    const publicJwk = await crypto.subtle.exportKey('jwk', encKeys.publicKey);
    publicJwk.alg = 'ECDH-ES';
    publicJwk.use = 'enc';

    const query = esm.buildHaipQuery({
        credentialId: 'pid',
        format: 'dc+sd-jwt',
        vctValues: ['urn:eudi:pid:1'],
        claims: ['age_over_18'],
    });

    const base = {
        requestUri: `https://${hostname}/request.jwt`,
        responseUri: `https://${hostname}/response`,
        nonce: 'smoke-nonce',
        signer,
        certificateChain: [new Uint8Array(cert.rawData), new Uint8Array(caCert.rawData)],
        encryptionKey: { publicJwk },
        vpFormatsSupported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'] } },
    };

    const sanReq = await esm.createSignedAuthorizationRequest({ ...base, hostname }, query);
    assert(
        sanReq.uri.includes(encodeURIComponent(`x509_san_dns:${hostname}`)) ||
            sanReq.uri.includes(`x509_san_dns%3A${hostname}`),
        `x509_san_dns client_id missing from uri: ${sanReq.uri}`,
    );

    const hashReq = await esm.createSignedAuthorizationRequest(
        { ...base, clientIdPrefix: 'x509_hash' },
        query,
    );
    assert(/x509_hash%3A[A-Za-z0-9_-]{43}/.test(hashReq.uri), `x509_hash client_id malformed: ${hashReq.uri}`);
});

// Pins the documented split (README "Verifying presentations"): unrecognised
// input resolves with valid:false, while structurally broken input of a known
// format throws. Both paths must survive bundling — the throwing path also
// proves the exported error classes are reachable from the packed entry.
await check('unrecognised token resolves valid:false rather than throwing', async () => {
    const result = await esm.parsePresentation('not-a-real-vp-token', { nonce: 'smoke-nonce' });
    assert(result.valid === false, `expected valid:false, got ${result.valid}`);
    assert(
        typeof result.error === 'string' && result.error.length > 0,
        `expected a diagnostic error string, got ${JSON.stringify(result.error)}`,
    );
});

await check('structurally broken SD-JWT throws MalformedCredentialError', async () => {
    let caught;
    try {
        await esm.parsePresentation('a~b~c', { nonce: 'smoke-nonce' });
    } catch (err) {
        caught = err;
    }
    assert(caught !== undefined, 'broken SD-JWT did not throw');
    assert(
        caught instanceof esm.MalformedCredentialError,
        `expected MalformedCredentialError from the packed entry, got ${caught?.constructor?.name}`,
    );
});

console.log('');
if (failures.length > 0) {
    console.error(`${failures.length} smoke check(s) failed against the packed package.`);
    for (const f of failures) console.error(`  - ${f.name}: ${f.err?.stack ?? f.err}`);
    process.exit(1);
}
console.log(`all smoke checks passed against @openeudi/openid4vp@${installedPkg.version}`);
