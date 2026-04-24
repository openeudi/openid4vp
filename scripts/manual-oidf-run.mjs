#!/usr/bin/env node
/**
 * Manual interop helper for OIDF verifier conformance testing against
 * demo.certification.openid.net.
 *
 * Usage:
 *   1. cd ~/Work/openeudi-openid4vp && npm run build
 *   2. Start a public tunnel on port 8080 (ngrok http 8080, or
 *      cloudflared tunnel --url http://localhost:8080).
 *   3. Set PUBLIC_BASE env to the tunnel https URL.
 *   4. node scripts/manual-oidf-run.mjs
 *   5. Open https://demo.certification.openid.net and create a verifier
 *      test plan with profile:
 *        sd_jwt_vc + x509_san_dns + request_uri_signed + dcql
 *        + response_mode=direct_post.jwt
 *      Plug the script-printed URLs into the test plan.
 *   6. Run the default test. Script logs verification result on /response POST.
 *
 * NOT shipped in the npm package (scripts/ excluded from package.json "files").
 */

import http from 'node:http';
import { URL } from 'node:url';
import * as x509 from '@peculiar/x509';
import {
    createSignedAuthorizationRequest,
    verifyAuthorizationResponse,
} from '../dist/index.js';

const PORT = 8080;
const PUBLIC_BASE = process.env.PUBLIC_BASE;
if (!PUBLIC_BASE) {
    console.error('Set PUBLIC_BASE to the https URL of your tunnel (e.g. https://abcd.ngrok.app).');
    process.exit(1);
}
const hostname = new URL(PUBLIC_BASE).hostname;
const nonce = 'nonce-' + Date.now();

// ---------------------------------------------------------------------------
// Key + cert generation (duplicates tests/fixtures/crypto-helpers.ts logic
// because this is plain JS and cannot import the TS test helpers directly).
// ---------------------------------------------------------------------------

const signer = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
);

const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${hostname}`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 3600_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: signer,
    extensions: [
        new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: hostname }]),
    ],
});
const certificateChain = [new Uint8Array(cert.rawData)];

const encKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits', 'deriveKey'],
);
const encryptionPublicJwk = await crypto.subtle.exportKey('jwk', encKeyPair.publicKey);
encryptionPublicJwk.alg = 'ECDH-ES';
encryptionPublicJwk.use = 'enc';
const decryptionKey = encKeyPair.privateKey;

// ---------------------------------------------------------------------------
// DCQL query and authorization request
// ---------------------------------------------------------------------------

const dcqlQuery = {
    credentials: [
        {
            id: 'pid',
            format: 'dc+sd-jwt',
            meta: { vct_values: ['urn:eudi:pid:1'] },
            claims: [{ path: ['given_name'] }],
        },
    ],
};

const req = await createSignedAuthorizationRequest(
    {
        hostname,
        requestUri: `${PUBLIC_BASE}/request.jwt`,
        responseUri: `${PUBLIC_BASE}/response`,
        nonce,
        signer,
        certificateChain,
        encryptionKey: { publicJwk: encryptionPublicJwk },
        vpFormatsSupported: {
            'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'] },
        },
    },
    dcqlQuery,
);

console.log('\n--- Configure the OIDF demo test plan with these values ---');
console.log('client_id:    ', `x509_san_dns:${hostname}`);
console.log('request_uri:  ', `${PUBLIC_BASE}/request.jwt`);
console.log('response_uri: ', `${PUBLIC_BASE}/response`);
console.log('Short URI:    ', req.uri);
console.log('\nServer listening on port', PORT, '\n');

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

http.createServer(async (request, response) => {
    const u = new URL(request.url ?? '/', `http://localhost:${PORT}`);

    if (u.pathname === '/request.jwt' && request.method === 'GET') {
        response.writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt' });
        response.end(req.requestObject);
        return;
    }

    if (u.pathname === '/response' && request.method === 'POST') {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const body = Buffer.concat(chunks).toString('utf8');
        console.log('\n--- /response POST body ---');
        console.log(body);
        console.log('---');

        try {
            const form = new URLSearchParams(body);
            const jwe = form.get('response');
            if (!jwe) {
                console.error('Expected form-encoded `response=<JWE>` (direct_post.jwt)');
                response.writeHead(400);
                response.end();
                return;
            }

            const result = await verifyAuthorizationResponse(
                { response: jwe },
                dcqlQuery,
                {
                    // TODO: set to the OIDF fake-wallet's issuer cert DER bytes
                    // once known. Empty array may cause trust-check failure but
                    // reveals whether the crypto layer round-trips correctly.
                    trustedCertificates: [],
                    nonce,
                    decryptionKey,
                },
            );
            console.log('\n--- Verification result ---');
            console.log(JSON.stringify(result, null, 2));
            response.writeHead(200, { 'Content-Type': 'application/json' });
            response.end('{}');
        } catch (err) {
            console.error('\nVerification threw:', err);
            response.writeHead(500);
            response.end();
        }
        return;
    }

    response.writeHead(404);
    response.end();
}).listen(PORT);
