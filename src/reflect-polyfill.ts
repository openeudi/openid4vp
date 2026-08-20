// Injected ahead of the entry module by tsup (`inject` in tsup.config.ts) so the
// reflect-metadata polyfill is installed before anything that pulls in
// @peculiar/x509 → tsyringe, which reads decorator metadata while its own module
// body evaluates. `src/index.ts` imports this polyfill too, for consumers that
// build from source rather than from dist.
//
// Keep this file side-effect-only: `inject` evaluates it for its side effects.
import 'reflect-metadata';
