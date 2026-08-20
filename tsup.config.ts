import { defineConfig } from 'tsup';

export default defineConfig({
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    treeshake: true,
    outDir: 'dist',
    // `src/index.ts` imports 'reflect-metadata' as its first statement, but that
    // is not enough on its own: the bundler hoists external *named* imports
    // (e.g. `@peculiar/x509`) above bare side-effect imports, so in the emitted
    // bundle @peculiar/x509 — and therefore tsyringe — evaluated BEFORE the
    // polyfill was installed, and importing the package threw
    // "tsyringe requires a reflect polyfill" unless the consumer preloaded it.
    //
    // esbuild's `inject` is evaluated ahead of the entry module in both the ESM
    // and CJS output, which is exactly the guarantee we need. Verified by
    // tests/bundle-polyfill-order.test.ts, which imports the built bundles in a
    // clean child process with no preload.
    inject: ['src/reflect-polyfill.ts'],
});
