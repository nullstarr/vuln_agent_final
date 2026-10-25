# Third-party notice: Meterless World Model reference engine

`world-model.mjs` is the **unmodified** TypeScript reference implementation of the Meterless World Model
(`engines/world-model/reference/src`), bundled into a single JavaScript file with esbuild so that it runs
with plain Node.js (no `npm install`).

- Source: https://github.com/Meterless/Meterless  (Apache-2.0, see `LICENSE` in this folder)
- Commit: `0aa7417ba5c826396d91e891328be78c45e6fbf6` (2026-07-22T16:14:36-07:00)
- Rebuild: `cd engines/world-model/reference && npm install && npx esbuild src/index.ts --bundle --platform=node --format=esm --target=node18 --outfile=world-model.mjs`
- Copyright remains with the Meterless authors. No changes were made to the engine.

`bridge.mjs` is ours: a small JSON-lines wrapper that lets the Python pipeline call the engine.
