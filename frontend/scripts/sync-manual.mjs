// Sync the user-manual source-of-truth into the frontend tree so Vite can
// bundle it into the SPA.
//
// Canonical content lives at <repo>/docs/user-manual/ (markdown + assets/) so it
// is discoverable and editable without digging into the frontend. The React
// manual feature (the manifest in src/manual/index.ts, the asset map in
// src/manual/assets/index.ts, and the render components) stays in the frontend
// and imports the COPIES this script writes:
//   docs/user-manual/*.md          -> frontend/src/manual/content/*.md   (gitignored)
//   docs/user-manual/assets/*.png  -> frontend/src/manual/assets/*.png   (gitignored)
//
// Runs automatically on `predev` and `prebuild` (see package.json). Run by hand
// with `npm run sync-manual` after editing a manual page in dev.
//
// Source resolution (no env var needed): the path is computed relative to this
// script, which lands at the same place on host and in containers —
//   host:           <repo>/frontend/scripts -> ../../docs/user-manual = <repo>/docs/user-manual
//   dev container:  /app/scripts             -> ../../docs/user-manual = /docs/user-manual  (compose-mounted)
//   prod build:     /app/scripts             -> ../../docs/user-manual = /docs/user-manual  (Dockerfile COPY)
// Override with MANUAL_SRC_DIR if you need a non-default location.

import { cpSync, mkdirSync, readdirSync, rmSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = process.env.MANUAL_SRC_DIR
  ? resolve(process.env.MANUAL_SRC_DIR)
  : resolve(here, "../../docs/user-manual");
const CONTENT_DEST = resolve(here, "../src/manual/content");
const ASSETS_DEST = resolve(here, "../src/manual/assets");

if (!existsSync(SRC)) {
  console.error(
    `[sync-manual] manual source not found: ${SRC}\n` +
      `  Set MANUAL_SRC_DIR, or ensure docs/user-manual/ is present ` +
      `(dev: compose-mounted at /docs/user-manual; prod: COPYed in the Dockerfile).`,
  );
  process.exit(1);
}

// Markdown -> src/manual/content/ (clean rebuild so deletions propagate).
rmSync(CONTENT_DEST, { recursive: true, force: true });
mkdirSync(CONTENT_DEST, { recursive: true });
const mdFiles = readdirSync(SRC).filter((f) => f.endsWith(".md"));
for (const f of mdFiles) cpSync(join(SRC, f), join(CONTENT_DEST, f));

// Assets (.png/.jpg/.svg) -> src/manual/assets/ (alongside the committed
// index.ts asset map). We do NOT wipe ASSETS_DEST because index.ts lives there.
const assetsSrc = join(SRC, "assets");
let assetCount = 0;
if (existsSync(assetsSrc)) {
  mkdirSync(ASSETS_DEST, { recursive: true });
  for (const f of readdirSync(assetsSrc)) {
    if (/\.(png|jpe?g|svg|webp|gif)$/i.test(f)) {
      cpSync(join(assetsSrc, f), join(ASSETS_DEST, f));
      assetCount++;
    }
  }
}

console.log(
  `[sync-manual] copied ${mdFiles.length} markdown + ${assetCount} asset file(s) ` +
    `from ${SRC}`,
);
