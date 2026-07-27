import { readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const buildRoot = join(packageRoot, ".medusa/server");
const inlineSourceMap =
  /\r?\n?\/\/[#@] sourceMappingURL=data:application\/json(?:;charset=[^;,]+)?;base64,[^\r\n]*(?:\r?\n)?/g;
let stripped = 0;

async function visit(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      await visit(path);
      continue;
    }
    if (![".js", ".cjs", ".mjs"].includes(extname(entry.name))) {
      continue;
    }
    const source = await readFile(path, "utf8");
    const output = source.replace(inlineSourceMap, "\n");
    if (output !== source) {
      await writeFile(path, output);
      stripped += 1;
    }
  }
}

await visit(buildRoot);
console.log(`Removed inline source maps from ${stripped} compiled files.`);
