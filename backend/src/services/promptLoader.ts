/**
 * Tiny prompt loader for the M6 LLM-mode SAST pass.
 *
 * Prompts live as Markdown files under `backend/prompts/` and use `{{KEY}}`
 * placeholders for runtime substitution. Missing variables throw at load
 * time so we never quietly send a half-baked prompt to the model.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PROMPTS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "prompts",
);

export class PromptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PromptError";
  }
}

const PLACEHOLDER_RE = /\{\{([A-Z0-9_]+)\}\}/g;

export function loadPrompt(name: string, vars: Record<string, string>): string {
  const filePath = path.join(PROMPTS_DIR, `${name}.md`);
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    throw new PromptError(`Cannot read prompt ${name} at ${filePath}: ${(err as Error).message}`);
  }

  const rendered = raw.replace(PLACEHOLDER_RE, (match, key: string) => {
    if (Object.prototype.hasOwnProperty.call(vars, key)) {
      return vars[key];
    }
    return match;
  });

  const unresolved = rendered.match(PLACEHOLDER_RE);
  if (unresolved && unresolved.length > 0) {
    const unique = [...new Set(unresolved)].join(", ");
    throw new PromptError(`Unresolved placeholders in prompt ${name}: ${unique}`);
  }

  return rendered;
}
