import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDir, "..");
const srcDir = path.join(projectRoot, "src");
const distDir = path.join(projectRoot, "dist");

const FORBIDDEN_DIST_PATTERNS = [
  "/api/login",
  "/api/servers",
  "/api/monitor",
  "/api/settings",
  "/api/nodes",
  "/api/subscriptions",
  "/agent/",
  "/download/",
  "X-Requested-With",
  "csrf",
];

function walkFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkFiles(full));
    } else if (entry.isFile()) {
      results.push(full);
    }
  }
  return results;
}

function extractImportSpecifiers(content) {
  const specs = [];
  const patterns = [
    /\b(?:import|export)\s+(?:[^"'`]*?\s+from\s+)?["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
    /@import\s+["']([^"']+)["']/g,
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) {
      specs.push(m[1]);
    }
  }
  return specs;
}

const errors = [];

// 1. Check status-web/src import boundaries
const srcFiles = walkFiles(srcDir);
for (const file of srcFiles) {
  const relFile = path.relative(projectRoot, file);
  const content = readFileSync(file, "utf8");
  for (const spec of extractImportSpecifiers(content)) {
    if (spec.includes("../web") || spec.startsWith("../../")) {
      errors.push(`${relFile}: forbidden import path "${spec}"`);
      continue;
    }
    if (spec.startsWith(".")) {
      const resolved = path.resolve(path.dirname(file), spec);
      const relToRoot = path.relative(projectRoot, resolved);
      if (relToRoot.startsWith("..") || path.isAbsolute(relToRoot)) {
        errors.push(`${relFile}: import "${spec}" escapes status-web (${resolved})`);
      }
    }
  }
}

// 2. Check status-web/dist bundle contents
let distStat;
try {
  distStat = statSync(distDir);
} catch {
  errors.push(`dist directory missing: ${distDir}`);
}

let distFiles = [];
if (distStat?.isDirectory()) {
  distFiles = walkFiles(distDir);
  if (distFiles.length === 0) {
    errors.push(`dist directory is empty: ${distDir}`);
  }
  for (const file of distFiles) {
    const relFile = path.relative(projectRoot, file);
    const text = readFileSync(file, "utf8");
    const lower = text.toLowerCase();
    for (const needle of FORBIDDEN_DIST_PATTERNS) {
      const matched =
        needle === "csrf" || needle === "X-Requested-With"
          ? lower.includes(needle.toLowerCase())
          : text.includes(needle);
      if (matched) {
        errors.push(`${relFile}: contains forbidden string "${needle}"`);
      }
    }
  }
}

if (errors.length > 0) {
  console.error("check-dist FAILED:");
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
}

console.log(
  `check-dist OK: verified ${srcFiles.length} source files in src/ and ${distFiles.length} built files in dist/ (0 boundary or leak violations).`,
);
