// Minimal, honest smoke check for the desktop UI: every JS module reachable
// from app.js must exist and parse as valid JavaScript, and app.js's import
// graph must not reference a file that isn't there. This replaces a test
// script that used to just print "passed" unconditionally.
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const jsRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'js');
const entry = path.join(jsRoot, 'app.js');

const visited = new Set();
const missing = [];
const syntaxErrors = [];

function walk(filePath) {
  if (visited.has(filePath)) return;
  visited.add(filePath);

  if (!existsSync(filePath)) {
    missing.push(filePath);
    return;
  }

  try {
    execFileSync(process.execPath, ['--check', filePath], { stdio: 'pipe' });
  } catch (err) {
    syntaxErrors.push({ filePath, message: err.stderr?.toString() || err.message });
    return;
  }

  const source = readFileSync(filePath, 'utf8');
  const importRe = /^import\s+.*?from\s+['"](\.[^'"]+)['"]/gm;
  let match;
  while ((match = importRe.exec(source))) {
    const resolved = path.resolve(path.dirname(filePath), match[1]);
    walk(resolved);
  }
}

walk(entry);

console.log(`Проверено модулей: ${visited.size}`);

if (missing.length > 0) {
  console.error('Отсутствующие файлы, на которые есть import:');
  for (const m of missing) console.error(`  - ${m}`);
}

if (syntaxErrors.length > 0) {
  console.error('Синтаксические ошибки:');
  for (const e of syntaxErrors) console.error(`  - ${e.filePath}\n${e.message}`);
}

if (missing.length > 0 || syntaxErrors.length > 0) {
  process.exit(1);
}

console.log('OK: все модули из графа импортов app.js существуют и синтаксически валидны.');
