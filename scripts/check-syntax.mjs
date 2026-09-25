// check-syntax.mjs - Comprehensive syntax and import graph smoke check
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const uiJsRoot = path.join(projectRoot, 'apps', 'desktop-ui', 'js');

const checked = new Set();
const missing = [];
const syntaxErrors = [];

function checkFile(filePath) {
  if (checked.has(filePath)) return;
  checked.add(filePath);

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
  const importRe = /^(?:import|export)\s+.*?from\s+['"](\.[^'"]+)['"]/gm;
  let match;
  while ((match = importRe.exec(source))) {
    const resolved = path.resolve(path.dirname(filePath), match[1]);
    checkFile(resolved);
  }
}

// 1. Walk app.js entrypoint
const entry = path.join(uiJsRoot, 'app.js');
if (existsSync(entry)) {
  checkFile(entry);
}

// 2. Recursively check all js files under apps/desktop-ui/js/ctf
function scanDir(dir) {
  if (!existsSync(dir)) return;
  const entries = readdirSync(dir);
  for (const name of entries) {
    const fullPath = path.join(dir, name);
    const st = statSync(fullPath);
    if (st.isDirectory()) {
      scanDir(fullPath);
    } else if (name.endsWith('.js') || name.endsWith('.mjs')) {
      checkFile(fullPath);
    }
  }
}

scanDir(path.join(uiJsRoot, 'ctf'));

console.log(`Проверено модулей: ${checked.size}`);

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

console.log('OK: все JS модули платформы существуют и синтаксически валидны.');
