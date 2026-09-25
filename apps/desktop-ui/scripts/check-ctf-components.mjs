import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));
const componentsDir = path.join(scriptsDir, '..', 'js', 'ctf', 'components');
const cssPath = path.join(scriptsDir, '..', 'css', 'ctf.css');

console.log('=== 1. Checking Line Count Limits (< 500 lines) ===');
let hasLineLimitError = false;

// Check CSS
const cssLines = readFileSync(cssPath, 'utf8').split('\n').length;
console.log(`[CSS] ctf.css: ${cssLines} lines (< 500)`);
if (cssLines >= 500) {
  console.error(`[FAIL] ctf.css exceeds 500 lines: ${cssLines}`);
  hasLineLimitError = true;
}

// Check JS Components
const jsFiles = readdirSync(componentsDir).filter((f) => f.endsWith('.js'));
for (const file of jsFiles) {
  const filePath = path.join(componentsDir, file);
  const lines = readFileSync(filePath, 'utf8').split('\n').length;
  console.log(`[JS] ${file}: ${lines} lines (< 500)`);
  if (lines >= 500) {
    console.error(`[FAIL] ${file} exceeds 500 lines: ${lines}`);
    hasLineLimitError = true;
  }
}

if (hasLineLimitError) {
  process.exit(1);
}

console.log('=== 2. Checking Component Syntax with node --check ===');
let hasSyntaxError = false;

for (const file of jsFiles) {
  const filePath = path.join(componentsDir, file);
  try {
    execFileSync(process.execPath, ['--check', filePath], { stdio: 'pipe' });
    console.log(`[PASS] ${file}`);
  } catch (err) {
    console.error(`[FAIL] ${file}:\n${err.stderr?.toString() || err.message}`);
    hasSyntaxError = true;
  }
}

if (hasSyntaxError) {
  process.exit(1);
}

console.log('=== 3. Testing Component Exports & Instantiation ===');
try {
  const {
    ChallengeMatrix,
    WorkspaceView,
    TerminalView,
    RecipeBuilder,
    FlagDrawer,
    WriteupView
  } = await import('../js/ctf/components/index.js');

  const components = [
    { name: 'ChallengeMatrix', cls: ChallengeMatrix },
    { name: 'WorkspaceView', cls: WorkspaceView },
    { name: 'TerminalView', cls: TerminalView },
    { name: 'RecipeBuilder', cls: RecipeBuilder },
    { name: 'FlagDrawer', cls: FlagDrawer },
    { name: 'WriteupView', cls: WriteupView }
  ];

  for (const { name, cls } of components) {
    if (typeof cls !== 'function') {
      throw new Error(`Export ${name} is not a constructor/class`);
    }
    const instance = new cls();
    if (typeof instance.mount !== 'function' || typeof instance.destroy !== 'function') {
      throw new Error(`Instance of ${name} does not implement mount/destroy lifecycle methods`);
    }
    console.log(`[PASS] ${name} class instantiated cleanly with mount/destroy lifecycle.`);
  }

  console.log('ALL CTF COMPONENT CHECKS PASSED SUCCESSFULLY!');
} catch (err) {
  console.error('[FAIL] Runtime instantiation error:', err);
  process.exit(1);
}
