import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ctfDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'js', 'ctf');

const files = [
  'ctf_ipc.js',
  'workspace_store.js',
  'hex_store.js',
  'job_runner_store.js',
  'recipe_store.js',
  'flag_store.js',
  'writeup_store.js'
];

console.log('--- Checking CTF modules syntax with node --check ---');
let hasError = false;

for (const file of files) {
  const fullPath = path.join(ctfDir, file);
  try {
    execFileSync(process.execPath, ['--check', fullPath], { stdio: 'pipe' });
    console.log(`[PASS] ${file}`);
  } catch (err) {
    console.error(`[FAIL] ${file}:\n${err.stderr?.toString() || err.message}`);
    hasError = true;
  }
}

if (hasError) {
  process.exit(1);
}

console.log('--- Testing module exports and instantiations ---');
try {
  const { CtfIpcClient, ctfIpc } = await import('../js/ctf/ctf_ipc.js');
  const { WorkspaceStore, workspaceStore } = await import('../js/ctf/workspace_store.js');
  const { HexStore, hexStore } = await import('../js/ctf/hex_store.js');
  const { JobRunnerStore, jobRunnerStore, TerminalRingBuffer } = await import('../js/ctf/job_runner_store.js');
  const { RecipeStore, recipeStore } = await import('../js/ctf/recipe_store.js');
  const { FlagStore, flagStore } = await import('../js/ctf/flag_store.js');
  const { WriteupStore, writeupStore } = await import('../js/ctf/writeup_store.js');

  console.log('[PASS] All 7 CTF modules imported cleanly.');

  // Test ring buffer
  const ring = new TerminalRingBuffer('test-job');
  ring.append('Hello world\nSecond line\n');
  if (ring.lines.length !== 3 || ring.droppedBytes !== 0) {
    throw new Error('TerminalRingBuffer logic error');
  }
  console.log('[PASS] TerminalRingBuffer unit check passed.');

  // Test Recipe in-memory transforms
  recipeStore.setInputData('SGVsbG8gV29ybGQ=');
  recipeStore.addOperation({ operation: 'base64_decode' });
  if (recipeStore.getState().livePreviewText !== 'Hello World') {
    throw new Error(`RecipeStore base64_decode mismatch: got "${recipeStore.getState().livePreviewText}"`);
  }
  console.log('[PASS] RecipeStore in-memory pipeline unit check passed.');

  // Test Recipe flag scanner
  recipeStore.setInputData('Here is your secret: CTF{s0m3_fl4g_v4lu3}');
  recipeStore.clearOperations();
  const flags = recipeStore.getState().detectedFlags;
  if (!flags.includes('CTF{s0m3_fl4g_v4lu3}')) {
    throw new Error('RecipeStore flag scanner failed to detect CTF flag');
  }
  console.log('[PASS] RecipeStore flag scanner unit check passed.');

  // Test Writeup secret redaction
  const redacted = writeupStore.redactSecrets('password="supersecret123" and api_key="abc123xyz"');
  if (redacted.includes('supersecret123') || !redacted.includes('[REDACTED]')) {
    throw new Error('WriteupStore secret redaction failed');
  }
  console.log('[PASS] WriteupStore redaction unit check passed.');

  console.log('ALL CTF MODULE CHECKS PASSED SUCCESSFULLY!');
} catch (e) {
  console.error('[FAIL] Runtime instantiation check error:', e);
  process.exit(1);
}
