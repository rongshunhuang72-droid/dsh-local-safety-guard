import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { classify, loadPolicy, checkedPath } from '../policy.mjs';
import { SafetyEngine } from '../engine.mjs';

// Fixtures are retained: this suite never recursively deletes any directory.
const run = path.resolve(import.meta.dirname, '..', '.test-runs', `${Date.now()}-${crypto.randomUUID()}`);
const root = path.join(run, 'workspace');
const outside = path.join(run, 'outside');
const installation = path.join(run, 'guard');
for (const directory of [root, outside, installation]) fs.mkdirSync(directory, { recursive: true });
const policy = { version: 1, allowedWorkspaces: [root], maxBackupBytes: 1024, maxDestructivePerSession: 1, gitExecutable: process.execPath };
fs.writeFileSync(path.join(installation, 'policy.json'), JSON.stringify(policy));
fs.writeFileSync(path.join(root, 'sample.txt'), 'original');
fs.writeFileSync(path.join(outside, 'important.txt'), 'important');
const context = { root, cwd: root, mode: 'workspace-write', sessionId: 'session-test' };
const engine = new SafetyEngine(installation, execution => execution.context ?? context);
const exec = (name, args, sessionId = context.sessionId) => ({ name, arguments: args, callId: crypto.randomUUID(), signal: new AbortController().signal, context: { ...context, sessionId } });
const deny = (name, args, ctx = context) => assert.match(classify(policy, name, args, ctx), /^\[DSH安全防护\]/);
const allow = (name, args, ctx = context) => assert.equal(classify(policy, name, args, ctx), undefined);

for (const [tool, command] of [
  ['pwsh', 'Remove-Item -Recurse C:\\Users'], ['pwsh', 'Get-ChildItem | ForEach-Object { Remove-Item $_ }'],
  ['bash', 'rm -rf /'], ['pwsh', 'python -c "import shutil; shutil.rmtree(\"x\")"'],
  ['pwsh', 'node -e "require(\"fs\").rmSync(\"x\",{recursive:true})"'],
  ['pwsh', 'cmd /c del /s x'], ['pwsh', 'robocopy C:\\Users D:\\out /MOVE'],
  ['pwsh', 'icacls C:\\Users /grant Everyone:F'], ['pwsh', 'git clean -fdx'],
  ['pwsh', 'npm run build'], ['terminal_write', 'del x'], ['run_code', 'await tools.pwsh({command:"del x"})'],
  ['mcp_filesystem_delete', 'x'], ['cordis', 'disable guard'], ['spawn_agent', 'run deletion'],
  ['jobs_start', 'start script'], ['computer_use', 'edit guard settings'],
]) test(`blocks execution/bypass: ${tool}: ${command}`, () => deny(tool, { command }));

for (const file_path of [
  ['sample.txt', 'another.txt'], '*.txt', 'folder\\*', root, path.join(outside, 'important.txt'),
  'sample.txt:payload', '\\\\server\\share\\file', '\\\\?\\C:\\x', 'CON', 'foo. ',
  'AGENTS.md', '.dsh/cordis.patch.yml', '.git/config', '.env', '.env.production',
]) test(`rejects unsafe mutation path: ${JSON.stringify(file_path)}`, () => deny('write', { file_path, content: 'changed' }));

test('allows scoped reads, searches, edits and directory listing', () => {
  allow('read', { file_path: 'sample.txt' }); allow('write', { file_path: 'new.txt', content: 'new' });
  allow('edit', { file_path: 'sample.txt', old_string: 'original', new_string: 'new' });
  allow('glob', { pattern: '**/*.txt' }); allow('grep', { pattern: 'original' });
  allow('safety_list_directory', {});
  assert.equal(engine.list(exec('safety_list_directory', {})).entries[0].name, 'sample.txt');
});
test('blocks escalation, full access, missing context, unapproved roots and clearing files', () => {
  deny('read', { file_path: 'sample.txt', sandbox_permissions: 'danger-full-access' });
  deny('write', { file_path: 'new.txt', content: 'x' }, { ...context, mode: 'danger-full-access' });
  deny('write', { file_path: 'new.txt', content: 'x' }, { ...context, mode: 'read-only' });
  deny('read', { file_path: 'sample.txt' }, null);
  deny('read', { file_path: 'sample.txt' }, { ...context, root: outside, cwd: outside });
  deny('write', { file_path: 'sample.txt', content: '' });
});
test('blocks directory links and file hardlinks', () => {
  fs.symlinkSync(outside, path.join(root, 'linked'), 'junction');
  deny('write', { file_path: 'linked/important.txt', content: 'changed' });
  fs.linkSync(path.join(outside, 'important.txt'), path.join(root, 'hardlink.txt'));
  deny('write', { file_path: 'hardlink.txt', content: 'changed' });
  assert.equal(fs.readFileSync(path.join(outside, 'important.txt'), 'utf8'), 'important');
});

test('blocks whitespace writes and edits that erase an entire file', () => {
  deny('write', { file_path: 'sample.txt', content: ' \r\n\t' });
  deny('edit', { file_path: 'sample.txt', old_string: 'original', new_string: '' });
  deny('edit', { file_path: 'sample.txt', old_string: 'original', new_string: '\n' });
  allow('edit', { file_path: 'sample.txt', old_string: 'original', new_string: 'revised' });
});

test('blocks even read-looking external program entry points', () => {
  deny('safety_git', { operation: 'status' });
  deny('git', { command: 'diff --no-ext-diff' });
});
test('backs up existing content before an edit', () => {
  const before = fs.readdirSync(path.join(installation), { withFileTypes: true }).length;
  const request = exec('edit', { file_path: 'sample.txt', old_string: 'original', new_string: 'edited' });
  engine.beforeDispatch(request);
  const backups = fs.readdirSync(path.join(installation, 'backups')).filter(x => x.endsWith('.bin'));
  assert.equal(backups.length, 1);
  assert.equal(fs.readFileSync(path.join(installation, 'backups', backups[0]), 'utf8'), 'original');
  assert.equal(fs.readFileSync(path.join(root, 'sample.txt'), 'utf8'), 'original');
  assert.ok(before > 0);
});
test('quarantines exactly one file and persists the per-session limit across restarts', () => {
  fs.writeFileSync(path.join(root, 'discard.txt'), 'recover me');
  fs.writeFileSync(path.join(root, 'keep.txt'), 'keep me');
  const result = engine.mutateFile(exec('safety_remove_file', { file_path: 'discard.txt' }, 'remove-session'));
  assert.equal(result.status, 'quarantined');
  assert.equal(fs.existsSync(path.join(root, 'discard.txt')), false);
  assert.equal(fs.readFileSync(result.quarantine, 'utf8'), 'recover me');
  const restarted = new SafetyEngine(installation, x => x.context);
  assert.throws(() => restarted.mutateFile(exec('safety_remove_file', { file_path: 'keep.txt' }, 'remove-session')), /本会话已使用/);
  assert.equal(fs.readFileSync(path.join(root, 'keep.txt'), 'utf8'), 'keep me');
});
test('moves one file, preserving content and refusing overwrite/cross-workspace/directory moves', () => {
  fs.writeFileSync(path.join(root, 'move.txt'), 'move me');
  deny('safety_move_file', { file_path: 'move.txt', destination: 'sample.txt' });
  deny('safety_move_file', { file_path: 'move.txt', destination: path.join(outside, 'moved.txt') });
  deny('safety_move_file', { file_path: '.', destination: 'folder' });
  const result = engine.mutateFile(exec('safety_move_file', { file_path: 'move.txt', destination: 'moved.txt' }, 'move-session'));
  assert.equal(result.status, 'moved');
  assert.equal(fs.readFileSync(path.join(root, 'moved.txt'), 'utf8'), 'move me');
  assert.equal(fs.existsSync(path.join(root, 'move.txt')), false);
});
test('fails closed on malformed policy and rejects oversized file modifications', () => {
  fs.writeFileSync(path.join(root, 'large.txt'), 'x'.repeat(1025));
  deny('write', { file_path: 'large.txt', content: 'changed' });
  fs.writeFileSync(path.join(installation, 'policy.json'), 'broken');
  assert.match(engine.check(exec('read', { file_path: 'sample.txt' })), /策略\/上下文读取失败/);
  assert.throws(() => loadPolicy(path.join(installation, 'policy.json')));
});
test('unknown native deletion cannot affect the outside sentinel', () => {
  assert.equal(fs.readFileSync(path.join(outside, 'important.txt'), 'utf8'), 'important');
});
