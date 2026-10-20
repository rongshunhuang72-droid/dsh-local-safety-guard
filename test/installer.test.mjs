import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const repository = path.resolve(import.meta.dirname, '..');
const powershell = process.env.DSH_GUARD_TEST_POWERSHELL ?? 'powershell.exe';
const run = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-guard-installer-test-'));
const app = path.join(run, 'fixture app');
const cliDirectory = path.join(app, 'resources', 'runtime', 'cli', 'bin');
const workspace = path.join(run, 'fixture workspace');
const home = path.join(run, 'fixture home');
const profile = path.join(home, 'profiles', 'desktop');
for (const directory of [cliDirectory, workspace, profile]) fs.mkdirSync(directory, { recursive: true });
const exe = path.join(app, 'fixture-dsh.exe');
fs.writeFileSync(exe, 'not an executable; only a path fixture');
fs.writeFileSync(path.join(cliDirectory, 'dsh.cmd'), `@"${process.execPath}" "%~dp0cli-stub.mjs" %*\r\n`);
// A local test double, never an actual DSH installation or model call.
fs.writeFileSync(path.join(cliDirectory, 'cli-stub.mjs'), `
import fs from 'node:fs'; import path from 'node:path';
const args = process.argv.slice(2);
if (args[0] !== 'plugin' || args[1] !== '--profile' || args[3] !== 'add' || !args[4]?.startsWith('file:')) throw Error('bad stub arguments');
const profile = path.join(process.env.DSH_HOME, 'profiles', args[2]);
const source = args[4].slice(5);
const manifestPath = path.join(profile, 'package.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
manifest.dependencies['dsh-local-safety-guard'] = args[4];
manifest.dsh.profile.bundles.push('dsh-local-safety-guard');
fs.writeFileSync(manifestPath, JSON.stringify(manifest));
const installed = path.join(profile, 'node_modules', 'dsh-local-safety-guard');
fs.mkdirSync(installed, {recursive:true});
for (const name of ['package.json','index.mjs','engine.mjs','policy.mjs','restore.mjs','cordis.patch.yml']) fs.copyFileSync(path.join(source,name),path.join(installed,name));
`);
const baseline = { name: 'fixture-profile', private: true, dependencies: { 'existing-pet': '^1.0.0' }, dsh: { profile: { bundles: ['existing-pet'] } } };
fs.writeFileSync(path.join(profile, 'package.json'), JSON.stringify(baseline));
fs.writeFileSync(path.join(home, 'AGENTS.md'), 'Original global rules.\n');
fs.writeFileSync(path.join(workspace, 'AGENTS.md'), 'Original project rules.\n');
fs.writeFileSync(path.join(home, '.credentials.yaml'), 'fixture-only-do-not-copy');
const invoke = (guard, roots = [workspace], options = ['-PlanOnly']) => spawnSync(powershell, [
  '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(repository, 'Install-DSHGuard.ps1'),
  '-DshExe', exe, '-Workspace', ...roots, '-GuardDirectory', guard, '-DshHome', home, ...options,
], { encoding: 'utf8', timeout: 30000 });

test('both PowerShell scripts parse under Windows PowerShell', () => {
  for (const name of ['Install-DSHGuard.ps1', 'Test-DSHGuard.ps1']) {
    const file = path.join(repository, name).replaceAll("'", "''");
    const script = `$errors=$null; $tokens=$null; [System.Management.Automation.Language.Parser]::ParseFile('${file}',[ref]$tokens,[ref]$errors) | Out-Null; if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }`;
    const result = spawnSync(powershell, ['-NoLogo', '-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
  }
});

test('installer plan handles spaces and writes nothing', () => {
  const guard = path.join(run, 'planned guard');
  const result = invoke(guard);
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.deepEqual(plan.allowedWorkspaces, [workspace]);
  assert.equal(plan.guardDirectory, guard);
  assert.equal(fs.existsSync(guard), false);
  assert.equal(fs.readFileSync(path.join(workspace, 'AGENTS.md'), 'utf8'), 'Original project rules.\n');
});

test('installer rejects workspace overlapping installation paths', () => {
  const result = invoke(path.join(run, 'guard'), [run]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /overlaps protected/i);
});

test('installer rejects drive roots and guard inside repository', () => {
  assert.notEqual(invoke(path.join(run, 'guard'), [path.parse(run).root]).status, 0);
  const result = invoke(path.join(repository, 'never-created'));
  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(path.join(repository, 'never-created')), false);
});

test('installer refuses existing target instead of overwriting it', () => {
  const guard = path.join(run, 'existing guard');
  fs.mkdirSync(guard);
  fs.writeFileSync(path.join(guard, 'keep.txt'), 'keep');
  const result = invoke(guard, [workspace], []);
  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(path.join(guard, 'keep.txt'), 'utf8'), 'keep');
});

test('installer assembles a new machine configuration with a local CLI stub', () => {
  const guard = path.join(run, 'installed guard');
  const result = invoke(guard, [workspace], []);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const policy = JSON.parse(fs.readFileSync(path.join(guard, 'policy.json'), 'utf8'));
  assert.deepEqual(policy.allowedWorkspaces, [workspace]);
  assert.equal(policy.maxDestructivePerSession, 1);
  const patch = fs.readFileSync(path.join(guard, 'cordis.patch.yml'), 'utf8');
  assert.ok(patch.includes(`dataDirectory: '${guard}'`));
  const manifest = JSON.parse(fs.readFileSync(path.join(profile, 'package.json'), 'utf8'));
  assert.equal(manifest.dependencies['existing-pet'], '^1.0.0');
  assert.ok(manifest.dsh.profile.bundles.includes('existing-pet'));
  assert.ok(manifest.dsh.profile.bundles.includes('dsh-local-safety-guard'));
  assert.match(fs.readFileSync(path.join(home, 'AGENTS.md'), 'utf8'), /^Original global rules\./);
  assert.match(fs.readFileSync(path.join(workspace, 'AGENTS.md'), 'utf8'), /DSH-LOCAL-SAFETY-GUARD:BEGIN/);
  const backups = fs.readdirSync(path.join(guard, 'install-backup'));
  assert.equal(backups.length, 1);
  assert.ok(!fs.readdirSync(path.join(guard, 'install-backup', backups[0])).includes('.credentials.yaml'));
  assert.equal(fs.readFileSync(path.join(home, '.credentials.yaml'), 'utf8'), 'fixture-only-do-not-copy');
  assert.equal(fs.existsSync(path.join(guard, 'records', 'active.json')), false, 'installation must not claim runtime activation');
});

test('checker refuses a forged active receipt from the wrong process', () => {
  const guard = path.join(run, 'installed guard');
  fs.mkdirSync(path.join(guard, 'records'));
  fs.writeFileSync(path.join(guard, 'records', 'active.json'), JSON.stringify({ active: true, processId: process.pid, startedAt: new Date().toISOString() }));
  const result = spawnSync(powershell, ['-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(repository, 'Test-DSHGuard.ps1'), '-GuardDirectory', guard], { encoding: 'utf8', timeout: 15000 });
  assert.notEqual(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.receiptActive, true);
  assert.equal(report.liveOfficialHost, false);
  assert.equal(report.active, false);
});
