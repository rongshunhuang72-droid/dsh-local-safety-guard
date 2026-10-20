import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { apply } from '../index.mjs';

const app = process.argv[2];
if (!app || !path.isAbsolute(app)) throw new Error('Provide the absolute installed DSH application directory.');
const runtime = path.join(app, 'resources', 'app.asar', 'dsh');
const require = createRequire(path.join(runtime, 'package.json'));
const { Context } = require('@deepseek-ai/cordis');
const { default: ToolRuntime } = await import(pathToFileURL(path.join(runtime, 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js')).href);
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-guard-runtime-probe-'));
const workspace = path.join(temporary, 'workspace');
const data = path.join(temporary, 'guard');
for (const directory of [workspace, data]) fs.mkdirSync(directory);
fs.writeFileSync(path.join(data, 'policy.json'), JSON.stringify({ version: 1, allowedWorkspaces: [workspace], maxBackupBytes: 1024, maxDestructivePerSession: 1 }));
const ctx = new Context();
ctx.provide('systemPrompt', { tools: () => () => {} });
ctx.plugin(ToolRuntime);
await new Promise(resolve => setTimeout(resolve, 20));
assert.ok(ctx.tools, 'official tool runtime initialized');
ctx.provide('workingDirectory', { get: session => session.header.cwd });
ctx.provide('sandboxPolicy', { resolve: () => ({ mode: 'workspace-write' }) });
ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }));
apply(ctx, { dataDirectory: data });
let bodyCalls = 0;
const names = ['pwsh', 'bash', 'run_unsafe', 'cordis', 'jobs_start'];
for (const name of names) {
  ctx.tools.register({ name, description: 'Test sentinel; must never execute', parameters: { type: 'object', additionalProperties: true },
    output: { schema: { type: 'object', additionalProperties: true }, render: () => [{ type: 'text', text: 'unexpected body entry' }] },
    execute: async () => { bodyCalls++; return {}; },
  });
}
for (const name of names) {
  const result = await ctx.tools.execute({ name, arguments: { command: 'not executed' }, callId: `probe-${name}`, signal: new AbortController().signal });
  assert.equal(result.isError, true);
  assert.match(JSON.stringify(result), /DSH安全防护/);
}
assert.equal(bodyCalls, 0);
const status = await ctx.tools.execute({ name: 'safety_status', arguments: {}, callId: 'probe-status', signal: new AbortController().signal });
assert.equal(status.isError, false);
assert.equal(status.value.active, true);
console.log(JSON.stringify({ passed: true, deniedTools: names.length, rejectedToolBodiesExecuted: bodyCalls, temporaryData: temporary }));
await ctx.fiber.dispose();
