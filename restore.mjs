import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { checkedPath, loadPolicy } from './policy.mjs';
import { SafetyEngine } from './engine.mjs';

const [id, option] = process.argv.slice(2);
if (!/^\d+-[a-f0-9-]{36}$/i.test(id ?? '') || option !== undefined && option !== '--overwrite') {
  throw new Error('Usage: node restore.mjs <backup-id> [--overwrite]');
}
const directory = import.meta.dirname;
const metadata = JSON.parse(fs.readFileSync(path.join(directory, 'backups', `${id}.json`), 'utf8'));
const content = fs.readFileSync(path.join(directory, 'backups', `${id}.bin`));
if (metadata.id !== id || crypto.createHash('sha256').update(content).digest('hex') !== metadata.sha256) throw new Error('Backup verification failed.');
const context = { root: metadata.root, cwd: metadata.root, mode: 'workspace-write', sessionId: 'manual-restore' };
const target = checkedPath(loadPolicy(path.join(directory, 'policy.json')), context, metadata.file, { mutation: true });
if (target.stat && option !== '--overwrite') throw new Error('Target exists. Inspect it first; --overwrite explicitly replaces this one file.');
if (target.stat) new SafetyEngine(directory, () => context).backup(target.target, context, 'before-manual-restore');
fs.copyFileSync(path.join(directory, 'backups', `${id}.bin`), target.target, target.stat ? 0 : fs.constants.COPYFILE_EXCL);
console.log(JSON.stringify({ restored: target.target, backupId: id }));
