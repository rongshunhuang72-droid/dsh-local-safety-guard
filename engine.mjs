import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { checkedPath, classify, isMutation, loadPolicy, PREFIX, workspace } from './policy.mjs';

export class SafetyEngine {
  constructor(directory, contextOf) {
    this.directory = directory;
    this.contextOf = contextOf;
    this.policyFile = path.join(directory, 'policy.json');
  }
  policy() { return loadPolicy(this.policyFile); }
  audit(kind, exec, details = {}) {
    fs.mkdirSync(path.join(this.directory, 'records'), { recursive: true });
    fs.appendFileSync(path.join(this.directory, 'records', 'audit.jsonl'), JSON.stringify({
      time: new Date().toISOString(), kind, tool: exec.name,
      session: this.contextOf(exec)?.sessionId ?? null, ...details,
    }) + '\n', { encoding: 'utf8', mode: 0o600 });
  }
  check(exec) {
    try {
      const context = this.contextOf(exec);
      const reason = classify(this.policy(), exec.name, exec.arguments, context);
      if (reason) return reason;
      if (['safety_remove_file', 'safety_move_file'].includes(exec.name)) {
        if (!context?.sessionId) return PREFIX + '缺少会话身份，拒绝删除/移动。';
        const key = crypto.createHash('sha256').update(context.sessionId).digest('hex');
        if (fs.existsSync(path.join(this.directory, 'records', 'destructive-limits', `${key}.json`))) {
          return PREFIX + '本会话已使用一次删除/移动额度，禁止拆分批量操作。后续请用户手动操作或亲自新建会话。';
        }
      }
    }
    catch (error) { return PREFIX + `策略/上下文读取失败，拒绝执行：${error.message}`; }
  }
  requireAllowed(exec) {
    const reason = this.check(exec);
    if (reason) throw new Error(reason);
    exec.signal?.throwIfAborted();
    return { policy: this.policy(), context: this.contextOf(exec) };
  }
  backup(filename, context, kind = 'before-edit') {
    const bytes = fs.readFileSync(filename);
    if (bytes.length > this.policy().maxBackupBytes) throw new Error('文件超过备份上限，已停止修改。');
    const hash = crypto.createHash('sha256').update(bytes).digest('hex');
    const directory = path.join(this.directory, 'backups');
    fs.mkdirSync(directory, { recursive: true });
    const id = `${Date.now()}-${crypto.randomUUID()}`;
    fs.writeFileSync(path.join(directory, `${id}.bin`), bytes, { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(path.join(directory, `${id}.json`), JSON.stringify({
      id, kind, file: filename, root: context.root, time: new Date().toISOString(), sha256: hash, size: bytes.length,
    }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return id;
  }
  beforeDispatch(exec) {
    const { policy, context } = this.requireAllowed(exec);
    if ((exec.name === 'write' || exec.name === 'edit') && isMutation(exec.name, exec.arguments)) {
      const file = checkedPath(policy, context, exec.arguments.file_path ?? exec.arguments.path, { mutation: true });
      if (file.stat) {
        const backupId = this.backup(file.target, context);
        this.audit('backup', exec, { file: file.target, backupId });
      }
    }
  }
  reserveDestructive(exec, context) {
    if (typeof context.sessionId !== 'string' || !context.sessionId) throw new Error('缺少会话身份，拒绝删除/移动。');
    const key = crypto.createHash('sha256').update(context.sessionId).digest('hex');
    const directory = path.join(this.directory, 'records', 'destructive-limits');
    fs.mkdirSync(directory, { recursive: true });
    try {
      fs.writeFileSync(path.join(directory, `${key}.json`), JSON.stringify({
        session: context.sessionId, tool: exec.name, time: new Date().toISOString(), callId: exec.callId,
      }) + '\n', { flag: 'wx', mode: 0o600 });
    } catch (error) {
      if (error.code === 'EEXIST') throw new Error(PREFIX + '本会话已使用一次删除/移动额度，禁止拆分批量操作。后续请用户手动操作或亲自新建会话。');
      throw error;
    }
  }
  mutateFile(exec) {
    const { policy, context } = this.requireAllowed(exec);
    const source = checkedPath(policy, context, exec.arguments.file_path, { mutation: true, fileRequired: true });
    let destination;
    if (exec.name === 'safety_move_file') {
      destination = checkedPath(policy, context, exec.arguments.destination, { mutation: true });
      if (destination.stat) throw new Error('禁止覆盖现有目标。');
    }
    this.reserveDestructive(exec, context);
    const backupId = this.backup(source.target, context, exec.name);
    const sourceAgain = checkedPath(policy, context, exec.arguments.file_path, { mutation: true, fileRequired: true });
    if (sourceAgain.stat.ino !== source.stat.ino || sourceAgain.stat.size !== source.stat.size || sourceAgain.stat.mtimeMs !== source.stat.mtimeMs) {
      throw new Error('文件在备份时发生变化，停止操作。');
    }
    if (destination) {
      destination = checkedPath(policy, context, exec.arguments.destination, { mutation: true });
      if (destination.stat) throw new Error('目标在执行前已存在，停止操作。');
      // Exclusive creation avoids rename's overwrite semantics; source removal is one explicit regular file.
      fs.copyFileSync(source.target, destination.target, fs.constants.COPYFILE_EXCL);
      fs.unlinkSync(source.target);
      this.audit('move-one-file', exec, { file: source.target, destination: destination.target, backupId });
      return { status: 'moved', file: source.target, destination: destination.target, backupId };
    }
    const quarantine = path.join(this.directory, 'quarantine');
    fs.mkdirSync(quarantine, { recursive: true });
    const target = path.join(quarantine, `${backupId}-${path.basename(source.target)}`);
    // The project can be on another drive, so copy exclusively before unlinking this one file.
    fs.copyFileSync(source.target, target, fs.constants.COPYFILE_EXCL);
    fs.unlinkSync(source.target);
    this.audit('quarantine-one-file', exec, { file: source.target, quarantine: target, backupId });
    return { status: 'quarantined', file: source.target, quarantine: target, backupId };
  }
  status(exec) {
    const context = this.contextOf(exec);
    const policy = this.policy();
    return {
      active: true, version: '1.1.0', mode: 'strict', processId: process.pid,
      workspace: context?.root ?? null, sandbox: context?.mode ?? null,
      allowedWorkspaces: policy.allowedWorkspaces,
      arbitraryShellAndScripts: 'blocked', fullAccessEscalation: 'blocked', unknownTools: 'blocked',
      destructiveLimit: 'one single regular file per session; explicit approval required',
      backups: path.join(this.directory, 'backups'), quarantine: path.join(this.directory, 'quarantine'),
    };
  }
  list(exec) {
    const { policy, context } = this.requireAllowed(exec);
    const directory = checkedPath(policy, context, exec.arguments.path ?? '.', { directoryAllowed: true });
    if (!fs.statSync(directory.target).isDirectory()) throw new Error('请指定目录。');
    return { path: directory.target, entries: fs.readdirSync(directory.target, { withFileTypes: true }).slice(0, 500).map(entry => ({
      name: entry.name, type: entry.isSymbolicLink() ? 'link' : entry.isDirectory() ? 'directory' : 'file',
    })) };
  }
}
