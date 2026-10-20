import fs from 'node:fs';
import path from 'node:path';

export const PREFIX = '[DSH安全防护] ';
const MUTATIONS = new Set(['write', 'edit', 'safety_remove_file', 'safety_move_file']);
const READS = new Set(['read', 'glob', 'grep', 'safety_list_directory']);
const INTERNAL = new Set(['safety_status', 'todo_write', 'ask_user', 'ask_user_question', 'skill']);
const CONTROL_SEGMENTS = new Set(['.git', '.dsh', '.codex', '.agents', '.ssh', '.aws', '.local-safety-guard']);
const CONTROL_FILES = new Set(['agents.md', 'agents.local.md', 'claude.md', 'claude.local.md', 'cordis.patch.yml', 'cordis.yml']);

export function loadPolicy(filename) {
  const p = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (p.version !== 1 || !Array.isArray(p.allowedWorkspaces) || !p.allowedWorkspaces.length ||
      p.allowedWorkspaces.some(x => typeof x !== 'string' || !path.isAbsolute(x)) ||
      !Number.isSafeInteger(p.maxBackupBytes) || p.maxBackupBytes < 1 ||
      p.maxDestructivePerSession !== 1) {
    throw new Error('Invalid local policy; refusing tool execution.');
  }
  return p;
}

export function isInside(root, target) {
  const rel = path.relative(root, target);
  return rel === '' || (!path.isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${path.sep}`));
}

/** Reject junctions/symlinks on every existing component, including workspace ancestors. */
export function noLinks(target) {
  const absolute = path.resolve(target);
  const parts = [];
  let current = absolute;
  while (true) {
    parts.push(current);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  for (const item of parts.reverse()) {
    let stat;
    try { stat = fs.lstatSync(item); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    if (stat.isSymbolicLink()) throw new Error(`禁止经过符号链接/目录联接：${item}`);
  }
}

export function workspace(policy, context) {
  if (!context || typeof context.root !== 'string' || typeof context.cwd !== 'string') throw new Error('缺少会话工作区，拒绝执行。');
  const root = path.resolve(context.root);
  if (root === path.parse(root).root || !policy.allowedWorkspaces.some(p => path.resolve(p).toLowerCase() === root.toLowerCase())) {
    throw new Error('该工作区不在本机允许清单中，请由用户手动添加到 policy.json。');
  }
  noLinks(root);
  if (!fs.statSync(root).isDirectory()) throw new Error('工作区不存在。');
  if (!isInside(root, path.resolve(context.cwd))) throw new Error('当前目录已离开会话工作区。');
  noLinks(context.cwd);
  if (!fs.statSync(context.cwd).isDirectory()) throw new Error('当前工作目录不存在。');
  return root;
}

export function checkedPath(policy, context, value, { mutation = false, fileRequired = false, directoryAllowed = false } = {}) {
  const root = workspace(policy, context);
  if (typeof value !== 'string' || !value.trim() || /[\x00-\x1f*?\[\]]/.test(value) ||
      value !== value.trim() || /^[\\/]{2}/.test(value) || /[<>|]/.test(value)) {
    throw new Error('必须提供一个明确的普通本地路径；禁止数组、通配符、UNC和设备路径。');
  }
  const target = path.resolve(context.cwd, value);
  if (target.slice(path.parse(target).root.length).includes(':') ||
      (/\.\.(?:[\\/]|$)|[. ](?:[\\/]|$)/.test(value) && !(value === '.' && directoryAllowed && !mutation)) ||
      value.split(/[\\/]/).some(part => /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(part))) {
    throw new Error('禁止备用数据流、特殊设备名和不明确的 Windows 路径。');
  }
  if (!isInside(root, target)) throw new Error('路径超出当前工作区，禁止跨工作区操作。');
  const segments = path.relative(root, target).split(/[\\/]/).map(s => s.toLowerCase());
  const basename = path.basename(target).toLowerCase();
  if (segments.some(s => CONTROL_SEGMENTS.has(s)) || CONTROL_FILES.has(basename) ||
      basename === '.env' || basename.startsWith('.env.') && !basename.endsWith('.example') || basename === '.credentials.yaml') {
    throw new Error('规则、凭据和控制目录受到保护；请用户手动操作。');
  }
  noLinks(target);
  let stat;
  try { stat = fs.lstatSync(target); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (mutation && target === root) throw new Error('禁止修改工作区根目录本身。');
  if (stat && !stat.isFile() && !(directoryAllowed && !mutation && stat.isDirectory())) throw new Error('此操作仅支持一个普通文件，禁止目录操作。');
  if (fileRequired && !stat?.isFile()) throw new Error('目标必须是已存在的单个普通文件。');
  if (mutation && stat?.nlink > 1) throw new Error('禁止修改硬链接文件。');
  if (mutation && stat && stat.size > policy.maxBackupBytes) throw new Error('文件超过自动备份上限，请手动处理。');
  return { root, target, stat };
}

export function isMutation(name, args) {
  return MUTATIONS.has(name);
}

/** Default-deny tools, including shells, interpreters, PTC, jobs, MCP and self-modification. */
export function classify(policy, name, args, context) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return PREFIX + '工具参数必须是对象。';
  if (Object.hasOwn(args, 'sandbox_permissions') && args.sandbox_permissions !== 'use_default') return PREFIX + '禁止脱离沙箱或请求更高权限。';
  if (name === 'safety_status') return;
  if (!MUTATIONS.has(name) && !READS.has(name) && !INTERNAL.has(name)) {
    return PREFIX + `严格模式禁止工具 ${name}。禁止任意命令/脚本、批处理、终端输入、PTC、后台任务及未审查扩展；不要改用其他入口绕过。构建测试请由用户在软件外手动运行。`;
  }
  try {
    workspace(policy, context);
    if (!['workspace-write', 'read-only'].includes(context.mode)) throw new Error('请先将权限模式切回“工作区内修改”或“只读”；完整访问模式下拒绝工作。');
    const mutation = isMutation(name, args);
    if (mutation && context.mode === 'read-only') throw new Error('当前是只读模式，禁止文件修改。');
    if (name === 'safety_remove_file' || name === 'safety_move_file') {
      checkedPath(policy, context, args.file_path, { mutation: true, fileRequired: true });
      if (name === 'safety_move_file') {
        const destination = checkedPath(policy, context, args.destination, { mutation: true });
        if (destination.stat) throw new Error('移动目标已存在；禁止覆盖。');
        if (!fs.statSync(path.dirname(destination.target)).isDirectory()) throw new Error('目标父目录不存在。');
      }
    } else if (name === 'read' || name === 'write' || name === 'edit') {
      const file = checkedPath(policy, context, args.file_path, { mutation });
      if (name === 'write' && file.stat?.size > 0 && typeof args.content === 'string' && !args.content.trim()) throw new Error('禁止清空现有文件或用空白覆盖。');
      if (name === 'edit' && file.stat?.size > 0 && typeof args.old_string === 'string' && args.old_string && typeof args.new_string === 'string') {
        const original = fs.readFileSync(file.target, 'utf8');
        const updated = args.replace_all ? original.split(args.old_string).join(args.new_string) : original.replace(args.old_string, () => args.new_string);
        if (original.trim() && !updated.trim()) throw new Error('禁止通过替换操作清空整个文件。');
      }
    } else if (name === 'safety_list_directory' || name === 'glob' || name === 'grep') {
      checkedPath(policy, context, args.path ?? '.', { directoryAllowed: true });
    }
  } catch (error) { return PREFIX + error.message; }
}
