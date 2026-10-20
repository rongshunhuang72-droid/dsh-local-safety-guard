import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SafetyEngine } from './engine.mjs';

export const name = 'dsh-local-safety-guard';
export const inject = ['tools', 'workingDirectory', 'sandboxPolicy'];

export function apply(ctx, config = {}) {
  const directory = config.dataDirectory ?? path.dirname(fileURLToPath(import.meta.url));
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) throw new Error('Safety data directory must be absolute.');
  const contextOf = exec => {
    if (!exec.agent?.session) return undefined;
    const session = exec.agent.session;
    return {
      root: session.header.cwd,
      cwd: ctx.workingDirectory.get(session),
      mode: ctx.sandboxPolicy.resolve({ session }).mode,
      sessionId: session.id,
    };
  };
  const engine = new SafetyEngine(directory, contextOf);
  // Register the default-deny policy globally, including delegated tool calls.
  ctx.tools.guard(exec => {
    const reason = engine.check(exec);
    if (reason) engine.audit('denied-final-guard', exec, { reason });
    return reason;
  });
  ctx.on('tools/pre-execute', async (exec, next) => {
    const reason = engine.check(exec);
    if (reason) {
      engine.audit('denied', exec, { reason });
      return { kind: 'deny', reason };
    }
    const decision = await next();
    if (decision.kind === 'allow' && ['safety_remove_file', 'safety_move_file'].includes(exec.name)) {
      return { kind: 'ask', reason: `单文件操作确认：${JSON.stringify(exec.arguments)}。删除会进入隔离区；每个会话最多一次删除或移动。` };
    }
    return decision;
  });
  ctx.on('tools/execute', async (exec, next) => {
    engine.beforeDispatch(exec);
    return next();
  });
  const properties = p => ({ type: 'object', properties: p, additionalProperties: false });
  const string = description => ({ type: 'string', description });
  const register = (toolName, description, parameters, execute) => ctx.tools.register({
    name: toolName, description, parameters,
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    },
    execute: (_args, exec) => execute(exec),
  });
  register('safety_status', '读取本机安全防护状态；不执行命令，不调用模型。', properties({}), exec => engine.status(exec));
  register('safety_list_directory', '只读列出当前工作区内的一个目录。任意Shell已禁用，请使用此工具。', properties({ path: string('目录路径，默认当前目录') }), exec => engine.list(exec));
  register('safety_remove_file', '经用户确认后将一个明确的普通文件移入隔离区，可恢复；禁止目录、通配符、链接、跨工作区。每个会话最多一次删除或移动，不得拆分批量操作。', { ...properties({ file_path: string('单个明确文件路径') }), required: ['file_path'] }, exec => engine.mutateFile(exec));
  register('safety_move_file', '经用户确认移动工作区内的一个明确普通文件，禁止目录/批量/覆盖/跨工作区。每个会话最多一次删除或移动。', { ...properties({ file_path: string('单个源文件'), destination: string('单个目标文件路径，不能已存在') }), required: ['file_path', 'destination'] }, exec => engine.mutateFile(exec));
  fs.mkdirSync(path.join(directory, 'records'), { recursive: true });
  const receipt = path.join(directory, 'records', 'active.json');
  fs.writeFileSync(receipt, JSON.stringify({ active: true, version: '1.1.0', processId: process.pid, startedAt: new Date().toISOString() }, null, 2) + '\n');
  ctx.effect(() => () => fs.writeFileSync(receipt, JSON.stringify({ active: false, processId: process.pid, stoppedAt: new Date().toISOString() }) + '\n'));
  ctx.logger?.info?.('DSH 本地安全防护已启用：严格工具白名单、工作区边界、编辑备份、单文件隔离/移动。');
}
