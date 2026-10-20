# DSH Local Safety Guard

为 Windows 版 DeepSeek Harness 提供严格工具限制的**非官方本地插件**。通过 DSH 的插件接口和工具 Guard 生效，不修改 EXE、app.asar，不需要 DSH 源码版，不需要额外模型或 API Key。

当前兼容性声明仅覆盖已验证的 **DSH 0.2.1-rc.2 / Windows**。不能保证新版本接口不变。安装后必须验证实际加载和工具拒绝；插件装不上或工具不存在时，不要声称已受保护。

## 功能与使用代价

- `AGENTS.md` 提供文字规则；原生 `tools.guard()` 提供最终拒绝，执行前 Hook 提供提前反馈，执行层 Hook 复核并在编辑前备份。
- 工具默认拒绝。只保留 read/glob/grep/write/edit、少量会话工具及本插件的四个专用工具。
- 任意 Shell、Python/Node 脚本、构建、测试、安装依赖、Git 命令、PTC、后台任务、MCP、子代理、电脑操控和未知工具均被禁止。**正常项目的构建、测试和依赖安装也需要用户在 DSH 外手工运行。**
- 只允许用户安装时指定的工作区；禁止跨工作区、链接路径、硬链接修改、目录删除/迁移、通配符/数组路径、UNC/设备路径、备用数据流。
- 保护规则文件、控制目录与常见凭据路径。搜索目录本身被允许，不能将此功能宣称为完备的敏感信息防泄漏机制。
- 已有文件修改前备份原内容与校验信息；超过32MiB或备份失败时停止修改。禁止直接写空/写空白，以及标准替换操作把整个非空文件清空。
- `safety_remove_file`：批准后将一个普通文件移入隔离区；`safety_move_file`：批准后在当前工作区移动一个文件，不覆盖现有目标。
- 每个会话最多一次删除或移动，记录跨重启保留。它按工具调用检查，**不能自动识别一次合法单文件申请背后的“全部删除”意图**；第一次仍可进入审批。模型对软规则的遵守不能作为安全保证。
- 拒绝完整访问模式及工具提权参数；保持 DSH 自带沙箱。提供本地审计与手工单文件恢复。

## 新用户安装

1. 安装官方 Windows DSH，打开一次，完成初始配置，然后**完全退出，包括托盘进程**。无需源码版。
2. 从本仓库下载 ZIP 或使用 Git clone，把源码解压到一个稳定目录。源码目录、插件目录及 DSH 程序目录都不能被选作可写工作区。
3. 在源码目录打开 PowerShell，先查看计划。把示例中的路径替换成自己的实际路径：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-DSHGuard.ps1 -DshExe "D:\Tools\DSH\DeepSeek Harness.exe" -Workspace "D:\Projects\demo" -GuardDirectory "D:\Tools\DSH\DSH-Guard" -PlanOnly
```

确认路径无误后，去掉 `-PlanOnly` 安装：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-DSHGuard.ps1 -DshExe "D:\Tools\DSH\DeepSeek Harness.exe" -Workspace "D:\Projects\demo" -GuardDirectory "D:\Tools\DSH\DSH-Guard"
```

这里的 ExecutionPolicy Bypass 仅用于这一次 PowerShell 进程，不更改系统长期策略。脚本不终止进程、不删除文件、不修改 API Key、不自动启动 DSH；DSH 仍在运行时会拒绝安装。

`-GuardDirectory` 不填时默认 `%LOCALAPPDATA%\DSH-Guard`。`-DshHome` 默认 `%USERPROFILE%\.dsh`，`-Profile` 默认 `desktop`；使用自定义配置位置时需显式传入。从当前 PowerShell 直接调用脚本时，`-Workspace` 可接受数组。仅支持全新安装，不会覆盖已有防护目录或重复安装；更新策略及升级需人工核对。

安装脚本会：校验路径边界；备份非凭据配置；把插件代码复制到 GuardDirectory；生成本机 `policy.json` 和带绝对数据目录的 `cordis.patch.yml`；保留原内容追加全局及工作区 AGENTS.md；调用 DSH 随附 CLI 的 `plugin --profile desktop add file:<目录>`；检查插件登记及代码哈希。无需单独发布到 npm，插件本身没有第三方 npm 依赖；DSH 插件管理器仍可能访问它配置的软件源。

**不要直接在插件界面填写本仓库 URL 就认为安装完成。** 仓库只有模板，没有个人工作区 policy.json；请使用安装脚本生成本机配置。安装失败不会自动回滚，请保持 DSH 关闭，检查 `install-backup/` 中的原配置与规则文件清单，先解决错误再打开。

4. 正常启动官方 DSH（原桌面快捷方式即可），然后运行只读状态检查：

```powershell
powershell.exe -NoProfile -File .\Test-DSHGuard.ps1 -GuardDirectory "D:\Tools\DSH\DSH-Guard"
```

检查器会核对启用回执、官方宿主进程、插件登记和已安装文件哈希。安装成功不代表已经启用；软件关闭时不能确认运行中的防护。检查器通过后仍需做下面的实际工具测试。

5. 在指定工作区新建会话，发送：

```text
请验证安全防护，每项只调用一次，展示实际工具结果。
1. 调用 safety_status，展示 active、mode 和 allowedWorkspaces。
2. 尝试调用 pwsh，仅执行 Write-Output 'DSH_GUARD_TEST'。
3. 尝试调用 safety_remove_file，file_path 严格填写：
   __DSH_GUARD_TEST_NOT_CREATED__\*.tmp
不要创建这个目录或文件，不展开通配符。收到拒绝后不换工具、不运行脚本绕过。
如果没有实际发起调用，明确说明未实际测试。
```

预期：状态返回 active=true、mode=strict；后两项实际工具调用均返回带 `[DSH安全防护]` 的拒绝结果。只口头承诺不算验证。`records/audit.jsonl` 应出现对应的拒绝记录。测试文字提示会使用普通对话额度；插件拦截和本地检查本身不请求模型。

## 文件职责

| 文件 | 职责 |
|---|---|
| index.mjs | 注册原生 Guard、执行前/执行层 Hook，以及状态、列目录、单文件隔离、单文件移动工具 |
| policy.mjs | 工具白名单、工作区/路径/权限判断、清空文件防护 |
| engine.mjs | 编辑前备份、隔离、移动、每会话次数限制、审计 |
| restore.mjs | 用户在软件外运行的单文件恢复工具 |
| cordis.patch.yml | 插件、沙箱、权限预设模板；安装时生成本机数据目录 |
| AGENTS-safety.md | 追加到全局及工作区 AGENTS.md 的软规则 |
| policy.example.json | 工作区策略示例；实际 policy.json 在安装时生成 |
| Install-DSHGuard.ps1 / Test-DSHGuard.ps1 | 全新安装、只读检查加载状态 |
| test/ | 策略测试、隔离的安装脚本测试、可选的真实 DSH 运行时探针 |

## 备份、恢复与规则调整

运行数据保留在 GuardDirectory：`backups/` 包含内容 `.bin` 与路径/哈希 `.json`；`quarantine/` 包含从工作区移出的文件；`records/` 包含日志、启用回执、每会话次数记录；`install-backup/` 包含安装前非凭据配置及原规则。备份可能包含项目敏感内容，**不要提交到 GitHub**。插件目录位于程序目录中时，更新或卸载主程序前先另行备份整个防护目录。

安装 Node.js 24 或更新的兼容版本后，可在 DSH 外恢复单个文件：

```powershell
node "D:\Tools\DSH\DSH-Guard\restore.mjs" <backup-id>
```

目标已存在时会拒绝覆盖；核对后可加 `--overwrite`，工具先备份现有版本再恢复这一个文件。它不会自动删除隔离区或旧备份。

增加工作区：退出 DSH，手工编辑实际 GuardDirectory 下的 policy.json，将明确的项目目录加入 allowedWorkspaces，并给该工作区追加 AGENTS-safety.md 的规则块；重新打开并验证。不要放行盘符根目录、整个用户目录、程序目录或防护源码目录。

停止使用：退出 DSH 后，按其插件管理方式卸载或禁用 `dsh-local-safety-guard`；人工从全局和项目 AGENTS.md 中移除 BEGIN/END 标记间的本插件规则块，保留其他原规则。备份、隔离区及恢复资料可继续保留。本项目不提供批量清理/删除脚本。

## 安全边界

这是 DSH 工具管线内的执行策略，不是 Windows 内核级隔离。不能约束第三方插件自身直接运行的本机代码、其他应用或同账号外部进程；不要安装不可信插件。不能防止模型把允许编辑的代码改错，备份只是恢复手段；不是全盘备份或语义正确性保证。目录搜索及读权限不是完整的数据防泄漏机制。路径复核不保证抵御恶意同账号进程制造的精确竞态。

Guard 的“默认拒绝”以插件正常加载并挂接工具管线为前提。软件升级、插件被人为禁用或插件加载失败后不能继续假定有效；重新做状态与实际拦截测试。需要运行任意项目脚本并隔离重要主机文件时，使用专用低权限账号或不映射重要目录的虚拟机，并保留独立备份。

## 验证与分享

开发验证需要 Windows、Node.js 24+、Windows PowerShell 5.1+：

```powershell
node --test test/*.test.mjs
```

安装器测试在临时目录使用自己创建的假 DSH CLI，不改真实桌面配置；不代表所有新机器上的真实安装都已经验证。测试夹具保留，不递归清理目录。

真实工具运行时探针（不启动桌面会话，不请求模型）：

```powershell
$env:ELECTRON_RUN_AS_NODE = '1'
& "D:\Tools\DSH\DeepSeek Harness.exe" --expose-internals .\test\runtime-probe.mjs "D:\Tools\DSH"
# 完成后关闭这个测试终端，避免该进程环境变量影响之后正常启动桌面程序。
```

探针通过实际安装的 DSH 工具运行时验证：即使测试前置 Hook 强制 allow，最终 Guard 仍拒绝五种执行工具，且被拒绝的工具体未进入；它使用独立临时策略，不修改正式版配置。

可以把**本分享源码目录**上传 GitHub，或发布随附的干净 ZIP。不要上传自己实际安装的 GuardDirectory、整个 `.dsh` 或原开发调试目录。`.gitignore` 提供辅助排除，但 Git 跟踪过的文件仍需人工检查。无需把官方 DSH 二进制、提取的源码、API Key 或 Node.js 打包进仓库。仓库采用 MIT 许可证；这是社区插件，不代表 DeepSeek 官方安全承诺。
