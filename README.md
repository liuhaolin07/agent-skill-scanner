# Agent Skill Scanner

一个零第三方依赖的静态安全扫描器，用于在安装前检查 `SKILL.md`、`skill.json`、MCP manifest 及相关 Markdown / JSON / YAML 文件。

**双引擎 + 单一规则源**：Node 引擎（`src/scanner.js`，人审/CI/Web UI）与 Python 引擎（`src/scanner.py`，agent 零依赖调用）共享 `rules/scanner-rules.json`，规则只维护一份，两端输出完全一致（已验证 15 个技能目录 JSON 结构逐字节等价）。

它检测六类信号：

- `.env`、SSH Key 和全量环境变量读取
- 外部网络访问与通配域名
- Shell / 子进程执行
- 持久 Memory 修改
- 管理员权限、全盘访问等过大权限
- 可疑 URL、下载命令与远程内容管道执行

输出统一风险等级：`LOW / MEDIUM / HIGH / CRITICAL`，0-100 评分，每条命中附原因（why）和修复建议（remediation），evidence 中的密钥自动脱敏。

## 网页使用

需要 Node.js 20 或更新版本：

```bash
npm start
```

浏览器打开 `http://127.0.0.1:4173`。扫描完全在浏览器中完成；本地服务只提供静态页面，不接收或保存上传文件。

## 命令行使用

Node 引擎扫描单文件：

```bash
npm run scan -- ./SKILL.md
```

Python 引擎（无需 Node，Hermes agent 调用）：

```bash
python src/scanner.py ./SKILL.md
python src/scanner.py ./my-skill --json
python src/scanner.py ./my-skill --min-risk HIGH
```

扫描整个目录并输出 JSON：

```bash
npm run scan -- ./my-skill --json
```

命令行退出码可直接用于 CI：

| 退出码 | 风险等级 |
| --- | --- |
| `0` | LOW |
| `1` | MEDIUM |
| `2` | HIGH |
| `3` | CRITICAL |
| `64` | 输入或运行错误 |

## 测试

```bash
npm test        # Node 引擎（11 用例）
npm run test:py # Python 引擎（11 用例，对齐 Node）
npm run test:all  # 双端一起跑
```

## 修改规则

规则在 `rules/scanner-rules.json`（单一规则源），每个规则含 `id` / `category` / `severity` / `title` / `why` / `remediation` / `case_insensitive` / `patterns`。

改完**必须**重新生成浏览器端规则并跑双端测试：

```bash
npm run build:rules   # 从 JSON 重新生成 rules/rules.js（网页端用，勿手改）
npm run test:all      # Node 11 用例 + Python 11 用例
```

Node/Python 引擎直接读 JSON；网页端（浏览器无文件系统）读 `rules/rules.js` 生成物，由 `scripts/sync-rules.mjs` 保证两者一致。

## 风险模型

每条规则只计一次分，保留至多三处证据，避免重复文本无限抬高分数。`CRITICAL` 规则会直接将总体等级提升为 `CRITICAL`；其他信号累加后分级。多文件扫描采用最高文件风险，并汇总全部发现。

这是启发式静态分析，不是完整沙箱。混淆代码、间接调用和运行时动态行为仍需要人工审计。

## 2026-08 修复记录（与 Hermes Python 版 scanner 交叉审计后）

- **`zx` 误报**：`zx\b` 匹配了 URL 路径段（如 `/zx/hd/sxjm/`），改为 `(?:^|[^/\w])zx\b`，仅识别真正的 zx shell 调用
- **`scope`/`permission` 误报**：`"scope": "all_units"` 这类业务数据字段被当成权限声明，规则改为要求值精确匹配（`*` / `all` / `any` / `0.0.0.0/0` 等完整词），`all_units` 不再误报
- 新增回归测试：反引号 URL 不误报 shell、紧凑 JSON `command` 键仍可检出（`test/scanner.test.js`，11 个用例全过）
- **整合为双引擎项目**：规则抽取到 `rules/scanner-rules.json`，新增 `src/scanner.py` Python 引擎与 `test/test_scanner.py`（11 用例），Node/Python 输出经 15 个数模技能目录验证逐字节等价
