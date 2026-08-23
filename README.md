# Agent Skill Scanner

[![CI](https://github.com/liuhaolin07/agent-skill-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/liuhaolin07/agent-skill-scanner/actions/workflows/ci.yml)
[![CodeQL](https://github.com/liuhaolin07/agent-skill-scanner/actions/workflows/codeql.yml/badge.svg)](https://github.com/liuhaolin07/agent-skill-scanner/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

**在线演示**：[https://liuhaolin07.github.io/agent-skill-scanner/](https://liuhaolin07.github.io/agent-skill-scanner/)（GitHub Pages，无需本地环境）

本地运行需要 Node.js 20 或更新版本：

```bash
npm start
```

浏览器打开 `http://127.0.0.1:4173`。扫描完全在浏览器中完成；本地服务只提供静态页面，不接收或保存上传文件。

## 安装

```bash
npm install -g @ryukorin/agent-skill-scanner
```

安装后直接使用 `skill-scan` 命令（或 `npx @ryukorin/agent-skill-scanner <path>` 免安装使用）。

## 命令行使用

Node 引擎扫描单文件：

```bash
npm run scan -- ./SKILL.md
npm run scan -- ./my-skill --json
npm run scan -- ./my-skill --sarif          # SARIF 2.1.0（GitHub Code Scanning 兼容）
npm run scan -- ./my-skill --fail-on HIGH
npm run scan -- ./my-skill --disable-rule NETWORK_ACCESS,SUSPICIOUS_URL
```

Python 引擎（无需 Node，Hermes agent 调用）：

```bash
python src/scanner.py ./SKILL.md
python src/scanner.py ./my-skill --json
python src/scanner.py ./my-skill --disable-rule SECRET_BROAD_ENV
```

扫描整个目录并输出 JSON：

```bash
npm run scan -- ./my-skill --json
```

一次扫描多个目录或文件（可混用）：报告中的文件名相对所有输入的公共根目录，即使两个目录里都有 `SKILL.md` 也不会混淆：

```bash
npm run scan -- ./skill-a ./skill-b --json   # 报告中显示 skill-a/SKILL.md 与 skill-b/SKILL.md
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
npm test        # Node 引擎全套（17 单元 + 4 回归 + 4 CLI = 25 用例）
python test/test_scanner.py  # Python 引擎单元测试（17 用例，对齐 Node）
python test/test_corpus.py   # 回归基准（同一 corpus，Python 侧）
python test/test_cli.py      # CLI 级回归（多根路径命名、SARIF URI 等）
npm run test:all  # 双端全套（Node 25 用例 + Python 22 用例）
```

回归基准（`examples/corpus/`）锁定每个用例的预期规则命中，防止改规则时"修一个误报、引入两个漏报"。

## 2026-08 新增能力

- **多行拼接检测**：`curl ... |` + 下一行 `bash`、反斜杠续行、`&&` 结尾等跨行命令会被合并为逻辑行再匹配，绕过手段可检出
- **YAML frontmatter 结构感知**：`permissions:\n  - network: "*"` 这类多行 YAML 列表会折叠成 `父键: 值` 补扫，上下文敏感规则可命中
- **回归基准 corpus**：`examples/corpus/` 4 个 edge case（多行管道、frontmatter 通配、反引号 URL 表格、SSH+env），双引擎断言测试
- **SARIF 2.1.0 输出**：`--sarif`，可直接对接 GitHub Code Scanning
- **`--disable-rule`**：CLI 关闭指定规则（可重复、逗号分隔）
- **pre-commit 钩子**：`.pre-commit-config.yaml` 提交前扫暂存的技能文件 + 校验规则束同步

## 修改规则

规则在 `rules/scanner-rules.json`（单一规则源），每个规则含 `id` / `category` / `severity` / `title` / `why` / `remediation` / `case_insensitive` / `patterns`。

改完**必须**校验结构、重新生成浏览器端规则并跑双端测试：

```bash
npm run check:rules   # 校验规则文件结构（id 唯一、severity/category 合法、正则可编译；CI 也会跑）
npm run build:rules   # 从 JSON 重新生成 rules/rules.js（网页端用，勿手改）
npm run test:all      # 双端全套（Node 25 用例 + Python 22 用例）
```

编写新规则的完整规范见 [docs/rule-authoring.md](docs/rule-authoring.md)（含历次误报教训：URL 路径段不算 shell、markdown 表格竖线、业务字段不算权限等）。

Node/Python 引擎直接读 JSON；网页端（浏览器无文件系统）读 `rules/rules.js` 生成物，由 `scripts/sync-rules.mjs` 保证两者一致。

## 参与贡献

[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md)（漏洞报告走 GitHub Private Vulnerability Reporting）· [CHANGELOG.md](CHANGELOG.md) · [规则编写规范](docs/rule-authoring.md) · [规则 JSON Schema](rules/scanner-rules.schema.json)

## License

[MIT](LICENSE) © liuhaolin07

## 风险模型

每条规则只计一次分，保留至多三处证据，避免重复文本无限抬高分数。`CRITICAL` 规则会直接将总体等级提升为 `CRITICAL`；其他信号累加后分级。多文件扫描采用最高文件风险，并汇总全部发现。

这是启发式静态分析，不是完整沙箱。混淆代码、间接调用和运行时动态行为仍需要人工审计。

## 2026-08 修复记录（与 Hermes Python 版 scanner 交叉审计后）

- **`zx` 误报**：`zx\b` 匹配了 URL 路径段（如 `/zx/hd/sxjm/`），改为 `(?:^|[^/\w])zx\b`，仅识别真正的 zx shell 调用
- **`scope`/`permission` 误报**：`"scope": "all_units"` 这类业务数据字段被当成权限声明，规则改为要求值精确匹配（`*` / `all` / `any` / `0.0.0.0/0` 等完整词），`all_units` 不再误报
- 新增回归测试：反引号 URL 不误报 shell、紧凑 JSON `command` 键仍可检出（`test/scanner.test.js`，11 个用例全过）
- **整合为双引擎项目**：规则抽取到 `rules/scanner-rules.json`，新增 `src/scanner.py` Python 引擎与 `test/test_scanner.py`（11 用例），Node/Python 输出经 15 个数模技能目录验证逐字节等价
