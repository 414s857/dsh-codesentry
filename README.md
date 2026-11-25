<div align="center">

# dsh-codesentry

**让 AI 帮你把整个代码仓库审一遍。**

任务化的代码审计插件 · 跑在 [DeepSeek Harness](https://github.com/deepseek-ai) 里 · 大仓库自动分片 · 出可直接交付的审计报告

</div>

---

## 它是什么

给它一个代码目录和一组漏洞类型（或一份审计 Skill），它开一个独立的 AI 会话，把仓库按模块切片、逐片深读代码找漏洞，边跑边显示进度，最后沉淀成一份能直接交出去的审计报告。

不是"问 AI 有没有漏洞"的一问一答，而是一个**能干完整趟活得**的审计工作台。

## 为什么用它

| 痛点 | dsh-codesentry 的解法 |
|---|---|
| 大仓库一次读不完，模型只能抽样 → 覆盖率是个谜 | **自动分片**：按顶层模块切成多个切片，每片独立会话深读，各自维护"已读文件台账"，`已读 X / Y` 一目了然 |
| 审计跑长了触发上下文压缩，前面读过的调用链丢了 | 切片之间**互不共享上下文**，一片读再多也不挤占别的片预算 |
| 切片的边界会把 `controller → service → dao` 的污点流切断 | 全部切片完成后自动跑一次**跨切片汇聚**，专门核对被切断的污点流和共享安全边界 |
| 报告靠手写，格式乱、没法交付 | 一键导出 **Markdown / HTML / JSON / SARIF**，带报告编号、风险分布、漏洞详情、**PoC 请求包** |

## 核心能力

- **两种审计模式** — 按漏洞提示词（内置 14 类）审，或完全按一份 `SKILL.md` 审计 Skill 执行
- **大仓库分片** — 超过阈值的仓库自动切片并行审计 + 跨切片汇聚
- **实时进度** — 百分比 / 当前切片 / 工具调用数 / 已发现漏洞数 / 运行时长，全程可见
- **暂停继续** — 运行中可暂停，继续时复用同一会话从中断点接着审
- **漏洞管理** — 按任务 / 状态 / 严重级别筛选，详情含证据代码、PoC、修复建议
- **专业报告** — 4 种格式，深色封面 HTML 可直接交付或归档
- **Agent 原生** — 斜杠命令 `/audit` + `code_audit_*` 工具，可被任意会话驱动

## 快速开始

```bash
# 1. 安装（DSH 插件）
dsh plugin --profile web add github:414s857/dsh-codesentry

# 2. 重启客户端后，左侧导航出现「代码审计」入口
# 3. 新建任务 → 选代码目录 + 勾漏洞类型 → 运行
```

## 怎么用（三步）

1. **建任务** —— 填名称、选代码目录、勾要审的漏洞类型（或选一个审计 Skill）、选调度方式（手动 / 定时 / Cron / 固定间隔）
2. **跑起来** —— 点「运行」，看进度条和切片芯片推进；随时可暂停 / 继续
3. **看报告** —— 修完后点「报告」导出 Markdown / HTML / JSON / SARIF，或直接复制 PoC 去验证

## Agent 工具

`code_audit_*` 系列工具让 AI 会话自己建任务、跑审计、上报漏洞与进度、导出报告。

## 配置

在 profile 的 `cordis.patch.yml` 里覆盖（都有合理默认值）：

```yaml
- id: codesentry
  config:
    dataDir: !!js dshHomePath('storages', 'codesentry')
    maxConcurrentRuns: 2
    llmRetryDelayMinutes: 5
    llmRetryCount: 3
    defaultProvider: deepseek
    defaultModel: deepseek-chat
```

## 存储

```text
${DSH_HOME}/storages/codesentry/
├── codesentry.db              # SQLite：tasks / runs / findings / prompts / skills / settings
├── trajectories/<runId>.jsonl # 每次运行的完整运行日志（NDJSON）
└── reports/                   # 导出的报告归档
```

独立 SQLite 为唯一事实来源，WAL 模式，插件卸载自动关闭。
