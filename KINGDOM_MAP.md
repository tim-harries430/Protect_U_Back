# 🏰 PUB 王国地图 — 66 模块 / 9 层 + 检查顺序

> 配套:判罚条文见 [PUB_CODEX.md](PUB_CODEX.md)(法典)。
> 立法精神:**眼睛解码、野兽判决;墙 > 关 > 出口;只能加严不能松;拿不准 → fail-closed。**
> 每层就是一块 NT 式的"法规模组":分帮治理,但书同文(共享一份真相源)。

---

## 结构(9 层)

### 0. 城门(入口)
| 文件 | 职责 |
|---|---|
| `pretool_admission.py` | 7 行薄壳 → PreToolUse hook |
| `posttool_autopsy.py` | 7 行薄壳 → PostToolUse 尸检 |
| `protect_u_back.py` | 离线 audit CLI(agent-audit) |
| `protect_launcher.py` | 菜单(Doctor/Schema/Smoke/连接器/PUB-OS prison) |
| `pub_agent_launcher.py` | `cc --cage` 一条命令(connect+gate+verify+caged launch) |
| `demo_60s.py` | 60 秒演示 |

### 1. 眼睛(解码/归一 — eyes decode)
`adapter_wall.py`(ActionEnvelope:万 agent 归一的形状)· `claude_code_hooks.py`(**2369 行,cc 活体流水线的心脏**)· `codex_bash_guard.py`(Codex shell 效应推断)· `harness_adapter.py` · `decoder_grounding.py`(解码 vs 判决的接缝)

### 2. 接驳(各 agent 连接器 + runtime guard)
`claude_code_connector` · `codex_connector` · `kimi_connector`+`kimi_runtime_guard` · `openclaw_connector`+`openclaw_runtime_guard` · `openharness_connector`+`harness_runtime_guard` · `codex_gate_proof`(证明 Codex 每次 shell 都过了闸)

### 3. 关(判官 — reference monitor 核心)
| 文件 | 职责 |
|---|---|
| `ot_gate.py` | **宪法**:intent/boundary/evidence 三判官 + scoped-delete |
| `capability_wall.py` | actor 能力清单(side-effect/target/skill 契约) |
| `parallel_audit.py` | **双court**:decode_court + ot_court,取强不取弱 |
| `opaque_executor.py` | 可判定地认"不透明执行" |
| `temporal_continuity.py` | **第四判官**:序列漂移(只升不降) |
| `scene_continuity.py` | 环境判官:pub 模块带外篡改(只升不降) |
| `scene_seed.py` / `scene_replay_guard.py` | 现场捕获 / 重放守卫 |
| `protect_scan.py` | egress/secret/个人面防护(1499 行) |
| `audit_layer.py` | 每分支一杀冷却 |
| `task_guard.py` | 累杀 → 任务终止 |
| `registry_admission.py` | 入口 admission(身份+信封结构) |
| `baseline_guards.py` | 无闸基线 = 对照组 |

### 4. 透视(X-ray — 看文件转换的物理事实)
`transition_xray.py`(**2163 行**:magic-number 拆压缩包、ADS、COMMAND_SURFACE+DECODE_REVIEW)· `xray_review`(伪装轴)· `xray_transport`(进/出帧封印=omega 见证)· `xray_field` · `xray_prison`(禁权边界)

### 5. 访问物理(P = A + S − T)
`access_equation`(1202)· `access_field` · `access_process_equation` · `access_sampler`(fs 元数据采样;nlink 目录豁免在此)· `access_time_grid`(时栅漂移)· `probe_authority_surface`(PROBE_MINT)· `agent_control_surface`(.claude/.codex 面)

### 6. 史官(身份 + 记忆 + 尸检)
`phi_registry`(actor 身份)· `event_ledger`(账本,累杀触发 bugcheck)· `autopsy_report`(**尸检**,927 行)· `benchmark_runner`(PhiBenchmarkRunner)· `redteam_intake`(红队 case 摄入)

### 7. 墙底座(PUB-OS 监狱/笼子 — OS 级容器)
| 文件 | 职责 |
|---|---|
| `pub_os_core` | 白房子:只判,从不执行 |
| `pub_os_broker` | 窗口:零权限中转 |
| `pub_os_box` | 牢房:单出口 |
| `pub_os_warden` | 手:只执行不判 |
| `pub_os_cage` | **bwrap 笼子**(全环境推导、userns 实测、npm 收窄) |
| `pub_os_cc_sandbox` | 借 Claude Code 自带沙箱(Seatbelt/bwrap via settings.json) |
| `pub_os_runner` / `pub_run` | 组装监狱、起 agent |
| `pub_os_ledger` | 笼外见证(witness 不与囚共室) |
| `pub_os_visibility` / `pub_os_profiles` | KingdomSession/sensors / 受监管态机 |
| `pub_os_authorization` / `pub_os_touch_pipeline` | 能力租约 / touch 流水线 |

### 8. 通道 + 公共(接缝)
`llm_channel.py`(**1794 行**:pass-road / `safe_git_write` — TIER 2a;曾外包的"通道")· `safe_path`(`safe_resolve`)· `pub_daily_workflow_probe`

---

## 检查顺序(cc 活体路径 · `run_pretool_admission`)

```
PreToolUse
  │
① 城门:pretool_admission → run_pretool_admission
② 眼睛:action_from_claude_event → ActionEnvelope → CommandProposal
        open_xray_transport(封进场帧)
        │
③ 空间闸 _audit_action = parallel_audit 双court(取强):
     ├ decode_court: transition_xray(COMMAND_SURFACE→opaque_executor / DECODE_REVIEW→xray_review)
     └ ot_court:     ot_gate(intent/boundary/evidence)+ capability_wall + grounding/access
     ├ 放行修正:llm_channel pass-road(仅 OPAQUE-only 放 git)、ot_gate scoped-delete
④ 工具识别:未知工具 → UNKNOWN_CAPABILITY(hold)
        │
⑤ 第四判官:_run_temporal(序列漂移)——— 只升不降(tighten-only)
⑥ 环境判官:_run_scene(pub 模块带外篡改)——— 只升不降
⑦ 笼外见证:PUB-OS ledger witness 丢失 → hold
        │
⑧ 放行后:_record_allowed_scoped_delete(首次留痕)
          _journal_reversible_targets(回填 pre-image;抓不到 → HOLD)
        │
⑨ 出口:allow(None)/ hold / deny → permissionDecision
─────────────────────────────────────────────
PostToolUse:posttool_autopsy → 出场帧封印 + 尸检
```

---

## 两条路、两种关法(NT 双子系统类比)

- **活体闸**(上面流水线):hook 在 agent **进程外**判,`native allow 越不过`。给 claude(进程内 fs)用——`pub_os_cage` 整进程笼子兜底。
- **broker 监狱**(`pub_run`:box → broker → `pub_os_core` 判 → warden 执行):agent 每个 op 走单出口 socket 中转。给走 shell/broker 的 agent 用。

---

_王国一句话纲领:**眼睛解码、野兽判决、双court 取强、第四/环境判官只能加严、墙底座 fail-closed 兜底。墙(L7 容器)> 关(L3 判官)> 出口(L8 通道)。**_
