"""Create D3 delivery records from actual saved experiments and logs."""
from pathlib import Path
import datetime,hashlib,json,re,subprocess,sys
R=Path(__file__).resolve().parents[2]; H=R/'research/data_sensitive'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(name,text):(H/name).write_text(text.strip()+'\n',encoding='utf8')
def dump(name,obj):write(name,json.dumps(obj,ensure_ascii=False,indent=2))
scan=json.loads((H/'D3_REAL_SCAN.json').read_text())
manifest=json.loads((H/'D3_SOURCE_MANIFEST.json').read_text())
freeze=json.loads((H/'D3_FREEZE.json').read_text())
for p,digest in freeze['file_sha256'].items():assert sha(R/p)==digest,'Frozen artifact changed: '+p
full=(R/'outputs/logs/d3-full-tests.log').read_text(); assert 'OK (skipped=11)' in full and 'Ran 537 tests' in full
targeted=(R/'outputs/logs/d3-design-tests.log').read_text();assert 'Ran 25 tests' in targeted and '\nOK\n' in targeted
assert subprocess.run([sys.executable,'-m','compileall','-q','src/ohscanner/detectors/data','tests/detectors/data','research/data_sensitive'],cwd=R).returncode==0
assert subprocess.run(['git','diff','--check'],cwd=R).returncode==0
pre='d33177135ec6c6aaf4a4c42de1f6878652b330e3';post='63efce3ff7f2708527eb29216decaf5fe2dc33d0'
tcp='core/transmission/trans_channel/tcp_direct/src/trans_tcp_direct_message.c'
rawroot=Path('/mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/d3-source-cache')
controls=[]
def control(id,commit,path,needle,label,assessment):
    row=next(x for x in manifest['files'] if x['commit']==commit and x['file']==path)
    raw=rawroot/commit/path;assert sha(raw)==row['sha256']
    lines=[i for i,line in enumerate(raw.read_text().splitlines(),1) if needle in line];assert lines
    controls.append(dict(id=id,commit=commit,file=path,blob=row['blob'],source_sha256=row['sha256'],lines=lines,anchor=needle,classification=label,actual_assessment=assessment))
control('real-public-constant',pre,tcp,'srv process recv data: decrypt message err.','nonmaterial_log_control','Private target probe traversed it; no material operand candidate at these lines. Public Runner withholds target parse-partial file.')
control('real-status',pre,tcp,'srv process message fail.[%d]','status_log_control','Private probe traversed status ret log; not treated as secret material. Not a product-safety label.')
control('real-anonymized', '05ca843ed7f6968686a47283916b7553f12932ed','core/discovery/coap/common/src/disc_coap_parser.c','AnonymizeWrapper(anonymizedStr)','protected_output_shape_unknown','Source inspection confirms explicit anonymization call, but this version/DISC API has no accepted source model; detector safety assessment unexecuted/unknown.')
control('real-log-implementation',pre,'core/common/log/softbus_log.c','void SoftBusLog(','unrelated_to_target_source','Public Runner scheduled this AST-complete file as partial; no target source and no candidate. This is API definition, not an independent same-name impostor function.')
controls.append(dict(id='real-parse-blocked',file='core/authentication/src/auth_session_key.c',commit='0e0c18c4a10b8fe2410d2097c38fd9f7a6ab8132',classification='unknown_parse_partial',actual_assessment='Actual public not_analyzed; macro missing-semicolon regions and function overlaps saved in D3_REAL_SCAN.json.'))
dump('D3_REAL_CONTROLS.json',{'controls':controls,'real_same_name_impostor_control':'not acquired; covered by synthetic design control only','independent_truth':False,'not_all_categories_formally_analyzed':True})
logs={p.name:sha(p) for p in (R/'outputs/logs').glob('d3-*.log')}
validation={'date':'2026-10-17','implementation_and_tests_head':freeze['development_head'],'frozen_at':freeze['frozen_at'],
 'full_suite':{'cases':537,'passed':526,'skipped':11,'failed':0,'errors':0},'d_targeted_methods':25,
 'existing_design_controls':71,'d3_design_controls':24,'total_design_controls':95,'existing_control_hashes_unchanged':True,
 'compileall':'passed','git_diff_check':'passed','logs_sha256':logs,
 'skip_reasons':[x for x in full.splitlines() if ' ... skipped ' in x],
 'runs':[{k:run[k] for k in ('name','commit','tree','snapshot_sha256','public_candidate_count','public_coverage','private_candidate_count','public_repeat_equal','private_repeat_equal','public_report_hashes')} for run in scan['runs']],
 'holdout_collection_files':3,'independent_holdout_evaluation_executed':False,'runtime_poc_executed':False,'validated_vulnerability':0,
 'historical_hardening_pairs_reviewed':2,'qualified_conditional_research_pairs':1,
 'source_manifest_sha256':sha(H/'D3_SOURCE_MANIFEST.json'),'real_scan_sha256':sha(H/'D3_REAL_SCAN.json'),
 'freeze_sha256':sha(H/'D3_FREEZE.json'),'holdout_collection_sha256':sha(H/'D3_HOLDOUT_COLLECTION.json'),
 'environment':{'python':sys.version,'platform':subprocess.check_output(['uname','-a'],text=True).strip()},
 'commands':['python -m unittest tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_d2_semantics tests.detectors.data.test_d3_historical -v','TMPDIR="$PWD/.tmp" python -m unittest discover -s tests -v','python -m research.data_sensitive.d3_experiment --history-repo <d3-upstream.git> --baseline-repo <dsoftbus-replay.git> --output-dir outputs/reports/d-sensitive/d3/real','python -m compileall -q src/ohscanner/detectors/data tests/detectors/data research/data_sensitive','git diff --check']}
dump('D3_VALIDATION.json',validation)
write('D3_IMPLEMENTATION.md','''# D3 实现与不支持范围

默认检测器/模型继续为 0.2.0 / 0.1.0；独立 HistoricalSensitiveExposureDetector 为 0.3.0，历史模型 0.2.0-historical.1。显式 historical_model(full_commit) 选择两个受审提交，其他提交拒绝；不注册 Catalog。

历史 profile 固定每端 10 个文件的 commit/tree/blob/SHA 与原始定义行号。执行前检查 ScanContext 中全部依赖文件的字节 SHA，缺失或不匹配即 blocked。公共 Git 加载器负责固定 Git 对象身份，直接研究探针则由实验脚本先核对同一清单。

新增 HistoricalLocalFlow 在原局部引擎之上，只支持一个已核验的一跳摘要：唯一、无直接语法错误的 DecryptMessage 第 2 个参数指向 MsgCryptInfo.out。依据是同版本函数把 outbuf.buf 指向该字段，调用 AuthDecrypt 并在成功后返回；不是自动构建调用图。

先观察 SoftBusCalloc 分配、局部非空检查，再在 DecryptMessage 与 SOFTBUS_OK 比较的成功边上引入条件材料流。失败边不引入材料，未检查状态、未确认分配、复杂别名或缺少摘要时不给这条来源。分支合并时分配/非空属于 must 信息，不能把某一分支成立当作所有分支成立。直接成员覆盖清除材料；内层同名声明与成员状态离开作用域后恢复。

旧 SoftBusLog 的格式下标是 2（从 0 开始），普通 %s 先经 secure-C 格式化，再被适配器以 public HiLog / printf 输出。它与默认 HiLog 的私有格式不同。未经核验的 %{public/private} 旧接口格式不套用隐私模型；历史模式下复制/格式化输出状态尚未建模，保留缺口而不无条件认定写成功。

默认引擎只新增 make_flow 扩展点及可选格式默认隐私参数；原模型语义、旧 71 控制不变。历史流限制在受审目标文件和 ProcessReceivedData。输出仍为 syntax 候选，附历史模型、请求内容、日志适配器和运行可见性义务，不记录秘密原值。

限制：may-flow 不证明请求种类、路径可行性、字符终止/日志长度成功、未知调用副作用、别名生命周期或编译器符号身份。所有依赖校验也不等于构建系统实际选择了这些实现。普通 Runner 仍拒绝目标 partial 文件；独立探针只作研究，不覆写覆盖等级。

代码/模型/测试按三次独立提交组织，实际哈希见 D3_FREEZE.json。24 个新增设计控制验证成功/失败、初始化、遮蔽、格式及版本边界；它们不是 holdout。''')
write('D3_MODEL_EVIDENCE.md','''# D3 历史 Source / Sink 原始依据

模型文件：src/ohscanner/detectors/data/historical_profiles.json；每端 10 个 required_files、完整版本与 evidence 行号/哈希均在其中。原默认 models.py 保持原字节。

仓库 openharmony/communication_dsoftbus；修改前 d33177135ec6c6aaf4a4c42de1f6878652b330e3，修改后 63efce3ff7f2708527eb29216decaf5fe2dc33d0。Git 原始提交确认父子关系，文件 blob SHA-1 和 SHA-256 均核验；完整清单 D3_SOURCE_MANIFEST.json。来源为官方组织 GitHub 镜像，GitCode 具体 API 请求返回 404，跨镜像身份尚未核验。

## Source 依据

softbus_message_open_channel.c 的 PackRequest 将 appInfo->sessionKey 经 SoftBusBase64Encode 编码，加入 SESSION_KEY JSON 字段；同文件 UnpackRequest 取出此字段并 Base64Decode 回会话密钥。协议头将 SESSION_KEY 定义为相应 JSON 字段名；AppInfo 声明与传递 ChannelInfo.sessionKey 的代码提供用途上下文。因此来源不是基于 key 字符串命名猜测，而是明确的编码、构造、反向解码与会话密钥使用关系。

目标 trans_tcp_direct_message.c 的 DecryptMessage 在修改前 377–395 行，将输出缓冲区绑定 cryptInfo->out（387 行），调用 AuthDecrypt，失败时返回错误，成功更新 outLen。ProcessReceivedData 先分配 out，检查非空，649 行检查 DecryptMessage 状态，解析 JSON；671 行将整个 out 当字符串打印。源位置为成功边 649 行，不是说该行生成了密钥。

必须保留条件：只有携带 PackRequest 会话密钥的请求数据才满足材料前提；reply/error 或其他 JSON 不一定携带秘密。该模型识别可能的密钥承载路径，不保证每次到达日志的数据都有密钥，也未自动追完整网络调用链。

## Sink 依据

core/common/include/softbus_log.h 声明参数 module、level、fmt、...；core/common/log/softbus_log.c 的 SoftBusLog 读取配置阈值，vsprintf_s 到 256 字节缓冲区，再调用 SoftBusOutPrint。adapter/common/log/softbus_adapter_log.c 对 ERROR 分支使用 %{public}s，SOFTBUS_PRINTF 分支用 printf。故这个版本普通 %s 不是默认 HiLog 私有槽位；格式位置为 2。

feature_config 默认 ADAPTER_LOG_LEVEL 为 0，只能作为该源码默认配置依据，不能证明量产运行配置。实际构建选择、阈值、模块/等级合法、格式化是否成功、长度上限、读取者权限仍待核验。过长日志可能格式化失败，不应假设任何长度材料都会输出。

## 审核状态与传播预算

模型是 research_source_reviewed，待队长验收；只绑定上述两个版本，语义相同，修复端不因没有日志而改变 Source 条件。最多一跳明确摘要，支持简单成员、指针别名赋值与局部成功分支，不支持泛化解密器、任意跨文件调用、复杂指针或未知构建变体。依赖缺失不加载模型，未知字段不因命名升级为秘密。''')
write('D3_HISTORICAL_CASES.md','''# D3 两组真实历史改动核验

## 服务发现：排除为本轮有效正例

05ca843ed7f6968686a47283916b7553f12932ed → 273637945ecb7b53d5d9af3bfd4e48a40bb88252 确实删除 DISC_LOGI 的 registerCapaData public 输出。但同版本 disc_coap_capability.c 中 DiscCoapAssembleCapData 忽略输入并返回 SOFTBUS_FUNC_NOT_SUPPORT；调用方对此释放缓冲区并返回，不会继续到该日志。

因此当前开源实现不能证明该日志路径可达，更不能证明其包含秘密。其他供应商扩展可能不同，但没有源码证据，保持 unknown。已核验 DISC_LOGI 宏转发与匿名化日志上下文，不据标题“sensitive”给漏洞标签。不为此建立敏感 Source 正例模型。

## TCP：选为条件研究候选 / 日志删除回归对

d33177135ec6c6aaf4a4c42de1f6878652b330e3 → 63efce3ff7f2708527eb29216decaf5fe2dc33d0。

真实源码存在 PackRequest 会话密钥编码入 JSON、解密输出、旧 SoftBusLog 公开适配的上下文。修改前独立探针在 ProcessReceivedData:671 输出 1 条候选；修改后该语句被删除，候选为 0。同规则语义、同 10 个路径范围，两端分别绑定正确文件哈希。

目标文件在两端均有 LIST_FOR_EACH_ENTRY 类宏导致的缺分号解析区域（修改前 78、136、601 行）；目标函数与 DecryptMessage 均无直接错误重叠。公共 Runner 整文件不准入，因此两端公共候选都是 0。不能把公共零候选差异宣传成平台已经检出/修复真实漏洞。

这个案例提供材料与公开日志代码依据，但请求内容、格式化长度成功、构建开关、真实入口与非授权读取者未闭环，仍是条件 candidate。没有 CVE、确认漏洞或产品受影响版本结论。没有修改原上游源码，没有给真实源码插入日志或移除守卫以制造正例。''')
table='\n'.join('| '+r['name']+' | '+str(r['public_candidate_count'])+' | '+str(r['private_candidate_count'])+' | '+str(r['public_coverage'])+' |' for r in scan['runs'])
write('D3_REAL_SCAN.md','''# D3 真实 Git 源码实验

本轮实际执行，不引用 D2 数字代替。实现/测试 HEAD 与文件冻结 SHA 见 D3_FREEZE.json，完整运行输入、tree/blob/source/snapshot、解析器环境、逐函数错误/Source/Sink/限制与输出哈希见 D3_REAL_SCAN.json。每种输入公共扫描和独立探针均重复两次，候选及覆盖一致；含耗时的报告不要求字节一致。

| 实验 | 公共候选 | 私有研究候选 | 公共覆盖 |
| --- | ---: | ---: | --- |
'''+table+'''

原九文件基线在开发开始和最终代码上实际重放，保持 0/3/6/0、候选 0。历史每端 10 文件，范围可比。修改前研究候选路径为成功解密输出 crypInfo.out（649 行）→ 受审一跳输出摘要 → 671 行 SoftBusLog 字符串参数；修改后输出语句删除。正式 Runner 并未产生这条真实候选，独立探针也未接入 Catalog。

## 实验 4：真实控制与缺口

D3_REAL_CONTROLS.json 固定原文件位置：目标函数的公开常量日志、ret 状态日志在研究遍历中不形成材料告警；日志实现文件被公共 Runner 分析为 partial 且无该来源。另一版本的显式 AnonymizeWrapper 输出仅确认保护形状，该版本无受审来源模型，安全检测结论仍 unknown。原九文件 auth_session_key.c 的宏解析失败如实记 not_analyzed。

同名无关普通函数、private 输出、未检查状态等有新增合成控制，但未收集到独立真实“同名冒充接口”对照。不得把合成 24 控制包装成全部真实五类实验完成；保护形状也不等于已验证匿名化效果。

## 执行方法

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m research.data_sensitive.d3_experiment \\
  --history-repo /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/d3-upstream.git \\
  --baseline-repo /mnt/c/Users/86150/Documents/Codex/2026-10-08/w/outputs/dsoftbus-replay.git \\
  --output-dir outputs/reports/d-sensitive/d3/real
```

源码 Git 对象应显式事先获取；扫描加载器禁止隐式 fetch，不运行上游源码。历史获取使用官方 GitHub 镜像的精确提交，30 个依赖文件字节已验证。原始第三方文件、对象库及大日志留在本机，不推入项目。

## 四类计数

真实代码研究候选：修改前 1、修改后 0；真实公共 Runner 候选：均 0。合成开发控制：旧 71＋新 24，不是漏洞数。历史日志删除线索：核验 2 组，1 组作为条件研究对，1 组因开源 stub 路径不成立排除。已确认漏洞：0。''')
write('D3_LIMITATIONS.md','''# D3 剩余限制与诚实停止边界

1. 目标 partial 文件未获公共准入；原九文件和两端十文件均没有 complete。私有探针不改变 file_outcomes，不绕过 Runner 发布生产结果。局部函数无错误重叠不等于宏/类型/构建语义正确。
2. Source 代表可能包含会话密钥的解密请求 JSON；回复/错误内容、实际运行入口、调用路径和请求种类仍未知。源码机制不是每次输出都含秘密的证明。
3. 日志实现有 public 依据，但生产构建选择、阈值、256 字节格式化是否成功、日志权限及非授权读者没有动态证据。没有执行 PoC，也没有批准新的 Harness。
4. 一跳摘要仅限固定函数，复制/格式化输出的历史成功状态未实现；间接调用、复杂别名、循环、初始化精确证明、后续未知副作用和生命周期不完整。
5. 实验 4 的真实保护日志仍是模型未覆盖，真实同名无关函数样本缺失；相应合成控制不冒充真实评估。
6. 已冻结并收集 3 个另一组件源码供盲审，未取得独立真值、未执行独立 holdout；无 Precision/Recall。
7. GitCode 具体 API 404，使用明确标识的官方 GitHub 镜像；未完成双镜像身份验证。模型尚待负责人接受，未注册 Catalog/UI。

本轮停止在任务书允许的“有证据的实际结果＋公共接口阻塞 RFC＋缺口”边界。下一轮由负责人决定局部准入与真实读取权限证据，不能将这些未完成事项标成安全或漏洞确认。''')
write('D3_interface_requirements_zh.md','''# 队友 D：D3 接口需求（独立文档）

## 已有实证阻塞

TCP 修改前的 ProcessReceivedData:628–679 与 DecryptMessage:377–395 无直接解析错误重叠，但同文件 78、136、601 行的宏解析缺分号使公共 Runner 拒绝整文件。独立探针可产生 1 条条件候选，公共结果为 0；不能由 D 自行改 Runner 准入。

## P0：请求负责人决定的最小接口

| 事实/策略 | 请求内容 | 验收标准 |
| --- | --- | --- |
| 固定来源事实 | repository/commit/tree/blob/file SHA、parser/profile/producer/version | 不同文件版本不可混用，缺失即 unknown |
| 函数和错误区域 | 函数稳定 ID、范围、缺失节点/错误范围、依赖区间 | 能表达上述两个函数不直接与错误重叠，但不自动判 complete |
| 局部准入策略 | 是否允许 partial 文件内经审查函数进入正式检测 | 由公共负责人实现及兼容测试；保留文件 partial 和未覆盖义务 |
| 声明/宏/绑定事实 | MsgCryptInfo、SoftBusLog、列表宏、实际 include 与构建分支 | 宏与类型依赖可解释，不能仅按名称认可符号 |
| 参数与成功边 | 调用身份、参数 2 输出成员、SOFTBUS_OK 分支及初始化限制 | 失败边、未检查状态、nullable 输出不凭空引入材料 |

## P1：提高证据可信度

提供版本化受限调用摘要的来源文件哈希、写出字段、成功条件与预算；提供日志 format_index、secure-C 与 HiLog 语义区分、格式化长度成功和构建选择事实。请求内容类型与真实入口证据不能由字符串变量名替代。

## P2：可选动态验证接口

若队长批准，复用现有 Docker Worker / 注册 Harness，传入固定源码、镜像 digest、合成凭据及修复前后/安全对照；返回触发、公开输出、读取主体与权限证据。D 不改公共队列、DB、Catalog 或 UI，不执行未经批准的 PoC。

## 兼容与验收

复用 SourceUnit、ScanContext、Finding、EvidenceObligations 与 file_outcomes，新增事实可选。以真实固定前后代码复核：公共准入前必须仍显示 not_analyzed；准入获准后若产生候选仍为 unassessed / partial，修复端消失需说明日志删除，不升级产品 fixed。A/B/C 和旧 71 控制继续通过。

负责人维护公共 schema、准入与注册；D 提供最小输入、模型和消费侧适配。当前只是 RFC，未修改公共内核。''')
write('D3_research_plan_zh.md','''# 队友 D：D3 后续研究方案（独立文档）

## 研究起点

已获得 1 条真实历史源码的条件研究候选，以及修改后为零的可重复差异；公共 Runner 尚未产出该候选。会话密钥编码入 JSON 与 public 日志实现有源码依据，运行权限及产品影响未证明。

## 下一轮顺序

1. 队长审核 D3 代码、版本模型与 RFC。优先决定 partial 文件内两个目标函数的准入事实与限制表达；D 不自行放宽 Runner。
2. 在同一真实提交和范围验证接口适配，分开报告原始 AST 状态、函数分析状态与文件覆盖。不能把“无直接错误”当“宏依赖已正确”。
3. 补齐请求路径、SESSION_KEY 的实际承载条件，以及日志 256 字节格式化成功条件。检查哪些有效消息能到达被删日志；不将任意解密 JSON 都认作秘密。
4. 核实对应构建是否选择受审适配器、日志等级和读取主体。只有静态路径足够可信并获批准后，设计固定 Docker Harness，以合成凭据做前/后/安全对照；不在宿主机或公开设备执行。
5. 由未参与规则调试的评审者标注冻结后收集的 3 个 security_access_token 源码样本，或选择具有独立真值的同型数据。该组件目前不受模型支持，初步应保留模型覆盖 unknown，不能用它直接计算召回。
6. 按实际需要新增经过审核的版本模型，再重新冻结并使用未见数据评估；不能看过盲审结果后回改规则却继续称同一集合独立。另补真实同名无关接口与可验证私有/脱敏对照。
7. 证据达到门槛才由负责人决定 Catalog 接入、产品影响版本与漏洞升级。PR 不自动 Ready 或合并。

## 独立评估口径

D3_FREEZE.json 在收集前固定算法/模型。D3_HOLDOUT_COLLECTION.json 保存三个非测试、非调试源码的 commit/tree/blob/SHA、选择规则与盲审流程；当前全部未标注，未执行检测，不宣称独立评估已完成。旧 71＋新 24 均是设计与回归控制。

盲审先不给检测预测，标签分 supported-sensitive-public-risk、protected-safe、unrelated、unknown，引用材料语义、路径、日志与权限依据，记录分歧。只有标签和模型适用性成立的子集才计算指标；总数、适用数、partial/not_analyzed/failed/unknown 全部单列。

## 下一轮验收与停止条件

交付负责人准入决议、同范围正式前后对照、请求与日志长度证据、真实控制补充、独立标注记录，以及获准后才执行的隔离结果。条件不足时保留证据缺口，不用更多合成命中或更多规则替代。若仍不能证明非授权读取和 CIA 影响，继续 candidate/unknown，不填写臆测 CVE 或产品 affected/fixed。''')
write('D3_acceptance_zh.md','''# 队友 D：D3 阶段验收文档（独立文档）

日期：2026-10-17。结论：已完成真实版本模型、最小历史算法扩展、前后源码实验与回归；有 1 条真实研究候选，但尚未成为公共 Runner 的正式候选或确认漏洞。

## 验收结果

| 项目 | 实际结果 |
| --- | --- |
| 起始 HEAD | d64d1787250fdff0f912c2733b2739cf6c78ff51；原分支干净、PR 无新评审 |
| 模型提交 | dc9ed46；精确前后版本、每端 10 依赖、来源/日志定义哈希 |
| 算法提交 | 7a75d9c；独立历史模式、分配/非空/成功边、受限一跳摘要 |
| 测试及冻结 HEAD | 88528b791323e25ea96108ab6c95cbc8f3ce646f |
| D 专项 | 25 个 unittest 方法通过；旧 71＋新 24 个设计控制 |
| 全量 | 537 项，526 通过、11 跳过、0 失败/错误 |
| 编译/格式检查 | compileall、git diff --check 通过 |
| 原九文件 | 公共候选 0，complete 0 / partial 3 / not_analyzed 6 / failed 0 |
| 历史前后各十文件 | 公共候选均 0，complete 0 / partial 4 / not_analyzed 6 / failed 0 |
| 真实独立探针 | 修改前 1，修改后 0；两次运行候选与覆盖一致 |
| 已确认漏洞 / PoC | 0 / 未执行 |
| holdout | 冻结后收集 3 个未标注新组件文件；独立评估未执行，无准确率 |

## 用大白话解释这次推进

以前主要证明“人工写的小样例能识别”。这次在未修改的真实鸿蒙历史代码中，找到了“请求 JSON 可以装会话密钥，解密成功后整个缓冲区被公开日志打印”的风险路径，并在删日志后的真实版本看到候选消失。

不过平台解析整个文件时，被其他函数里的宏卡住，所以这条发现来自明确标注的研究探针；网页/正式 Runner 还没有获得同样能力。也没有证明量产设备会实际输出、普通应用能读取，故不能说已确认一个真实信息泄露漏洞。

## 与任务目标对应

- A：真实日志删除前后实验已执行，输入固定到完整 Git 对象，双跑稳定。
- B：两个精确版本独立模型已实现，敏感性依据为 Base64 编码/解码的会话密钥字段及协议用途，日志依据为具体格式化与 public 适配。
- C：真实源码已执行，公共与私有结果分开；零候选和解析阻塞均有解释。
- D：模型、算法、测试分开提交，研究证据与独立三份文档交付；最终远端提交和 Draft 状态以发布核验回执为准。

实验 4 尚缺独立真实同名无关函数；真实脱敏形状未在受审模型上正式评估。独立真值与产品验证未完成，任务书允许先交付实际收集/盲审流程及阻塞 RFC，不能将这些缺口标为通过。

## 主要修复/新增机制

为旧 SoftBusLog 单独核验参数和默认公开语义，避免误用 HiLog 私有默认值。只有检查成功返回、分配与非空的局部路径才引入历史来源；失败、未初始化、未知别名、未审提交或依赖哈希不符时不硬报。同名遮蔽和成员覆盖有控制；未支持的复制成功状态与复杂语义保留限制。

## 复核入口

research/data_sensitive/D3_HANDOFF.md 是总入口；D3_MODEL_EVIDENCE.md 核对模型；D3_HISTORICAL_CASES.md 核对服务发现排除与 TCP 条件候选；D3_REAL_SCAN.json / .md 核对实际实验；D3_VALIDATION.json 核对日志 SHA 与 skip 理由。

本机 Ubuntu：/home/lzc/projects/OHScanner-teammate-D。专项命令：

```bash
cd /home/lzc/projects/OHScanner-teammate-D
PY=/home/lzc/projects/CyberSecurity-Innovation-Audit/.venv-web/bin/python
$PY -m unittest tests.detectors.data.test_sensitive_exposure tests.detectors.data.test_d2_semantics tests.detectors.data.test_d3_historical -v
TMPDIR="$PWD/.tmp" $PY -m unittest discover -s tests -v
```

11 项 skip 为既有语料/固定历史源码缺失与禁止宿主机执行的 Docker 测试；逐条理由见 JSON。未修改公共 Runner、Catalog、contracts、frontend、DB/UI 或其他队友模块；旧 71 控制哈希保持不变。

## 下一步审批点

先审核 D3_interface_requirements_zh.md 的局部事实与准入请求；再按 D3_research_plan_zh.md 补真实请求、日志与读取权限证据。不能将研究探针直接当生产能力，不自动 Ready、合并或确认漏洞。''')
write('D3_HANDOFF.md','''# D3 交付与停止核对

本轮按任务书在原 D 分支执行。起始与远端状态见 D3_BASELINE.json；源码来源见 D3_SOURCE_MANIFEST.json。模型、算法、测试分别提交，冻结实现见 D3_FREEZE.json；证据/文档提交在其后，不改变冻结算法。

| 交付 | 入口 |
| --- | --- |
| 实现及边界 | D3_IMPLEMENTATION.md |
| 模型来源 | D3_MODEL_EVIDENCE.md、historical_profiles.json |
| 两组历史判断 | D3_HISTORICAL_CASES.md |
| 真实实验与覆盖 | D3_REAL_SCAN.md / .json、D3_REAL_CONTROLS.json |
| 本轮验证 | D3_VALIDATION.json |
| 剩余限制 | D3_LIMITATIONS.md |
| 三份独立用户文档 | D3_acceptance_zh.md、D3_interface_requirements_zh.md、D3_research_plan_zh.md |
| 冻结后未标注数据 | D3_HOLDOUT_COLLECTION.json |

实际结果：537 测试中 526 通过、11 跳过；D 专项 25 个方法。原九文件覆盖无变化。真实 TCP 历史前后研究候选 1→0，公共均 0，目标 partial 文件未获公共准入。服务发现案例因开源 stub 返回不支持而排除为有效正例。已确认漏洞 0，没有 PoC/独立评估准确率。

四类统计与真实控制缺口不可混算。三个新组件源码仅收集待独立盲审，无标签、未测评。未调用其他 agent 或把本次自审冒充独立真值。

开发范围保持 D 的四个获准目录。任务书禁止修改其他路径，故 D3 当前状态在本研究交付中记录，不修改公共状态表；此明确任务约束优先于根 AGENTS 的通用状态更新规则。

本地可执行目标已到达任务书允许的停止边界：真实实验、模型、必要代码、回归与缺口/RFC已形成。按授权更新原 Draft PR #17 后停止，不继续扩规则，不擅改公共准入，不执行未经批准的动态 PoC。远端发布是否成功以单独核验回执为准，不把本地文档当推送证明。''')
print(json.dumps({'full_suite':validation['full_suite'],'docs_generated':True,'freeze_unchanged':True},ensure_ascii=False))
