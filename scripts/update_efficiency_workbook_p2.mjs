import fs from 'node:fs/promises';
import { FileBlob, SpreadsheetFile } from '@oai/artifact-tool';

const root = 'D:/openHarmonyScanner/worktrees/c-line-task-tree-20261020/research/deliveries/performance/full_efficiency_20261021';
const folder = `${root}/p2_corpus_result_cache`;
const path = `${root}/OHScanner_Efficiency_E0-E4_20261021.xlsx`;
const e2Folder = `${root}/E2_fixed_corpus`;
const e2Names = ['same_environment_e0', 'ext4_cold', 'ext4_hot'];
const e2Labels = ['E0 同环境全量无缓存', 'E2 冷缓存（ext4）', 'E2 热缓存（ext4）'];
const e2Reports = {};
for (const name of e2Names) {
  e2Reports[name] = JSON.parse(await fs.readFile(`${e2Folder}/${name}.json`, 'utf8'));
}
const e2BaselineRows = Object.fromEntries(e2Reports.same_environment_e0.rows.map(row => [row.label, row]));
const e2Pct = (value, baseline) => `${((value / baseline - 1) * 100).toFixed(1)}%`;
const e2Sum = (name, key) => e2Reports[name].rows.reduce((n, row) => n + Number(row[key] ?? 0), 0);
const e2Stats = Object.fromEntries(e2Names.map(name => {
  const rows = e2Reports[name].rows;
  const equal = name === 'same_environment_e0' || rows.every(row =>
    e2BaselineRows[row.label]?.result_signature === row.result_signature);
  return [name, {
    wall: e2Sum(name, 'wall_seconds'), cpu: e2Sum(name, 'cpu_seconds'),
    astCpu: e2Sum(name, 'ast_parse_cpu_seconds'), detectorWall: e2Sum(name, 'detector_stage_wall_seconds'),
    files: e2Sum(name, 'scanned_files'), parseFiles: e2Sum(name, 'parse_files'),
    astHits: e2Sum(name, 'ast_cache_hits'), resultHits: e2Sum(name, 'detector_result_cache_hits'),
    resultMisses: e2Sum(name, 'detector_result_cache_misses'),
    reusedSourcePaths: e2Sum(name, 'detector_result_cache_reused_source_paths'),
    candidates: e2Sum(name, 'diagnostic_count'),
    maxRssKb: Math.max(...rows.map(row => Number(row.peak_rss_kb ?? 0))),
    completed: rows.filter(row => row.exit_code === 0).length,
    limited: rows.filter(row => row.status === 'completed_with_limitations').length,
    equal,
  }];
}));
const names = ['E0_no_result_cache', 'E3_result_cache_cold', 'E3_result_cache_hot'];
const reports = {};
for (const name of names) reports[name] = JSON.parse(await fs.readFile(`${folder}/${name}.json`, 'utf8'));
const summarize = (report) => {
  const rows = report.rows;
  const sum = (key) => rows.reduce((n, row) => n + Number(row[key] ?? 0), 0);
  return {
    wall: sum('wall_seconds'), cpu: sum('cpu_seconds'), astWall: sum('ast_parse_seconds'),
    astCpu: sum('ast_parse_cpu_seconds'), parseFiles: sum('parse_files'),
    hits: sum('detector_result_cache_hits'), misses: sum('detector_result_cache_misses'),
    detectorWall: sum('detector_stage_wall_seconds'), detectorCpu: sum('detector_stage_cpu_seconds'),
    peakRssKb: Math.max(...rows.map(row => Number(row.peak_rss_kb ?? 0))),
    completed: rows.filter(row => row.exit_code === 0).length,
    partial: rows.filter(row => row.status === 'completed_with_limitations').length,
  };
};
const stats = Object.fromEntries(names.map(name => [name, summarize(reports[name])]));
const baselineRows = Object.fromEntries(reports.E0_no_result_cache.rows.map(row => [row.label, row]));
const equivalence = names.slice(1).map(name => ({name, allSignaturesMatch: reports[name].rows.every(row => baselineRows[row.label]?.result_signature === row.result_signature)}));
const pct = (value, baseline) => `${((value / baseline - 1) * 100).toFixed(1)}%`;
const wb = await SpreadsheetFile.importXlsx(await FileBlob.load(path));
let ws;
try { ws = wb.worksheets.getItem('P2 fixed corpus'); }
catch { ws = wb.worksheets.add('P2 fixed corpus'); }
const navy = '#17365D', blue = '#2F5597', amber = '#FFF2CC', text = '#243244';
ws.showGridLines = false;
ws.tabColor = navy;
ws.getRange('A1:L1').merge();
ws.getRange('A1').values = [['P2 单文件检测结果缓存：固定 11 组件冷/热对照']];
ws.getRange('A1:L1').format = {fill:navy,font:{name:'Arial',size:15,bold:true,color:'#FFFFFF'},verticalAlignment:'center'};
ws.getRange('A2:L2').merge();
ws.getRange('A2').values = [['固定 manifest SHA / 同一工作区与示例 detector；11 组件、9,508 源文件。仍完整索引与解析 head，只实验 source-only detector 结果缓存。']];
ws.getRange('A2:L2').format = {font:{name:'Arial',size:10,color:'#526174',italic:true},wrapText:true,verticalAlignment:'center'};
ws.getRange('A4:L4').values = [['实验','模式','状态','总墙钟秒','进程 CPU 秒','AST 墙钟秒','AST CPU 秒','解析文件数','结果缓存 hit / miss','Detector 阶段墙钟秒','峰值 RSS KB','结果等价']];
ws.getRange('A4:L4').format = {fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true,horizontalAlignment:'center',verticalAlignment:'center'};
const modes = [
  ['E0','无结果缓存','E0_no_result_cache','基线'],
  ['E3 cold','冷 detector-result cache','E3_result_cache_cold',equivalence[0].allSignaturesMatch?'11/11 与 E0 一致':'不匹配'],
  ['E3 hot','热 detector-result cache','E3_result_cache_hot',equivalence[1].allSignaturesMatch?'11/11 与 E0 一致':'不匹配'],
];
const rows = modes.map(([label,mode,key,eq]) => { const s=stats[key]; return [label,mode,`${s.completed}/11 completed; ${s.partial}/11 with limitations`,s.wall,s.cpu,s.astWall,s.astCpu,s.parseFiles,`${s.hits} / ${s.misses}`,s.detectorWall,s.peakRssKb,eq]; });
ws.getRange('A5:L7').values = rows;
ws.getRange('A5:L7').format = {font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
ws.getRange('D5:G7').format.numberFormat = '0.000';
ws.getRange('H5:H7').format.numberFormat = '#,##0';
ws.getRange('J5:K7').format.numberFormat = '#,##0.000';
ws.getRange('A9:C9').values = [['核对','实测','解释']];
ws.getRange('A9:C9').format = {fill:blue,font:{name:'Arial',size:10,bold:true,color:'#FFFFFF'}};
const checks = [
 ['组件与范围','11 / 11；9,508 文件','三轮使用同一固定 manifest；扫描范围不变'],
 ['候选、位置、解析、覆盖、整体状态',equivalence.every(item=>item.allSignaturesMatch)?'cold/hot 均 11/11 一致':'存在不匹配','signature 包含诊断、定位、源哈希、解析、detector coverage 和总状态'],
 ['partial 状态','33 / 33 completed_with_limitations','没有抹掉扫描限制或把状态提升为完整'],
 ['热跑总墙钟变化',pct(stats.E3_result_cache_hot.wall,stats.E0_no_result_cache.wall),`${stats.E0_no_result_cache.wall.toFixed(3)}s -> ${stats.E3_result_cache_hot.wall.toFixed(3)}s；增幅来自当前实验全流程`],
 ['热跑进程 CPU 变化',pct(stats.E3_result_cache_hot.cpu,stats.E0_no_result_cache.cpu),`${stats.E0_no_result_cache.cpu.toFixed(3)}s -> ${stats.E3_result_cache_hot.cpu.toFixed(3)}s`],
 ['AST 解析 CPU 变化',pct(stats.E3_result_cache_hot.astCpu,stats.E0_no_result_cache.astCpu),`${stats.E0_no_result_cache.astCpu.toFixed(3)}s -> ${stats.E3_result_cache_hot.astCpu.toFixed(3)}s；源解析完整运行`],
 ['Detector 阶段墙钟',`${stats.E0_no_result_cache.detectorWall.toFixed(3)} / ${stats.E3_result_cache_cold.detectorWall.toFixed(3)} / ${stats.E3_result_cache_hot.detectorWall.toFixed(3)}s`,'顺序为 E0 / E3 cold / E3 hot；文件缓存读写耗时超过示例 detector 本身'],
 ['峰值 RSS',`${stats.E0_no_result_cache.peakRssKb} / ${stats.E3_result_cache_cold.peakRssKb} / ${stats.E3_result_cache_hot.peakRssKb} KB`,'逐组件最大值；不同组件单进程上界，不是可靠内存收益'],
 ['CPU quota','unknown','环境未暴露可验证的有限配额，不估算利用率'],
];
ws.getRange('A10:C18').values = checks;
ws.getRange('A10:C18').format = {font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
ws.getRange('B10:B18').format.font = {name:'Arial',size:9,bold:true,color:navy};
ws.getRange('A20:L20').merge();
ws.getRange('A20').values = [['结论：输出等价通过，但该 detector-result cache 反而显著变慢，AST 解析 CPU 不变；仅保持 opt-in 研究状态，不作为性能收益交付。P0/P1 AST summary cache 是减少重复 AST 解析的实现，数据另见 P3 current 页。示例 detector 不是 ABCD 全量漏洞扫描。']];
ws.getRange('A20:L20').format = {fill:amber,font:{name:'Arial',size:9,color:'#7F6000'},wrapText:true,verticalAlignment:'center'};
ws.getRange('A22:L22').merge();
ws.getRange('A22').values = [['Workbench 增量基线接口与边界']];
ws.getRange('A22:L22').format = {fill:blue,font:{name:'Arial',size:10,bold:true,color:'#FFFFFF'},verticalAlignment:'center'};
const apiRows = [
 ['界面/API','预览与扫描 API 接受可选完整 base_commit；UI 和任务详情展示基线 SHA。',null,null,null,null,null,null,null,null,null,null],
 ['任务绑定','校验 base commit 存在且是 head 祖先；workflow SHA 和 job spec 都绑定该值。',null,null,null,null,null,null,null,null,null,null],
 ['执行语义','Worker 将 base_commit 交给扫描器；报告列变更路径、依赖完整性与 fallback。',null,null,null,null,null,null,null,null,null,null],
 ['正确性边界','依赖索引或 detector 跨文件重用无法证明时继续完整 head scan；不把 E1 变更文件扫描当完整结果。',null,null,null,null,null,null,null,null,null,null],
 ['回归验证','Workbench API/Worker: 94 passed, 1 skipped；前端 build + tests: 69 passed。',null,null,null,null,null,null,null,null,null,null],
];
ws.getRange('A23:L27').values = apiRows;
ws.getRange('A23:L27').format = {font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
for (let row=23; row<=27; row++) ws.getRange(`B${row}:L${row}`).merge();
ws.getRange('A23:A27').format.font = {name:'Arial',size:9,bold:true,color:navy};
ws.getRange('A29:L29').merge();
ws.getRange('A29').values = [['P4 中途 detector 分片检查点与恢复验证']];
ws.getRange('A29:L29').format = {fill:blue,font:{name:'Arial',size:10,bold:true,color:'#FFFFFF'},verticalAlignment:'center'};
const checkpointRows = [
 ['恢复边界','每次任务重试仍重新读取固定 Git 源码并重建 AST、索引与事实；只可跳过身份验证通过的已完成 detector 分片。',null,null,null,null,null,null,null,null,null,null],
 ['身份绑定','仓库、commit、snapshot、profile、来源类型、完整 SourceUnit 内容/语言/解析状态、共享事实摘要、detector ID/version/实现文件 SHA、required facts 和 engine SHA。',null,null,null,null,null,null,null,null,null,null],
 ['持久化与上限','检查点为带 payload SHA-256 的 JSON；原子替换并 fsync。单条上限 16 MiB；超限时不缓存并照常运行 detector。',null,null,null,null,null,null,null,null,null,null],
 ['覆盖保护','只保存 detector execution status=completed；保存并逐项验证原始覆盖侧车。覆盖状态仍可为 partial；failed/blocked 不保存，损坏/不匹配一律重新检测。',null,null,null,null,null,null,null,null,null,null],
 ['验证','WSL 定向集成：15 passed、4 subtests passed。覆盖冷/热结果身份、源码/引擎失效、损坏回退、failed/blocked 不缓存及 partial 保留。',null,null,null,null,null,null,null,null,null,null],
 ['性能结论','本次检查点夹具验证正确性和恢复路径，不构成固定 11 组件性能测量；没有新增加速比例或 CPU/RSS 结论。',null,null,null,null,null,null,null,null,null,null],
 ['相关回归','最新 P2–P5 综合回归：218 passed、1 skipped、22 subtests passed；覆盖 detector checkpoint、增量、事实提供器、资源模式、CPU 配额、Worker 并发、Workbench 与 Agent workflow。',null,null,null,null,null,null,null,null,null,null],
];
ws.getRange('A30:L36').values = checkpointRows;
ws.getRange('A30:L36').format = {font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
for (let row=30; row<=36; row++) ws.getRange(`B${row}:L${row}`).merge();
ws.getRange('A30:A36').format.font = {name:'Arial',size:9,bold:true,color:navy};
ws.getRange('A1:A20').format.columnWidth = 18;
ws.getRange('B1:B20').format.columnWidth = 26;
ws.getRange('C1:C20').format.columnWidth = 28;
ws.getRange('D1:H20').format.columnWidth = 14;
ws.getRange('I1:I20').format.columnWidth = 22;
ws.getRange('J1:K20').format.columnWidth = 18;
ws.getRange('L1:L20').format.columnWidth = 23;
ws.getRange('A2:L2').format.rowHeight = 34;
ws.getRange('A4:L4').format.rowHeight = 38;
ws.getRange('A5:L7').format.rowHeight = 44;
ws.getRange('A10:C18').format.rowHeight = 35;
ws.getRange('A20:L20').format.rowHeight = 54;
ws.getRange('A22:L22').format.rowHeight = 27;
ws.getRange('A23:L27').format.rowHeight = 34;
ws.getRange('A29:L29').format.rowHeight = 27;
ws.getRange('A30:L36').format.rowHeight = 42;
ws.freezePanes.freezeRows(4);
const summary = wb.worksheets.getItem('E0-E4对照');
summary.getRange('C5').values = [['合成风险夹具已完成；固定语料未测']];
summary.getRange('H5').values = [['三文件样本：仅扫变更文件漏掉 3/3 个未变文件候选；不作为完整扫描或性能结果']];
summary.getRange('B5:H5').format.wrapText = true;
summary.getRange('B5:H5').format.verticalAlignment = 'center';
summary.getRange('A5:H5').format.rowHeight = 48;
summary.getRange('B9').values = [['离线调度 helper 夹具；真实 Provider 未运行']];
summary.getRange('C9').values = [['离线 fixture 完成；Provider not_run']];
summary.getRange('H9').values = [['helper 验证根因键、义务动作排序与重复 memo；模型延迟、Token、成本和质量 unknown']];
summary.getRange('B9:H9').format.wrapText = true;
summary.getRange('B9:H9').format.verticalAlignment = 'center';
summary.getRange('A9:H9').format.rowHeight = 42;
summary.getRange('B6').values = [['base→head；变更配置时保守全量回退，复用已声明的完整单文件 detector 结果']];
summary.getRange('C6').values = [['固定语料 E2 冷/热已完成；11/11 等价']];
summary.getRange('D6').values = [[e2Stats.ext4_hot.wall]];
summary.getRange('E6').values = [[e2Stats.ext4_hot.cpu]];
summary.getRange('F6').values = [[e2Stats.ext4_hot.parseFiles]];
summary.getRange('G6').values = [[e2Stats.ext4_hot.maxRssKb]];
summary.getRange('H6').values = [[`同环境 E0=${e2Stats.same_environment_e0.wall.toFixed(1)}s；E2 冷=${e2Stats.ext4_cold.wall.toFixed(1)}s，热=${e2Stats.ext4_hot.wall.toFixed(1)}s（热 vs E0 ${e2Pct(e2Stats.ext4_hot.wall, e2Stats.same_environment_e0.wall)}）。热缓存未减少扫描覆盖；所有组件仍 completed_with_limitations。`]];
summary.getRange('B6:H6').format.wrapText = true;
summary.getRange('B6:H6').format.verticalAlignment = 'center';
summary.getRange('A6:H6').format.rowHeight = 64;
summary.getRange('D6:G6').format.numberFormat = '0.000';
summary.getRange('H6').format.wrapText = true;
wb.recalculate();
const inspection = await wb.inspect({kind:'sheet,region',sheetId:'P2 fixed corpus',range:'A1:L36',maxChars:12000});
const image = await wb.render({sheetName:'P2 fixed corpus',range:'A1:L36',scale:1,format:'png'});
await fs.writeFile(`${folder}/P2_cache_corpus_preview.png`,new Uint8Array(await image.arrayBuffer()));
const summaryInspection = await wb.inspect({kind:'region',sheetId:'E0-E4对照',range:'A3:H10',maxChars:3000});
const summaryImage = await wb.render({sheetName:'E0-E4对照',range:'A1:H10',scale:1,format:'png'});
await fs.writeFile(`${folder}/E0_E4_summary_preview.png`,new Uint8Array(await summaryImage.arrayBuffer()));
const m2Folder = `${root}/p2_m2_fixed_corpus`;
const m2Names = ['E0_M2_no_cache','M2_ast_cache_hot_no_result_cache','E3_M2_cold_ext4','E3_M2_hot_ext4'];
const m2Labels = ['E0 无缓存','AST-only 热缓存','E3 冷缓存','E3 热缓存'];
const m2Reports = {};
for (const name of m2Names) m2Reports[name] = JSON.parse(await fs.readFile(`${m2Folder}/${name}.json`, 'utf8'));
const m2Sum = (name, key) => m2Reports[name].rows.reduce((n, row) => n + Number(row[key] ?? 0), 0);
const m2Rows = m2Names.map((name, i) => {
  const report = m2Reports[name];
  const rss = Math.max(...report.rows.map(row => Number(row.peak_rss_kb ?? 0)));
  const equal = name === m2Names[0] || report.rows.every((row, index) =>
    row.result_signature === m2Reports[m2Names[0]].rows[index].result_signature);
  return [m2Labels[i], m2Sum(name,'wall_seconds'), m2Sum(name,'cpu_seconds'),
    m2Sum(name,'ast_parse_cpu_seconds'), m2Sum(name,'detector_stage_wall_seconds'),
    m2Sum(name,'parse_files'), m2Sum(name,'ast_cache_hits'),
    m2Sum(name,'detector_result_cache_hits'), m2Sum(name,'detector_result_cache_misses'),
    m2Sum(name,'diagnostic_count'), rss,
    `${report.rows.filter(row => row.status === 'completed_with_limitations').length}/11 completed_with_limitations`,
    equal ? '11/11 与 E0 一致' : '存在差异'];
});
let m2Sheet;
try { m2Sheet = wb.worksheets.getItem('P2 M2 固定语料'); }
catch { m2Sheet = wb.worksheets.add('P2 M2 固定语料'); }
const pale='#EAF2F8';
m2Sheet.showGridLines = false;
m2Sheet.tabColor = navy;
m2Sheet.getRange('A1:M1').merge();
m2Sheet.getRange('A1').values = [['P2：M2 两个逐文件 detector 的固定 11 组件缓存对照']];
m2Sheet.getRange('A1:M1').format = {fill:navy,font:{name:'Arial',size:14,bold:true,color:'#FFFFFF'},verticalAlignment:'center'};
m2Sheet.getRange('A2:M2').merge();
m2Sheet.getRange('A2').values = [['固定 9,508 个源码文件；候选执行成本实验，不是漏洞准确率或 ABCD 全量扫描。E3 缓存位于 WSL2 ext4；所有组候选/位置/解析/覆盖/状态签名需与 E0 一致。所有 11 个 head SHA 匹配 manifest，但 parent commit 对象 0/11 可用，完整 E2 base→head 语料对照未运行。']];
m2Sheet.getRange('A2:M2').format = {fill:pale,font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center'};
m2Sheet.getRange('A4:M4').values = [['实验组','总墙钟秒','进程 CPU 秒','AST CPU 秒','Detector 阶段秒','Parser 调用文件','AST cache hit','结果 cache hit','结果 cache miss','候选数','峰值 RSS KB','整体状态','结果等价']];
m2Sheet.getRange('A4:M4').format = {fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true,horizontalAlignment:'center',verticalAlignment:'center'};
m2Sheet.getRange('A5:M8').values = m2Rows;
m2Sheet.getRange('A5:M8').format = {font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
m2Sheet.getRange('B5:E8').format.numberFormat = '0.000';
m2Sheet.getRange('F5:J8').format.numberFormat = '#,##0';
m2Sheet.getRange('K5:K8').format.numberFormat = '#,##0';
m2Sheet.getRange('A10:D10').values = [['关键对照','实测变化','解释','边界']];
m2Sheet.getRange('A10:D10').format = {fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true};
const m2Checks=[
  ['E3 热 vs E0 总墙钟',pct(m2Sum(m2Names[3],'wall_seconds'),m2Sum(m2Names[0],'wall_seconds')),'两个 M2 detector、全量 head inventory','含 AST 与逐文件 detector cache'],
  ['E3 热 vs E0 进程 CPU',pct(m2Sum(m2Names[3],'cpu_seconds'),m2Sum(m2Names[0],'cpu_seconds')),'resource.getrusage 汇总','该环境没有有限 CPU quota'],
  ['E3 热 vs AST-only 总墙钟',pct(m2Sum(m2Names[3],'wall_seconds'),m2Sum(m2Names[1],'wall_seconds')),'用于显示 detector per-file cache 的增量贡献','仍是完整源码与 AST 索引'],
  ['E3 热结果命中','13,037 hit / 107 miss','只复用完整单文件 adapter 结果','107 个非完整/不满足条件结果继续检测'],
  ['准确率 / 已验证漏洞','未测 / 0','没有独立标签；63 条保持 candidate','不是 ABCD 全量扫描结论'],
];
m2Sheet.getRange('A11:D15').values=m2Checks;
m2Sheet.getRange('A11:D15').format={font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
m2Sheet.getRange('A16:D16').values=[['目标回归','22 passed','P2 cache、M2 integration、incremental equivalence/planning','`compileall` 与 `git diff --check` passed']];
m2Sheet.getRange('A16:D16').format={font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
m2Sheet.getRange('A17:M17').merge();
m2Sheet.getRange('A17').values=[['逐组件原始对照：每行一个组件/实验组；result signature 绑定诊断、源码定位、解析、检测器覆盖和整体状态。']];
m2Sheet.getRange('A17:M17').format={fill:navy,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true};
m2Sheet.getRange('A18:M18').values=[['组件','实验组','固定 commit','墙钟秒','进程 CPU 秒','AST CPU 秒','Detector 阶段秒','Parser 调用','AST hit','结果 hit/miss','候选数','整体状态','与 E0 等价']];
m2Sheet.getRange('A18:M18').format={fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true,horizontalAlignment:'center',verticalAlignment:'center'};
const e0ByLabel=Object.fromEntries(m2Reports[m2Names[0]].rows.map(row=>[row.label,row]));
const detail=[];
for (let group=0; group<m2Names.length; group++) {
  const name=m2Names[group];
  for (const row of m2Reports[name].rows) {
    const e0=e0ByLabel[row.label];
    detail.push([row.label,m2Labels[group],row.commit,row.wall_seconds,row.cpu_seconds,
      row.ast_parse_cpu_seconds,row.detector_stage_wall_seconds,row.parse_files,
      row.ast_cache_hits,`${row.detector_result_cache_hits ?? 0} / ${row.detector_result_cache_misses ?? 0}`,
      row.diagnostic_count,row.status,row.result_signature===e0?.result_signature?'一致':'不一致']);
  }
}
m2Sheet.getRange(`A19:M${18+detail.length}`).values=detail;
m2Sheet.getRange(`A19:M${18+detail.length}`).format={font:{name:'Arial',size:8,color:text},wrapText:true,borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
m2Sheet.getRange(`D19:G${18+detail.length}`).format.numberFormat='0.000';
m2Sheet.getRange(`H19:I${18+detail.length}`).format.numberFormat='#,##0';
m2Sheet.getRange(`A1:A${18+detail.length}`).format.columnWidth=18;
m2Sheet.getRange(`B1:B${18+detail.length}`).format.columnWidth=22;
m2Sheet.getRange(`C1:C${18+detail.length}`).format.columnWidth=42;
m2Sheet.getRange(`D1:G${18+detail.length}`).format.columnWidth=14;
m2Sheet.getRange(`H1:I${18+detail.length}`).format.columnWidth=13;
m2Sheet.getRange(`J1:J${18+detail.length}`).format.columnWidth=16;
m2Sheet.getRange(`K1:K${18+detail.length}`).format.columnWidth=10;
m2Sheet.getRange(`L1:L${18+detail.length}`).format.columnWidth=27;
m2Sheet.getRange(`M1:M${18+detail.length}`).format.columnWidth=18;
m2Sheet.getRange('A1:M1').format.rowHeight=32;
m2Sheet.getRange('A2:M2').format.rowHeight=38;
m2Sheet.getRange('A4:M4').format.rowHeight=42;
m2Sheet.getRange('A5:M8').format.rowHeight=40;
m2Sheet.getRange('A10:D10').format.rowHeight=30;
m2Sheet.getRange('A11:D15').format.rowHeight=42;
m2Sheet.getRange('A16:D16').format.rowHeight=42;
m2Sheet.getRange('A17:M18').format.rowHeight=34;
m2Sheet.getRange(`A19:M${18+detail.length}`).format.rowHeight=27;
m2Sheet.freezePanes.freezeRows(4);
const m2Preview=await wb.render({sheetName:'P2 M2 固定语料',range:`A1:M${18+detail.length}`,scale:0.75,format:'png'});
await fs.writeFile(`${m2Folder}/P2_M2_fixed_corpus_preview.png`,new Uint8Array(await m2Preview.arrayBuffer()));
const m2Inspection=await wb.inspect({kind:'sheet,region',sheetId:'P2 M2 固定语料',range:`A1:M${18+detail.length}`,maxChars:10000});
let e2Sheet;
try { e2Sheet = wb.worksheets.getItem('E2 fixed corpus'); }
catch { e2Sheet = wb.worksheets.add('E2 fixed corpus'); }
try { e2Sheet.getRange('A16:N16').unmerge(); } catch { /* not merged on the initial build */ }
e2Sheet.showGridLines = false;
e2Sheet.tabColor = navy;
e2Sheet.getRange('A1:N1').merge();
e2Sheet.getRange('A1').values = [['E2：固定 11 组件 base→head 与热缓存对照']];
e2Sheet.getRange('A1:N1').format = {fill:navy,font:{name:'Arial',size:14,bold:true,color:'#FFFFFF'},verticalAlignment:'center'};
e2Sheet.getRange('A2:N2').merge();
e2Sheet.getRange('A2').values = [['同环境 WSL2 / Python 3.14，11 个固定 head/base、9,508 个源码文件、两个 M2 detector。E2 冷/热缓存位于 WSL 原生 /tmp ext4；命中复用已声明可缓存的完整单文件 detector 结果，依赖或构建配置不完整时仍全量检查 head。不是 ABCD 全量扫描或准确率实验。']];
e2Sheet.getRange('A2:N2').format = {fill:pale,font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center'};
e2Sheet.getRange('A4:M4').values = [['实验组','墙钟秒','进程 CPU 秒','AST CPU 秒','Detector 阶段秒','扫描文件清单','Parser 调用','AST hit','结果 hit','结果 miss','候选诊断','最大组件 RSS KB','等价/覆盖']];
e2Sheet.getRange('A4:M4').format = {fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true,horizontalAlignment:'center',verticalAlignment:'center'};
const e2TableRows = e2Names.map((name, i) => {
  const s = e2Stats[name];
  return [e2Labels[i],s.wall,s.cpu,s.astCpu,s.detectorWall,s.files,s.parseFiles,s.astHits,
    s.resultHits,s.resultMisses,s.candidates,s.maxRssKb,
    `${s.completed}/11 completed；${s.limited}/11 completed_with_limitations；${s.equal ? '11/11 签名一致' : '签名差异'}`];
});
e2Sheet.getRange('A5:M7').values = e2TableRows;
e2Sheet.getRange('A5:M7').format = {font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
e2Sheet.getRange('B5:E7').format.numberFormat = '0.000';
e2Sheet.getRange('F5:L7').format.numberFormat = '#,##0';
e2Sheet.getRange('A9:D9').values = [['对照指标','E2 热 vs E0','E2 冷 vs E0','说明']];
e2Sheet.getRange('A9:D9').format = {fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true};
const e2Comparisons = [
  ['总墙钟',e2Pct(e2Stats.ext4_hot.wall,e2Stats.same_environment_e0.wall),e2Pct(e2Stats.ext4_cold.wall,e2Stats.same_environment_e0.wall),'冷缓存包括序列化/写盘填充成本；热缓存测已填充目录。'],
  ['进程 CPU',e2Pct(e2Stats.ext4_hot.cpu,e2Stats.same_environment_e0.cpu),e2Pct(e2Stats.ext4_cold.cpu,e2Stats.same_environment_e0.cpu),'用 process CPU 记录，不是 CPU 配额利用率。'],
  ['AST 解析 CPU',e2Pct(e2Stats.ext4_hot.astCpu,e2Stats.same_environment_e0.astCpu),e2Pct(e2Stats.ext4_cold.astCpu,e2Stats.same_environment_e0.astCpu),'热缓存解析调用从 9,508 降到 201，命中 9,307。'],
  ['Detector 阶段墙钟',e2Pct(e2Stats.ext4_hot.detectorWall,e2Stats.same_environment_e0.detectorWall),e2Pct(e2Stats.ext4_cold.detectorWall,e2Stats.same_environment_e0.detectorWall),'E2 热跑复用完整结果 13,037 次，另有 107 次 miss 后重算。'],
  ['结果复用 source paths',`${e2Stats.ext4_hot.reusedSourcePaths.toLocaleString()} paths`,'0 paths','head inventory 的 9,508 个文件仍全部扫描；复用仅作用于声明了安全单文件契约的 detector。'],
  ['结果/覆盖',`${e2Stats.ext4_hot.candidates} diagnostics; 11/11 等价`,'11/11 等价','E0 与 E2 热缓存签名一致；11 组均 completed_with_limitations，未声称漏洞准确率。'],
  ['最大组件 RSS',e2Pct(e2Stats.ext4_hot.maxRssKb,e2Stats.same_environment_e0.maxRssKb),e2Pct(e2Stats.ext4_cold.maxRssKb,e2Stats.same_environment_e0.maxRssKb),'按串行组件进程的最大峰值计算；热缓存 RSS 高于 E0，不能宣称内存降低。'],
];
e2Sheet.getRange('A10:C16').values = e2Comparisons.map(row => row.slice(0,3));
e2Sheet.getRange('D10:D16').values = e2Comparisons.map(row => [row[3]]);
e2Sheet.getRange('A10:N16').format = {fill:'#FFFFFF',font:{name:'Arial',size:9,color:text},wrapText:true,verticalAlignment:'center',borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
for (let row=10; row<=16; row++) {
  try { e2Sheet.getRange(`D${row}:N${row}`).merge(); } catch { /* already merged on a previous build */ }
}
e2Sheet.getRange('A17:N17').values = [[null,null,null,null,null,null,null,null,null,null,null,null,null,null]];
e2Sheet.getRange('A17:N17').format = {fill:'#FFFFFF',font:{name:'Arial',size:8,color:text}};
e2Sheet.getRange('A18:N18').merge();
e2Sheet.getRange('A18').values = [['组件级原始对照：E0 / E2 冷 / E2 热，每行绑定固定 commit、阶段计时、覆盖状态与结果签名。']];
e2Sheet.getRange('A18:N18').format = {fill:navy,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true};
e2Sheet.getRange('A19:N19').values = [['组件','实验组','固定 head commit','墙钟秒','CPU 秒','AST CPU 秒','Detector 阶段秒','扫描文件清单','Parser 调用','AST hit','结果 hit / miss','候选诊断','整体 / detector 状态','与 E0 签名']];
e2Sheet.getRange('A19:N19').format = {fill:blue,font:{name:'Arial',size:9,bold:true,color:'#FFFFFF'},wrapText:true,horizontalAlignment:'center',verticalAlignment:'center'};
const e2Detail = [];
for (let group=0; group<e2Names.length; group++) {
  const name=e2Names[group];
  for (const row of e2Reports[name].rows) {
    const base=e2BaselineRows[row.label];
    e2Detail.push([row.label,e2Labels[group],row.commit,row.wall_seconds,row.cpu_seconds,
      row.ast_parse_cpu_seconds,row.detector_stage_wall_seconds,row.scanned_files,row.parse_files,
      row.ast_cache_hits,`${row.detector_result_cache_hits ?? 0} / ${row.detector_result_cache_misses ?? 0}`,
      row.diagnostic_count,`${row.status} / ${row.detector_status}`,
      row.result_signature===base?.result_signature?'一致':'不一致']);
  }
}
e2Sheet.getRange(`A20:N${19+e2Detail.length}`).values = e2Detail;
e2Sheet.getRange(`A20:N${19+e2Detail.length}`).format = {font:{name:'Arial',size:8,color:text},wrapText:true,borders:{insideHorizontal:{style:'thin',color:'#E4EAF0'}}};
e2Sheet.getRange(`D20:G${19+e2Detail.length}`).format.numberFormat = '0.000';
e2Sheet.getRange(`H20:J${19+e2Detail.length}`).format.numberFormat = '#,##0';
const e2Widths = {A:24,B:24,C:40,D:13,E:13,F:13,G:15,H:13,I:12,J:10,K:13,L:12,M:42,N:16};
for (const [col,width] of Object.entries(e2Widths)) e2Sheet.getRange(`${col}1:${col}${19+e2Detail.length}`).format.columnWidth=width;
e2Sheet.getRange('A1:N1').format.rowHeight=32;
e2Sheet.getRange('A2:N2').format.rowHeight=48;
e2Sheet.getRange('A4:M4').format.rowHeight=42;
e2Sheet.getRange('A5:M7').format.rowHeight=42;
e2Sheet.getRange('A9:D9').format.rowHeight=30;
e2Sheet.getRange('A10:N16').format.rowHeight=42;
e2Sheet.getRange('A17:N17').format.rowHeight=8;
e2Sheet.getRange('A18:N19').format.rowHeight=34;
e2Sheet.getRange(`A20:N${19+e2Detail.length}`).format.rowHeight=30;
e2Sheet.freezePanes.freezeRows(4);
const e2Preview=await wb.render({sheetName:'E2 fixed corpus',range:`A1:N${19+e2Detail.length}`,scale:0.7,format:'png'});
await fs.writeFile(`${e2Folder}/E2_fixed_corpus_preview.png`,new Uint8Array(await e2Preview.arrayBuffer()));
const e2Inspection=await wb.inspect({kind:'sheet,region',sheetId:'E2 fixed corpus',range:`A1:N${19+e2Detail.length}`,maxChars:12000});
await (await SpreadsheetFile.exportXlsx(wb)).save(path);
await fs.writeFile(`${folder}/P2_cache_corpus_inspect.ndjson`,inspection.ndjson ?? JSON.stringify(inspection),'utf8');
await fs.writeFile(`${folder}/E0_E4_summary_inspect.ndjson`,summaryInspection.ndjson ?? JSON.stringify(summaryInspection),'utf8');
await fs.writeFile(`${m2Folder}/P2_M2_fixed_corpus_inspect.ndjson`,m2Inspection.ndjson ?? JSON.stringify(m2Inspection),'utf8');
await fs.writeFile(`${e2Folder}/E2_fixed_corpus_inspect.ndjson`,e2Inspection.ndjson ?? JSON.stringify(e2Inspection),'utf8');
console.log(JSON.stringify({path,stats,equivalence,e2Stats,e2Inspection:e2Inspection.ndjson}));
