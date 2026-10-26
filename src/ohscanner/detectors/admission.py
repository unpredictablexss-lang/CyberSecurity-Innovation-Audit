"""Owner-reviewed pending deliveries; no factories or execution fallback.

These records explain missing evidence. They are not approved detectors, do
not expand default selection, and cannot authorize partial-AST execution.
"""
from copy import deepcopy

_PENDING = (
    {
        "id": "ohscanner.data.sensitive_exposure", "lane": "D",
        "kind": "admission_pending", "version": "0.3.0",
        "upstream_head": "c250bd57fa6670c21afa82a2e4684c0bc4c21298",
        "supported_languages": ["c", "cpp"], "required_facts": ["ast"],
        "admission_status": "blocked", "execution_enabled": False,
        "evidence_level": "candidate/unknown; research only",
        "summary": "敏感数据到日志的局部传播研究；历史目标尚未满足公共扫描准入",
        "accepted_evidence": [
            "D3 的固定源码、密钥字段和旧 SoftBusLog 格式/公开输出语义可独立复核",
            "旧 SoftBusLog 与现代 HiLog 的默认隐私语义必须分开建模",
            "公共 Runner 与私有 partial 探针结果分开记录",
            "主线预留显式模型数据摘要冻结能力；D 模型仍未交付到 main",
        ],
        "missing_evidence": [
            "真实候选所在文件仍为 partial；公共 Runner 不准入，私有探针 1→0 不能替代系统扫描验收",
            "需生产适配器显式选择精确版本模型、绑定依赖和 blob；禁止回退到默认模型或扩大到当前版本",
            "需真实同名替身、受保护/脱敏路径的反例和独立留出集；不得把跨版本未建模路径当负例",
            "未来准入时须交付精确模型数据，并显式纳入任务冻结身份；当前 main 不含 D 模型 JSON",
        ],
        "confirmation_evidence": [
            "产品构建/日志开关、格式化成功与长度、日志读取权限、实际包含密钥的请求、入口和安全影响仍 unknown；未执行运行时验证",
        ],
    },
)


def pending_admissions():
    """Return detached descriptive metadata. Never instantiate pending code."""
    return deepcopy(list(_PENDING))


def pending_admission(detector_id):
    return next((row for row in pending_admissions() if row["id"] == detector_id), None)
