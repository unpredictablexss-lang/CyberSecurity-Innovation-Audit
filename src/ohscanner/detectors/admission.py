"""Owner-reviewed pending deliveries; no factories or execution fallback.

These records explain missing evidence. They are not approved detectors, do
not expand default selection, and cannot authorize partial-AST execution.
"""
from copy import deepcopy

_PENDING = (
    {
        "id": "ohscanner.ark.runtime.type_safety", "lane": "C",
        "kind": "admission_pending", "version": "0.1.1",
        "upstream_head": "33242fbd2b58e2f510fa74f1521e247fea08db27",
        "supported_languages": ["cpp"], "required_facts": ["ast"],
        "admission_status": "blocked", "execution_enabled": False,
        "evidence_level": "candidate/unknown; research only",
        "summary": "Ark TypedArray 类型来源研究；真实目标尚未满足公共扫描准入",
        "accepted_evidence": [
            "固定 Git commit/tree/blob/SHA-256 可独立复核",
            "局部研究历史差异可重放；控制样例通过不等于产品漏洞确认",
            "隔离审查分支已修复嵌套调用和同名谓词错误抑制并保留反例；本次 main 不交付 C 实现",
        ],
        "missing_evidence": [
            "真实历史目标文件仍为 partial（creator 文件已能完整解析）；需完整 AST，或单独评审的局部准入契约及依赖不受解析错误污染的证据",
            "需将仓库/版本/目标和 creator 依赖绑定落实到生产适配器；当前原始适配器可套用显式模型假设到其他源码",
            "需复核宏、类型、继承、方法和构建配置；局部同名排除不等于编译器符号解析",
            "需独立留出集验证适用范围与误报边界；现有自写控制不构成精确率/召回率",
        ],
        "confirmation_evidence": [
            "产品入口和攻击者控制、生成路径可行性、真实 species 行为及安全影响仍 unknown；未执行运行时验证",
        ],
    },
)


def pending_admissions():
    """Return detached descriptive metadata. Never instantiate pending code."""
    return deepcopy(list(_PENDING))


def pending_admission(detector_id):
    return next((row for row in pending_admissions() if row["id"] == detector_id), None)
