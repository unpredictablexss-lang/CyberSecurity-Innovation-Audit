"""Pinned evidence for how a PoC target is reached, and what that leaves open.

A PoC that only shows "the code does X when called directly" leaves the
reachability obligation exactly where it was. This module records the
source-pinned relations that establish *how* the target is reached, each with
what it does and does not establish, so the remaining gap is named rather than
implied.

Every relation is verified twice: the file digest must match the pinned commit,
and the quoted line must actually appear at the recorded line number. A stale
quote or a moved file fails the run instead of quietly describing different code.
"""
from dataclasses import dataclass
import hashlib

from .sources import SourceMismatch, SourceUnavailable, read_blob


class ReachabilityQuoteMismatch(RuntimeError):
    """The recorded evidence text is not at the recorded line any more."""


@dataclass(frozen=True)
class Relation:
    kind: str
    path: str
    commit: str
    sha256: str
    line: int
    evidence: str
    establishes: str
    does_not_establish: str


@dataclass(frozen=True)
class ReachabilityEvidence:
    status: str            # "not_evidenced" | "partial" | "evidenced"
    summary: str
    relations: tuple


def verify(entry, git_dir):
    """Digest-check and line-check every recorded relation.

    Returns `None` when the manifest declares no reachability block, so a harness
    that has not done this work says so by omission rather than by an empty claim.
    """
    if not entry:
        return None
    relations = []
    for item in entry.get("relations", ()):
        blob = read_blob(git_dir, item["commit"], item["path"])
        digest = hashlib.sha256(blob).hexdigest()
        if digest != item["sha256"]:
            raise SourceMismatch(
                "digest mismatch for " + item["path"] + " at " + item["commit"]
                + ": recorded " + item["sha256"][:12] + ", read " + digest[:12])
        lines = blob.decode("utf-8", errors="replace").splitlines()
        number = int(item["line"])
        if number < 1 or number > len(lines) or item["evidence"].strip() not in lines[number - 1]:
            raise ReachabilityQuoteMismatch(
                item["path"] + ":" + str(number) + " no longer contains the recorded evidence "
                "for relation " + item["kind"])
        relations.append(Relation(
            kind=item["kind"], path=item["path"], commit=item["commit"], sha256=item["sha256"],
            line=number, evidence=item["evidence"].strip(),
            establishes=item["establishes"], does_not_establish=item["does_not_establish"]))
    return ReachabilityEvidence(status=entry["status"], summary=entry["summary"],
                                relations=tuple(relations))


def render_markdown(evidence):
    lines = ["## 可达性证据", "",
             "- 状态：**" + evidence.status + "**",
             "- " + evidence.summary, ""]
    for relation in evidence.relations:
        lines += ["### `" + relation.kind + "` — `" + relation.path + ":" + str(relation.line) + "`", "",
                  "```cpp", relation.evidence, "```", "",
                  "- 固定提交：`" + relation.commit + "`（sha256 `" + relation.sha256[:12] + "`）",
                  "- **证明了**：" + relation.establishes,
                  "- **没有证明**：" + relation.does_not_establish, ""]
    return "\n".join(lines)
