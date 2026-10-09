// Joern CPG query: "nothrow allocation without a null guard".
//
// Emits findings in the JSON convention consumed by src/providers/joern.py
// (see that adapter for the schema). Run it as:
//
//   JOERN_CPG=cpg.bin JOERN_OUT=findings.json JOERN_VERSION=4.0.649 \
//       joern --script scripts/joern_nothrow_guard.sc
//
// What the query actually tests, per `[:ID] = new (std::nothrow) T(...)`
// assignment inside a method:
//   1. the allocated variable must actually be dereferenced in that method
//      (`[:ID]->...`), and
//   2. the method must not contain a null-ish comparison of *that same
//      variable* (`[:ID] == nullptr`, `NULL == [:ID]`, ...).
// Only assignments that dereference without guarding the pointer itself are
// reported (CWE-476).
//
// Honest limitations (do not read more into the output than this):
//   - It is a *structural* guard heuristic, not a proof of a null dereference.
//   - It looks for guards in the same method only: a wrapper that allocates and
//     returns the pointer, with the caller doing the null check, is not
//     flagged (that is the intended fix of the earlier GetClientProxy false
//     positive), but neither is a guard that lives in the caller.
//   - A guard written in a form other than an equality comparison of the
//     variable (e.g. a custom `is_valid()` helper) is not recognised.
//   - A hit is a candidate for review, never a vulnerability.
//   - A comparison anywhere in the method suppresses a candidate, even if it
//     occurs after the dereference or does not guard it. Identifier substring
//     matching can also confuse different variables. No dominance is checked.

import java.io.PrintWriter

val cpgPath = sys.env.getOrElse("JOERN_CPG", "")
val outPath = sys.env.getOrElse("JOERN_OUT", "")
val toolVersion = sys.env.getOrElse("JOERN_VERSION", "unknown")

if (cpgPath.isEmpty || outPath.isEmpty) {
  throw new RuntimeException("JOERN_CPG and JOERN_OUT environment variables must be set")
}

importCpg(cpgPath)

def esc(value: String): String =
  value
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n")
    .replace("\r", "\\r")
    .replace("\t", "\\t")

// Line metadata is exposed as a nullable Integer on some Joern versions and as
// an Option on others; normalise both to a plain Int (0 = unknown).
def toInt(value: Any): Int = value match {
  case null                 => 0
  case Some(inner)          => toInt(inner)
  case None                 => 0
  case i: java.lang.Integer => i.intValue()
  case i: Int               => i
  case i: Long              => i.toInt
  case _                    => 0
}

// "sptr<BusCenterClientProxy> clientProxy" -> "clientProxy"
def variableName(lhsCode: String): String = {
  val cleaned = lhsCode.replaceAll("[^A-Za-z0-9_\\s]", " ").trim
  cleaned.split("\\s+").lastOption.getOrElse("")
}

def isNullLiteral(code: String): Boolean = {
  val value = code.trim
  value == "nullptr" || value == "NULL" || value == "0" || value.endsWith("nullptr")
}

// True when the method compares the *allocated variable itself* against a
// null-ish literal. Comparisons of unrelated expressions (e.g. `strcmp(...) != 0`)
// intentionally do not count.
def isNullGuarded(method: io.shiftleft.codepropertygraph.generated.nodes.Method,
                  variable: String): Boolean = {
  method.call
    .nameExact("<operator>.equals", "<operator>.notEquals")
    .l
    .exists { comparison =>
      val args = comparison.argument.l
      val mentionsVariable = args.exists(arg => arg.code.contains(variable))
      val comparesToNull = args.exists(arg => isNullLiteral(arg.code))
      mentionsVariable && comparesToNull
    }
}

val findings = scala.collection.mutable.ArrayBuffer[String]()

cpg.method.l.foreach { method =>
  val nothrowAllocations = method.call
    .name("<operator>.new")
    .l
    .filter(call => call.code.contains("nothrow"))

  nothrowAllocations.foreach { allocation =>
    val lhsCode = allocation.inAssignment.l.headOption
      .map(assignment => assignment.argument(1).code)
      .getOrElse("")
    val variable = variableName(lhsCode)

    if (variable.nonEmpty) {
      val dereferenced = method.call.l.exists(call => call.code.contains(variable + "->"))
      val guarded = isNullGuarded(method, variable)

      if (dereferenced && !guarded) {
        val file = allocation.file.name.l.headOption.getOrElse("")
        val line = toInt(allocation.lineNumber)
        findings += (
          "    {\"rule_id\": \"oh-nothrow-alloc-unchecked-deref\", "
            + "\"file\": \"" + esc(file) + "\", "
            + "\"line\": " + line + ", "
            + "\"symbol\": \"" + esc(method.name) + "\", "
            + "\"variable\": \"" + esc(variable) + "\", "
            + "\"message\": \"nothrow allocation '" + esc(variable) + "' in method '"
            + esc(method.name) + "' is dereferenced without a null check on that variable\", "
            + "\"severity\": \"warning\", "
            + "\"evidence_type\": \"syntax\", "
            + "\"cwe\": [\"CWE-476\"]}"
        )
      }
    }
  }
}

val writer = new PrintWriter(outPath)
try {
  writer.println("{")
  writer.println("  \"joern_version\": \"" + esc(toolVersion) + "\",")
  writer.println("  \"query\": \"oh-nothrow-alloc-unchecked-deref\",")
  writer.println("  \"findings\": [")
  writer.println(findings.mkString(",\n"))
  writer.println("  ]")
  writer.println("}")
} finally {
  writer.close()
}

println("JOERN_FINDINGS=" + findings.size)
