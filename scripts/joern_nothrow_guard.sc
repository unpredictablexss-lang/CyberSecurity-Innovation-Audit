// Joern CPG query: "nothrow allocation without a null guard".
//
// Emits findings in the JSON convention consumed by src/providers/joern.py
// (see that adapter for the schema). Run it as:
//
//   JOERN_CPG=cpg.bin JOERN_OUT=findings.json JOERN_VERSION=4.0.649 \
//       joern --script scripts/joern_nothrow_guard.sc
//
// What the query actually tests: for every method that contains a
// `new (std::nothrow)` allocation, it checks whether the method body contains
// an equality/inequality comparison (`==` / `!=`). A method with an allocation
// and no comparison is reported as a candidate missing null guard (CWE-476).
//
// Honest limitations (do not read more into the output than this):
//   - It is a *structural* guard heuristic, not a proof of a null dereference.
//   - The comparison count is method-wide, so an unrelated comparison can mask
//     a real missing guard (false negative) and a guard that lives in the
//     caller (e.g. a safe wrapper) is not seen (false positive).
//   - A hit is a candidate for review, never a vulnerability.

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

val findings = scala.collection.mutable.ArrayBuffer[String]()

cpg.method.l.foreach { method =>
  val nothrowAllocations = method.call
    .name("<operator>.new")
    .l
    .filter(call => call.code.contains("nothrow"))

  if (nothrowAllocations.nonEmpty) {
    val comparisons = method.call
      .nameExact("<operator>.equals", "<operator>.notEquals")
      .size

    if (comparisons == 0) {
      nothrowAllocations.foreach { call =>
        val file = call.file.name.l.headOption.getOrElse("")
        val line = toInt(call.lineNumber)
        findings += (
          "    {\"rule_id\": \"oh-nothrow-alloc-unchecked-deref\", "
            + "\"file\": \"" + esc(file) + "\", "
            + "\"line\": " + line + ", "
            + "\"symbol\": \"" + esc(method.name) + "\", "
            + "\"message\": \"nothrow allocation in method '" + esc(method.name)
            + "' has no equality comparison in the method body (candidate missing null guard)\", "
            + "\"severity\": \"warning\", "
            + "\"evidence_type\": \"control_flow\", "
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
