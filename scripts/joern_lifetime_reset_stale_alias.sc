// Structural candidate query: owner.reset() followed by same-name `->` use.
//
// This query intentionally stays lexical within one method. It does not prove
// alias identity, ownership, path reachability, rebinding or exploitability.
// A hit is syntax evidence for review only.

import java.io.PrintWriter

val cpgPath = sys.env.getOrElse("JOERN_CPG", "")
val outPath = sys.env.getOrElse("JOERN_OUT", "")
val toolVersion = sys.env.getOrElse("JOERN_VERSION", "unknown")

if (cpgPath.isEmpty || outPath.isEmpty) {
  throw new RuntimeException("JOERN_CPG and JOERN_OUT environment variables must be set")
}

importCpg(cpgPath)

def esc(value: String): String =
  value.replace("\\", "\\\\").replace("\"", "\\\"")
    .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

def toInt(value: Any): Int = value match {
  case null => 0
  case Some(inner) => toInt(inner)
  case None => 0
  case i: java.lang.Integer => i.intValue()
  case i: Int => i
  case i: Long => i.toInt
  case _ => 0
}

val resetPattern = "([A-Za-z_][A-Za-z0-9_]*)\\.reset\\s*\\(\\s*\\)".r
val findings = scala.collection.mutable.ArrayBuffer[String]()

cpg.method.l.foreach { method =>
  method.call.name("reset").l.foreach { reset =>
    resetPattern.findFirstMatchIn(reset.code) match {
      case Some(matched) =>
        val variable = matched.group(1)
        val resetLine = toInt(reset.lineNumber)
        val staleUse = method.call.l.find { call =>
          toInt(call.lineNumber) > resetLine && call.code.contains(variable + "->")
        }
        staleUse.foreach { use =>
          val file = reset.file.name.l.headOption.getOrElse("")
          findings += (
            "    {\"rule_id\": \"oh-lifetime-reset-stale-alias\", "
              + "\"file\": \"" + esc(file) + "\", "
              + "\"line\": " + toInt(use.lineNumber) + ", "
              + "\"symbol\": \"" + esc(method.name) + "\", "
              + "\"variable\": \"" + esc(variable) + "\", "
              + "\"message\": \"same-name pointer use follows reset() in one method; alias identity and reachability are unknown\", "
              + "\"severity\": \"warning\", "
              + "\"evidence_type\": \"syntax\", "
              + "\"cwe\": [\"CWE-416\"]}"
          )
        }
      case None => ()
    }
  }
}

val writer = new PrintWriter(outPath)
try {
  writer.println("{")
  writer.println("  \"joern_version\": \"" + esc(toolVersion) + "\",")
  writer.println("  \"query\": \"oh-lifetime-reset-stale-alias\",")
  writer.println("  \"findings\": [")
  writer.println(findings.mkString(",\n"))
  writer.println("  ]")
  writer.println("}")
} finally {
  writer.close()
}

println("JOERN_FINDINGS=" + findings.size)
