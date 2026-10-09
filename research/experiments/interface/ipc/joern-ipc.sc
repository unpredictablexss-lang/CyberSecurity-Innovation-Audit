import io.shiftleft.semanticcpg.language.*
import java.nio.file.{Files,Paths}
@main def exec(cpgFile: String, outFile: String) = {
  importCpg(cpgFile)
  val rows = cpg.method.filter(m => m.name == "OnRemoteRequest" || (m.name.endsWith("Inner") && m.parameter.code.exists(_.contains("MessageParcel")))).l.flatMap { m =>
    val calls = m.ast.isCall.l
    val descriptor = calls.exists(_.name == "ReadInterfaceToken")
    val permissions = calls.exists(c => Set("VerifyAccessToken","CheckPermission","VerifyPermission").contains(c.name))
    val sensitive = Set("StartAbility","GetDisplaySnapshot","GetRemoteHapTokenInfo","DeleteRemoteHapTokenInfo","GetReqPermissions","SetMutePolicy")
    val output = scala.collection.mutable.ListBuffer[ujson.Value]()
    def emit(family:String,rule:String,line:Int) = output += ujson.Obj("family"->family,"rule"->rule,"file"->m.filename,"symbol"->m.fullName,"line"->line)
    if(m.name=="OnRemoteRequest" && !descriptor) emit("AUTH-01","joern-descriptor-existence",m.lineNumber.getOrElse(1))
    calls.filter(c => sensitive.contains(c.name) && !permissions).foreach(c => emit("AUTH-02","joern-permission-existence",c.lineNumber.getOrElse(1)))
    calls.filter(c => c.name=="VerifyAccessToken" && c.argument.code.exists(x => x.contains("GetSelfTokenID") || x.contains("getuid("))).foreach(c => emit("AUTH-03","joern-self-identity",c.lineNumber.getOrElse(1)))
    calls.filter(c => Set("WriteRemoteObject","WriteFileDescriptor").contains(c.name) && !permissions).foreach(c => emit("CAP-01","joern-capability-existence",c.lineNumber.getOrElse(1)))
    output.toList
  }
  Files.writeString(Paths.get(outFile),ujson.write(ujson.Arr.from(rows),indent=2))
  Files.writeString(Paths.get(outFile+".methods.json"),ujson.write(ujson.Arr.from(cpg.method.filterNot(_.isExternal).l.map(m => ujson.Obj("file"->m.filename,"name"->m.name,"line"->m.lineNumber.getOrElse(0),"end"->m.lineNumberEnd.getOrElse(0)))),indent=2))
}
