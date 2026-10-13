/**
 * @name OpenHarmony IPC structural boundary candidates
 * @description Custom experiment baseline, not a default CodeQL vulnerability query.
 * @kind problem
 * @problem.severity warning
 * @id ohscanner-research/ipc-boundary
 */
import cpp
predicate permissionIn(Function f) {
  exists(FunctionCall c | c.getEnclosingFunction()=f and
    c.getTarget().getName() in ["VerifyAccessToken","CheckPermission","VerifyPermission"])
}
from Element e, string family, string detail
where
  exists(Function f | e=f and f.getName()="OnRemoteRequest" and
    not exists(FunctionCall c | c.getEnclosingFunction()=f and c.getTarget().getName()="ReadInterfaceToken") and
    family="AUTH-01" and detail="No direct descriptor read in entry; descriptor semantics not proved")
  or
  exists(FunctionCall c | e=c and c.getEnclosingFunction().getName()="OnRemoteRequest" and
    c.getTarget().getName() in ["StartAbility","GetDisplaySnapshot","GetRemoteHapTokenInfo","DeleteRemoteHapTokenInfo"] and
    not permissionIn(c.getEnclosingFunction()) and family="AUTH-02" and detail="No direct permission call in same function")
  or
  exists(FunctionCall c | e=c and c.getTarget().getName()="VerifyAccessToken" and
    c.getAnArgument().toString().matches("%GetSelfTokenID%") and family="AUTH-03" and detail="Self identity in access check")
  or
  exists(FunctionCall c | e=c and c.getEnclosingFunction().getName()="OnRemoteRequest" and
    c.getTarget().getName() in ["WriteRemoteObject","WriteFileDescriptor"] and
    not permissionIn(c.getEnclosingFunction()) and family="CAP-01" and detail="Capability export without direct permission predicate")
select e, family+": "+detail+"; candidate only."
