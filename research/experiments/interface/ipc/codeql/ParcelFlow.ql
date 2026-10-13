/**
 * @name IPC Parcel scalar to copy length
 * @description Custom taint baseline without range sanitizers; candidate only.
 * @kind path-problem
 * @problem.severity warning
 * @id ohscanner-research/ipc-parcel-flow
 */
import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
module Config implements DataFlow::ConfigSig {
 predicate isSource(DataFlow::Node n) {
  exists(FunctionCall c | n.asExpr()=c and c.getTarget().getName() in ["ReadInt32","ReadUint32"])
 }
 predicate isSink(DataFlow::Node n) {
  exists(FunctionCall c | c.getTarget().getName()="memcpy" and n.asExpr()=c.getArgument(2))
 }
}
module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph
from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source,sink)
select sink.getNode(),source,sink,"DATA-01: Parcel-derived length reaches copy; range not modeled."
