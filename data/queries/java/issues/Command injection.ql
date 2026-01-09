/**
 * @name Java Command Injection (Red Team Generic)
 * @kind path-problem
 * @severity error
 * @id java/redteam/universal-cmd-injection
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module RedTeamConfig implements DataFlow::ConfigSig {
  
  // Source: 红队思维——不仅是远程流量，还要包含从数据库、文件、属性中读取的变量
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    exists(Call c |
      c.getCallee().getName().regexpMatch("(?i).*(get|read).*") and
      c.getCallee().getDeclaringType().getName().regexpMatch(".*(Prop|File|DB|Row|Record|Scanner).*") and
      source.asExpr() = c
    )
  }

  // Sink: 覆盖 Runtime.exec, ProcessBuilder 以及常见反射调用
  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      (
        // 匹配 Runtime.exec
        c.getCallee().hasName("exec") and 
        c.getCallee().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
      ) or (
        // 匹配 ProcessBuilder 的构造函数 (ConstructorCall 是 Call 的子类)
        c.getCallee().hasName("<init>") and
        c.getCallee().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
      ) or (
        // 红队视角：如果反射参数受控，也是高危
        c.getCallee().hasName("invoke") and
        c.getCallee().getDeclaringType().hasQualifiedName("java.lang.reflect", "Method")
      ) |
      sink.asExpr() = c.getArgument(_)
    )
  }
}

module MyFlow = TaintTracking::Global<RedTeamConfig>;
import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential Command Injection (Red Team Found): tainted data flows to command execution."