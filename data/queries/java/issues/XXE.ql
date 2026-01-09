/**
 * @name Aggressive XXE Recovery (Red Team)
 * @kind path-problem
 * @problem.severity error
 * @id java/redteam/xxe-high-recall
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

/**
 * 核心逻辑：不依赖官方脆弱的模块，直接定义红队关心的流
 */
module XXEConfig implements DataFlow::ConfigSig {
  
  predicate isSource(DataFlow::Node source) {
    // 1. 标准远程流量
    source instanceof RemoteFlowSource
    or
    // 2. 增强：捕捉任何类似从存储读取数据的行为
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("(?i)(read|get|load|input|from|fetch).*") and
      source.asExpr() = mc
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      // 只要方法名像解析，且类名相关，红队就感兴趣
      mc.getMethod().getName().regexpMatch("(?i)(parse|unmarshal|read|decode|load|fromXml).*") and
      (
        // 模糊匹配解析器类名，防止漏掉自研或第三方库
        mc.getReceiverType().(RefType).getQualifiedName().regexpMatch("(?i).*(xml|sax|dom|jaxb|stream|reader|parser|document).*")
      ) and
      sink.asExpr() = mc.getAnArgument()
    )
  }
}

module XXEFlow = TaintTracking::Global<XXEConfig>;
import XXEFlow::PathGraph

from XXEFlow::PathNode source, XXEFlow::PathNode sink
where XXEFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Possible XXE: data from $@ reaches XML parser.", source.getNode(), "this source"