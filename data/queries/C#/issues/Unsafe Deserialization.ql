/**
 * @name RedTeam C# Unsafe Deserialization
 * @description 使用红队思维追踪不可信输入到危险的反序列化 Sink。
 * @kind path-problem
 * @id custom/csharp/unsafe-deserialization-redteam
 * @problem.severity error
 * @security.severity 9.8
 * @tags security external/cwe/cwe-502
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
// 引用包含 RemoteFlowSource 的正确路径
import semmle.code.csharp.dataflow.flowsources.Remote

module UnsafeDeserConfig implements DataFlow::ConfigSig {
  
  /**
   * Source: 识别远程流和公共接口
   */
  predicate isSource(DataFlow::Node source) {
    // 1. 远程输入源（如 HttpRequest）
    source instanceof RemoteFlowSource
    or
    // 2. 识别公共类中的公共方法参数
    exists(Parameter p, Method m |
      p.getCallable() = m and
      m.hasModifier("public") and // 现在 m 是 Method，拥有 hasModifier
      m.getDeclaringType().hasModifier("public") and
      source.asParameter() = p
    )
  }

  /**
   * Sink: 覆盖危险的反序列化调用
   */
  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      (
        mc.getTarget().getName().regexpMatch("(?i)Deserialize.*|LoadXml|Parse.*") 
      )
      and sink.asExpr() = mc.getArgument(_)
    )
    or
    // 针对特定高危类型的实例化
    exists(ObjectCreation oc |
      oc.getType().getName().regexpMatch("(?i)BinaryFormatter|NetDataContractSerializer|JavaScriptSerializer")
      and sink.asExpr() = oc.getArgument(_)
    )
  }
}

module Flow = TaintTracking::Global<UnsafeDeserConfig>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential Deserialization Vulnerability: Data from $@ flows to unsafe API.", source.getNode(), "untrusted source"