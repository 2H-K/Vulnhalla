/**
 * @name Professional Command Injection Detection
 * @description 检测从外部不可信来源到系统命令执行函数的完整路径。
 * @kind path-problem
 * @problem.severity error
 * @id js/redteam-command-injection
 * @tags security
 * external/cwe/cwe-078
 */

import javascript
import semmle.javascript.security.dataflow.CommandInjectionCustomizations
import semmle.javascript.dataflow.TaintTracking

/**
 * 定义配置模块 (最新版语义)
 */
module CommandInjectionConfig implements DataFlow::ConfigSig {
  
  // 1. 定义源：涵盖所有远程流量输入
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  // 2. 定义汇聚点：使用官方建模的系统命令执行节点
  predicate isSink(DataFlow::Node sink) {
    sink instanceof SystemCommandExecution
  }

  /**
   * 3. 修复 RegExpTest 报错
   * 在最新的 API 中，应该使用 RegExpTerm 配合其相关的 DataFlow 节点
   * 或者直接通过逻辑谓词匹配 .test() 或 .match() 调用
   */
  predicate isBarrier(DataFlow::Node node) {
    exists(MethodCallExpr mce |
      (mce.getMethodName() = "test" or mce.getMethodName() = "match") and
      mce.getAnArgument() = node.asExpr()
    )
  }
}

// 4. 实例化 TaintTracking 并生成路径图
module Taint = TaintTracking::Global<CommandInjectionConfig>;
import Taint::PathGraph

from Taint::PathNode source, Taint::PathNode sink
where Taint::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential Command Injection from $@.", source.getNode(), "user input"