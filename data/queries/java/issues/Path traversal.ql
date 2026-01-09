/**
 * @name RedTeam Path Traversal
 * @description 发现受污染的输入流向文件系统操作，包含更激进的 Source 和 Sink 定义。
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/redteam-path-traversal
 * @tags security
 * external/cwe/cwe-022
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
// 必须导入 PathGraph 以支持 path-problem
import RedTeamPathFlow::PathGraph

/**
 * 红队配置模块
 */
module RedTeamPathConfig implements DataFlow::ConfigSig {
  
  // 1. 定义 Source：不仅仅是 RemoteFlowSource
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    // 红队思维：系统属性和环境变量也可能被注入（例如在某些容器化环境中）
    exists(MethodCall mc |
      mc.getMethod().hasName("getProperty") and
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "System") and
      source.asExpr() = mc
    )
    or
    // 考虑从数据库读取的文件名（存储型路径遍历）
    exists(MethodCall mc |
      mc.getMethod().getName().regexpMatch("(?i)get.*") and
      mc.getMethod().getDeclaringType().getName().regexpMatch(".*(ResultSet|Mapper|Dao).*") and
      source.asExpr() = mc
    )
  }

  // 2. 定义 Sink：覆盖所有文件操作
  predicate isSink(DataFlow::Node sink) {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.io", "File") or
      cc.getConstructedType().hasQualifiedName("java.io", "FileInputStream") or
      cc.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") or
      cc.getConstructedType().hasQualifiedName("java.nio.file", "Path")
      |
      sink.asExpr() = cc.getArgument(0)
    )
    or
    // 覆盖 NIO 的 Files 工具类
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      sink.asExpr() = mc.getArgument(0)
    )
  }

  // 3. 绕过净化器（红队思维：不定义 isSanitizer）
  // 官方规则会排除掉 contains("..") 的检查，但红队倾向于保留它们以检查逻辑绕过
}

module RedTeamPathFlow = TaintTracking::Global<RedTeamPathConfig>;

from RedTeamPathFlow::PathNode source, RedTeamPathFlow::PathNode sink
where RedTeamPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential path traversal from $@.", source.getNode(), "user-provided input"