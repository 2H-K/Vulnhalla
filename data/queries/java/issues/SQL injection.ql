/**
 * @name SQL injection
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.FlowSources
// 1. 确保导入此路径
import semmle.code.java.security.SqlInjectionQuery

// 2. 关键点：从 SqlInjectionQuery 模块中显式导入 PathGraph
import SqlInjectionQuery::SqlInjection::PathGraph

// 3. 使用完整的限定名来定义 source 和 sink
from SqlInjectionQuery::SqlInjection::PathNode source, SqlInjectionQuery::SqlInjection::PathNode sink
where SqlInjectionQuery::SqlInjection::flowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on a $@.", source.getNode(), "user-provided value"