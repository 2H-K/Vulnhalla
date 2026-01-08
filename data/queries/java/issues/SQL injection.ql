/**
 * @name SQL injection
 * @kind path-problem
 */

import java
import semmle.code.java.dataflow.FlowSources
// 导入标准 SQL 注入查询库
import semmle.code.java.security.SqlInjectionQuery

// 使用标准库定义的 QueryInjectionFlow 模块
import QueryInjectionFlow::PathGraph

from QueryInjectionFlow::PathNode source, QueryInjectionFlow::PathNode sink
where QueryInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on a $@.", source.getNode(), "user-provided value"