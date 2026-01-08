/**
 * @name C# SQL Injection (2026 Compatible)
 * @description 检测从不可信输入到数据库查询的污点路径。
 * @kind path-problem
 * @id redteam/csharp-sql-injection-modern
 * @problem.severity error
 * @security.severity 8.8
 * @precision high
 * @tags security external/cwe/cwe-089
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
// 必须导入 PathGraph 来支持可视化路径
import MyFlow::PathGraph

/**
 * 污点跟踪配置
 */
module SqlInjectionConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    // 1. 公共方法参数（类库入口）
    exists(Parameter p, Method m |
      m = p.getCallable() and
      m.hasModifier("public") and
      p.getType().hasName("string") and
      source.asParameter() = p
    )
    or
    // 2. ASP.NET Core HttpRequest 属性 (Form, Query, Headers)
    exists(PropertyAccess pa, Type t |
      pa.getTarget().getName().regexpMatch("(?i)(Form|Query|Headers)") and
      t = pa.getTarget().getDeclaringType() and
      t.hasFullyQualifiedName("Microsoft.AspNetCore.Http", "HttpRequest") and
      source.asExpr() = pa
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // 1. ADO.NET: 针对 CommandText 属性的赋值
    exists(Assignment a, PropertyAccess pa, Type t |
      pa = a.getLValue() and
      pa.getTarget().hasName("CommandText") and
      t = pa.getTarget().getDeclaringType() and
      (
        t.hasFullyQualifiedName("System.Data.SqlClient", "SqlCommand") or
        t.hasFullyQualifiedName("Microsoft.Data.SqlClient", "SqlCommand")
      ) and
      sink.asExpr() = a.getRValue()
    )
    or
    // 2. EF Core: 常见的原生 SQL 执行方法
    exists(MethodCall mc, Type t |
      mc.getTarget().getName().regexpMatch("FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync") and
      t = mc.getTarget().getDeclaringType() and
      // EF Core 扩展方法通常定义在这些类中
      (
        t.hasFullyQualifiedName("Microsoft.EntityFrameworkCore", "RelationalQueryableExtensions") or
        t.hasFullyQualifiedName("Microsoft.EntityFrameworkCore", "RelationalDatabaseFacadeExtensions")
      ) and
      sink.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * 实例化全局污点跟踪
 */
module MyFlow = TaintTracking::Global<SqlInjectionConfig>;

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection: user input flows to database query from $@", source.getNode(), "this source"