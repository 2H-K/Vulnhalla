/**
 * @name Unsafe eval
 * @description Detects use of eval() or similar functions
 * @kind problem
 * @problem.severity error
 * @id js/unsafe-eval
 * @tags security
 *       external/cwe/cwe-095
 */

import javascript

from CallExpr call
where call.toString().matches("%eval%")
select call, "Use of eval or similar dynamic code execution function"
