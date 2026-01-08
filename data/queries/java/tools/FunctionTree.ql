/**
 * @name Java Function Tree Metadata
 * @description 提取 Java 函数的元数据及其调用者信息。
 */

import java

/**
 * 获取调用了 c 的调用者的位置标识。
 */
string get_callers(Callable c) {
  if exists(Call call | call.getCallee() = c) // 注意：在某些版本中使用 getCallee() 或 getTarget()
  then result = concat(Call call | call.getCallee() = c | 
    call.getEnclosingCallable().getLocation().getFile().getBaseName() + ":" + 
    call.getEnclosingCallable().getLocation().getStartLine().toString(),
    "|" 
  )
  else result = "NONE"
}



from Callable c
where 
  c.fromSource() 
select 
  c.getQualifiedName() as function_name,
  c.getLocation().getFile().getAbsolutePath() as file_path,
  c.getLocation().getStartLine() as start_line,
  c.getBody().getLocation().getEndLine() as end_line,
  c.getLocation().getFile().getAbsolutePath() + ":" + c.getLocation().getStartLine().toString() as function_id,
  get_callers(c) as caller_ids