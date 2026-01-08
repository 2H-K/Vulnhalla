import csharp

/** Returns the location of the *caller* that calls method `m` */
string get_caller(Method m) {
  exists(MethodCall mc |
      mc.getTarget() = m
    and
      result = mc.getEnclosingCallable().getLocation().getFile().toString() + ":" +
               mc.getEnclosingCallable().getLocation().getStartLine().toString()
  )
}

from Method m
select
  m.getName() as function_name,
  m.getLocation().getFile() as file,
  m.getLocation().getStartLine() as start_line,
  (m.getLocation().getFile().toString() + ":" + m.getLocation().getStartLine().toString()) as function_id,
  (m.getBody().getLocation().getEndLine()) as end_line,
  get_caller(m) as caller_id
