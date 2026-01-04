import java

string get_caller(Callable c){
  if exists(Call d | c.getACall() = d)
  then result = c.getACall().getEnclosingCallable().getLocation().getFile() + ":" + c.getACall().getEnclosingCallable().getLocation().getStartLine()
  else result = ""
}


from Callable c
select c.getName() as function_name, c.getLocation().getFile() as file, c.getLocation().getStartLine() as start_line, file + ":" + start_line as function_id, c.getBody().getLocation().getEndLine() as end_line, get_caller(c) as caller_id