import javascript

from Function f
select f.getName() as function_name, f.getLocation().getFile() as file, f.getLocation().getStartLine() as start_line, file + ":" + start_line as function_id, f.getBody().getLocation().getEndLine() as end_line, "" as caller_id
