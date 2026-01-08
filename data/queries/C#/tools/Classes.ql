import csharp

private string getType(NamedElement e) {
  e instanceof Class and result = "Class"
  or
  e instanceof Interface and result = "Interface"
  or
  e instanceof Struct and result = "Struct"
  or
  e instanceof Enum and result = "Enum"
  or
  e instanceof Namespace and result = "Namespace"
}

private string getSimpleName(NamedElement e) {
  e instanceof Namespace and result = ""
  or
  result = e.getName()
}

from NamedElement e
where e instanceof Class or e instanceof Interface or e instanceof Struct or e instanceof Enum or e instanceof Namespace
select getType(e) as type, e.getName() as name, e.getLocation().getFile() as file, e.getLocation().getStartLine() as start_line, e.getLocation().getEndLine() as end_line, getSimpleName(e) as simple_name
