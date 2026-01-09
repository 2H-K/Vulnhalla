/**
 * @name Java class/interface/enum metadata
 * @description Extract metadata about types in Java source code
 */

import java

/**
 * 获取类型名称
 */
private string getTypeName(RefType t) {
  t instanceof Class and result = t.getName()
  or
  t instanceof Interface and result = t.getName()
  or
  t instanceof EnumType and result = t.getName()
}

/**
 * 获取类型限定名
 */
private string getQualifiedName(RefType t) {
  t instanceof Class and result = t.getQualifiedName()
  or
  t instanceof Interface and result = t.getQualifiedName()
  or
  t instanceof EnumType and result = t.getQualifiedName()
}

/**
 * 获取类型标识
 */
private string getTypeKind(RefType t) {
  t instanceof Class and result = "class"
  or
  t instanceof Interface and result = "interface"
  or
  t instanceof EnumType and result = "enum"
}

from RefType t
where
  t.fromSource() and
  (t instanceof Class or t instanceof Interface or t instanceof EnumType)
select
  getTypeKind(t) as typeKind,
  getQualifiedName(t) as qualifiedName,
  getTypeName(t) as simpleName,
  t.getLocation().getFile().getAbsolutePath() as filePath,
  t.getLocation().getStartLine() as startLine,
  t.getLocation().getEndLine() as endLine,
  (t.getLocation().getFile().getAbsolutePath() + ":" +
   t.getLocation().getStartLine().toString()) as id
