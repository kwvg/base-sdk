/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Helpers for reading and resolving written type positions.
 */

import rust
private import codeql.rust.internal.typeinference.Type as T
private import codeql.rust.internal.typeinference.TypeMention

/** Gets the head identifier of `tr`, e.g. `Vec` for `Vec<u8>`. */
string typeHead(TypeRepr tr) {
  result = tr.(PathTypeRepr).getPath().getSegment().getIdentifier().getText()
}

/** Gets the type item `tr` names, resolved through the type layer. */
TypeItem namedTypeItem(TypeRepr tr) {
  result = tr.(TypeMention).getType().(T::DataType).getTypeItem()
}

/** Gets the declared type of a field of `t`, including enum variant fields. */
TypeRepr fieldTypeRepr(TypeItem t) {
  result = t.(Struct).getFieldList().(StructFieldList).getAField().getTypeRepr()
  or
  result = t.(Struct).getFieldList().(TupleFieldList).getField(_).getTypeRepr()
  or
  result = t.(Union).getStructFieldList().getAField().getTypeRepr()
  or
  exists(Variant v |
    v = t.(Enum).getVariantList().getAVariant() and
    (
      result = v.getFieldList().(StructFieldList).getAField().getTypeRepr() or
      result = v.getFieldList().(TupleFieldList).getField(_).getTypeRepr()
    )
  )
}
