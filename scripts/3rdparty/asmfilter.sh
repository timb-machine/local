#!/bin/bash

REG="%\([a-z]*\)"
HEXCONST="\(0x[0-9a-f]*\)"
LABEL="\([_\.a-z][_\.a-z0-9]*\)"
TAB="&\t\t\t"

sed "s/mov    $HEXCONST($REG),$REG/$TAB \3 = M(\2 + \1);/" \
| sed "s/mov    $HEXCONST($LABEL),$REG/$TAB \3 = M(\2 + \1);/" \
| sed "s/mov    ($REG),$REG/$TAB \2 = M(\1);/" \
| sed "s/mov    $REG,$HEXCONST($REG)/$TAB M(\3 + \2) = \1;/" \
| sed "s/mov    $REG,($REG)/$TAB M(\2) = \1;/" \
| sed "s/mov    \$$HEXCONST,$REG/$TAB \2 = \1;/" \
| sed "s/mov    $HEXCONST($REG,$REG,\([0-9]*\)),$REG/$TAB \5 = M(\1 + \2 + \3 * \4);/" \
| sed "s/mov    ($REG,$REG,\([0-9]*\)),$REG/$TAB \4 = M(\1 + \2 * \3);/" \
| sed "s/mov    $REG,$HEXCONST($REG,$REG,\([0-9]*\))/$TAB M(\2 + \3 + \4 * \5) = \1;/" \
| sed "s/mov    $REG,($REG,$REG,\([0-9]*\))/$TAB M(\2 + \3 * \4) = \1;/" \
| sed "s/movl   \$$HEXCONST,$HEXCONST($REG)/$TAB M32(\2 + \3) = \1;/" \
| sed "s/movl   \$$LABEL,$HEXCONST($REG)/$TAB M32(\2 + \3) = \1;/" \
| sed "s/movl   \$$LABEL,($REG)/$TAB M32(\2) = \1;/" \
| sed "s/movl   \$$HEXCONST,($REG)/$TAB M32(\2) = \1;/" \
| sed "s/addl   \$$HEXCONST,$HEXCONST($REG)/$TAB M32(\2 + \3) += \1;/" \
| sed "s/subl   \$$HEXCONST,$HEXCONST($REG)/$TAB M32(\2 + \3) -= \1;/" \
| sed "s/incl   $HEXCONST($REG)/$TAB M32(\1 + \2) += 1;/" \
| sed "s/incl   $HEXCONST($LABEL)/$TAB M32(\1 + \2) += 1;/" \
| sed "s/decl   $HEXCONST($REG)/$TAB M32(\1 + \2) -= 1;/" \
| sed "s/decl   $HEXCONST($LABEL)/$TAB M32(\1 + \2) -= 1;/" \
| sed "s/lea    $HEXCONST($REG),$REG/$TAB \3 = \2 + \1;/" \
| sed "s/and    \$$HEXCONST,$REG/$TAB \2 \&= \1;/" \
| sed "s/or     \$$HEXCONST,$REG/$TAB \2 |= \1;/" \
| sed "s/or     $REG,$REG/$TAB \2 |= \1;/" \
| sed "s/and    $REG,$REG/$TAB \2 \&= \1;/" \
| sed "s/mov    $REG,$REG/$TAB \2 = \1;/" \
| sed "s/shl    \$$HEXCONST,$REG/$TAB \2 <<= \1;/" \
| sed "s/shr    \$$HEXCONST,$REG/$TAB \2 >>= \1;/" \
| sed "s/movzwl $REG,$REG/$TAB \2 = ZEXT(\1, 16, 32);/" \
| sed "s/movzbl $REG,$REG/$TAB \2 = ZEXT(\1, 8, 32);/" \
| sed "s/movzwl $HEXCONST($REG),$REG/$TAB \3 = ZEXT(M16(\2 + \1), 16, 32);/" \
| sed "s/movzbw $HEXCONST($REG),$REG/$TAB \3 = ZEXT(M8(\2 + \1), 8, 16);/" \
| sed "s/movzbl $HEXCONST($REG),$REG/$TAB \3 = ZEXT(M8(\2 + \1), 8, 32);/" \
| sed "s/lea    $HEXCONST($REG,$REG,\([0-9]*\)),$REG/$TAB \5 = \1 + \2 + \3 * \4;/" \
| sed "s/lea    ($REG,$REG,\([0-9]*\)),$REG/$TAB \4 = \1 + \2 * \3;/" \
| sed "s/add    $HEXCONST($REG),$REG/$TAB \3 += M(\1 + \2);/" \
| sed "s/add    ($REG),$REG/$TAB \2 += M(\1);/" \
| sed "s/add    \$$HEXCONST,$REG/$TAB \2 += \1;/" \
| sed "s/add    $REG,$REG/$TAB \2 \+= \1;/" \
| sed "s/sub    $HEXCONST($REG),$REG/$TAB \3 -= M(\1 + \2);/" \
| sed "s/sub    ($REG),$REG/$TAB \2 -= M(\1);/" \
| sed "s/sub    \$$HEXCONST,$REG/$TAB \2 -= \1;/" \
| sed "s/sub    $REG,$REG/$TAB \2 \-= \1;/" \
| sed "s/dec    $REG/$TAB \1--;/" \
| sed "s/inc    $REG/$TAB \1++;/" \
| sed "s/xor    $REG,$REG/$TAB \2 ^= \1;/" \
