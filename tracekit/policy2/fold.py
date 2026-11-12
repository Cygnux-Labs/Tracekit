"""#683: the value fold — two values a live rule reads alike are one reading of the line.

A rule is a regular expression, and a regular expression tells values apart only by the character classes its pattern
holds: `.`, a `\\w` or a set, and each literal character as a class of its own. So two values of the same length that
fall in the same class at every position find the same matches, hold the same literals and require the same things —
reading one of them stands for both, and a loop over a thousand names costs one reading of its body instead of a
thousand.

That claim is only as good as the classes, so every way a reader can tell two characters apart has to be in them:

- a category (`\\d`, `\\w`, `\\s`, `\\b`) and a negated set (`[^x]`) tell characters apart as surely as a listed
  character does; read as "matches everything" they tell nothing apart, which folds two values a rule does read
  differently (#729 class 4).
- a subject read casefolded (a path, a program name) is told apart by its folded letters, so each character is keyed by
  its own class *and* by the class of its folded form: `J` and `Z` fold to `j` and `z`, which a rule naming
  `authorized_keys` does tell apart (#729 class 3).
- the shell parser has its own separators, and `.` and `/` among them: `/etc/q/../shadow` is `/etc/shadow`, so a value
  holding `..` is not the text it looks like (#729 class 4).

A character this walk has no reading for makes the pattern unreadable, and an unreadable pattern makes the fold refuse
rather than guess: `key` then answers None, and a reading that cannot fold reads every value.

`char_sets` reads a pattern into the character sets it holds, `Partition` builds the classes all of a policy's shell
rules make of one alphabet, and `key` is what two readings share under a mask of the rules alive in one command.
`partition` is the same fold for a single pattern, which is what `tests/test_policy2.py` states it by.

Nothing here outlives the decision that asked: a `Partition` is built from a policy and holds no value a command
gave it, and a `Lazy` key is built inside one decision and dropped with it.
"""

from ..policy import _sre_c, _sre_p

# the characters the shell parser itself reads specially: the fold keeps those apart whatever the rules say, because
# `a;b` and `aXb` are not one line however alike the rules read them. `.` is the source builtin, and `.` and `/`
# separate the components of a path, so `/a/./b` and `/a/b` are one file written two ways (#729 class 4).
PARSER_CHARS = frozenset(" \t\n'\"`\\$*?[]{}~=<>|&;()#!./")

# the characters each category matches, as a reader of ASCII sees them: a category tells its own characters from the
# rest, and that distinction is what a set records here. A subject holding anything outside ASCII is not folded at all,
# so the Unicode categories and their ASCII forms come to the same thing.
_ASCII = frozenset(map(chr, range(128)))
_DIGITS = frozenset("0123456789")
_SPACES = frozenset(" \t\n\r\f\v")
_WORDS = frozenset(c for c in _ASCII if c.isalnum() or c == "_")
_NEWLINE = frozenset("\n")

_CATEGORY_NAMES = {name: getattr(_sre_c, name) for name in dir(_sre_c) if name.startswith("CATEGORY_")}
_CATEGORIES = {"DIGIT": _DIGITS, "NOT_DIGIT": _ASCII - _DIGITS, "SPACE": _SPACES, "NOT_SPACE": _ASCII - _SPACES,
               "WORD": _WORDS, "NOT_WORD": _ASCII - _WORDS, "LINEBREAK": _NEWLINE, "NOT_LINEBREAK": _ASCII - _NEWLINE}

# a boundary is a word character on one side and not on the other, so it tells those two apart
_BOUNDARIES = {getattr(_sre_c, name) for name in dir(_sre_c)
               if name in ("AT_BOUNDARY", "AT_NON_BOUNDARY", "AT_LOC_BOUNDARY", "AT_LOC_NON_BOUNDARY",
                           "AT_UNI_BOUNDARY", "AT_UNI_NON_BOUNDARY")}


def _category(av):
    """The ASCII characters a category matches, or None when this walk has no reading for it."""
    name = next((n for n, v in _CATEGORY_NAMES.items() if v == av), None)
    if name is None:
        return None
    name = name[len("CATEGORY_"):]
    for prefix in ("UNI_", "LOC_"):   # (`\d` under re.UNICODE is the same set over ASCII)
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return _CATEGORIES.get(name)


def char_sets(pattern):
    """The character sets a checked pattern holds, in the order the walk meets them, each a set whose members that
    construct tells apart from the rest. Two characters no set holds exactly one of are characters the pattern cannot
    tell apart anywhere in a subject — which is the partition RE2 builds its byte classes from: two values alike in it
    find the same matches, the same literals (a literal's own characters are singleton sets here) and the same
    requirements. None when the pattern holds something this walk cannot read, which makes a fold on it unsound."""
    out, stack = [], list(_sre_p.parse(pattern))
    while stack:
        op, av = stack.pop()
        if op == _sre_c.LITERAL:
            out.append(frozenset(chr(av)))
        elif op == _sre_c.NOT_LITERAL:
            out.append(frozenset(chr(av)))   # `[^x]`: x is told from everything that set does match
        elif op == _sre_c.CATEGORY:
            got = _category(av)
            if got is None:
                return None
            out.append(got)
        elif op == _sre_c.IN:
            got, wide, negated = set(), [], False
            for iop, iav in av:
                if iop == _sre_c.LITERAL:
                    got.add(chr(iav))
                elif iop == _sre_c.RANGE:
                    got |= {chr(c) for c in range(iav[0], min(iav[1], 127) + 1)}
                elif iop == _sre_c.CATEGORY:
                    cat = _category(iav)
                    if cat is None:
                        return None
                    wide.append(cat)
                elif iop == _sre_c.NEGATE:
                    negated = True
                else:   # a big charset, anything else this walk has no reading for
                    return None
            if got:
                out.append(frozenset(got))
            out.extend(wide)   # negated or not: what it lists (or refuses) is what it tells from the rest
        elif op == _sre_c.ANY:
            out.append(_ASCII - _NEWLINE)   # `.` tells a newline from what it does match
        elif op == _sre_c.AT:
            if av in _BOUNDARIES:
                out.append(_WORDS)
        elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
            stack.extend(av[2])
        elif op == _sre_c.SUBPATTERN:
            stack.extend(av[-1])
        elif op == _sre_c.BRANCH:
            for branch in av[1]:
                stack.extend(branch)
        else:   # a class with no reading here, a group reference, anything this walk cannot follow
            return None
    return out


class Partition:
    """The character classes the patterns given tell apart, for folding a line's values (#683): two values of one
    length that every live pattern reads alike give the same matches, so one reading of the body stands for both.
    Built once per policy, from the policy alone; `mask` selects the classes of the patterns alive in one command,
    since a pattern whose literals no part of the line holds cannot fire there and must not narrow the fold."""

    def __init__(self, patterns, parser=True):
        self._bits, self._masks, self._parser = {}, {}, 0
        if parser:
            for c in PARSER_CHARS:
                self._parser |= self._bit(frozenset(c))
        unreadable = False
        for p in dict.fromkeys(patterns):
            sets = char_sets(p)
            if sets is None:
                unreadable = True
                break
            m = 0
            for s in sets:
                if s is not None:
                    m |= self._bit(s)
            self._masks[p] = m
        self._all = self._parser
        for m in self._masks.values():
            self._all |= m
        # what each character is under every pattern given: one row per character, built once
        self._chars = None if unreadable else {
            c: sum(b for s, b in self._bits.items() if c in s) for c in map(chr, range(128))}

    def _bit(self, s):
        if s not in self._bits:
            self._bits[s] = 1 << len(self._bits)
        return self._bits[s]

    def mask(self, patterns=None):
        """The classes of those patterns, and the parser's own: only characters one of them separates are told apart.
        None when this partition holds a pattern it cannot read, which makes a fold on it unsound."""
        if self._chars is None:
            return None
        if patterns is None:
            return self._all
        out = self._parser
        for p in patterns:
            out |= self._masks.get(p, 0)
        return out

    def key(self, texts, mask=None):
        """What two readings share when no live pattern can tell them apart: each text's length and, for each
        character, its classes under `mask` as written and under `mask` as a reader that folds case sees it. A string
        is one text and keys to its own pair; a sequence keys to their tuple. The mask is part of the key, because two
        values folded under different masks were read under different rules. None: not foldable (an unreadable
        partition, no mask, or a character outside the table, which this fold refuses to guess at)."""
        chars, mask = self._chars, self._all if mask is None else mask
        if chars is None or mask is None:
            return None
        single = isinstance(texts, str)
        out = []
        for t in ((texts,) if single else texts):
            seq = []
            for c in t:
                b, folded = chars.get(c), chars.get(c.casefold())
                if b is None or folded is None:
                    return None
                seq.append((b & mask, folded & mask))
            out.append((len(t), tuple(seq)))
        return (mask, out[0] if single else tuple(out))


def partition(pattern, parser=False):
    """The fold one pattern makes of a value: two values with the same key are values that pattern cannot tell apart,
    so a line reading one reads the other. `parser`: count the shell parser's own classes too, because a value holding
    `;` is not the text it looks like — the line reads `a;b` as two commands and `aXb` as one word."""
    return Partition([pattern], parser=parser)


class Lazy:
    """A fold key built on first use: a decision that folds no value pays nothing for the fold, and what it builds
    belongs to that decision alone, so no value an agent makes is remembered past the call that made it."""

    def __init__(self, build):
        self._build, self._key = build, False

    def __call__(self, texts):
        if self._key is False:
            self._key = self._build()
        return None if self._key is None else self._key(texts)
