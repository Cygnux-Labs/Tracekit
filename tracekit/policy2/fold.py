"""#683: the value fold — two values a live rule reads alike are one reading of the line.

A rule is a regular expression, and a regular expression tells values apart only by the character classes its pattern
holds: `.`, a `\\w` or a set, and each literal character as a class of its own. So two values of the same length that
fall in the same class at every position find the same matches, hold the same literals and require the same things —
reading one of them stands for both, and a loop over a thousand names costs one reading of its body instead of a
thousand.

`char_sets` reads a pattern into the character sets it holds, `Partition` builds the classes all of a policy's shell
rules make of one alphabet, and `key` is what two readings share under a mask of the rules alive in one command.
`partition` is the same fold for a single pattern, which is what `tests/test_policy2.py` states it by.

Nothing here outlives the decision that asked: a `Partition` is built from a policy and holds no value a command
gave it, and a `Lazy` key is built inside one decision and dropped with it.
"""

from ..policy import _sre_c, _sre_p

# the characters the shell parser itself reads specially: the fold keeps those apart whatever the rules say, because
# `a;b` and `aXb` are not one line however alike the rules read them
PARSER_CHARS = frozenset(" \t\n'\"`\\$*?[]{}~=<>|&;()#!")

_ANY = None   # a set holding every character: a constant bit in every class, so it separates nothing


def char_sets(pattern):
    """The character sets a checked pattern holds, in the order the walk meets them, with None standing for one that
    holds every character (`.` a category, a negated set). Two characters no set holds exactly one of are characters
    the pattern cannot tell apart anywhere in a subject — which is the partition RE2 builds its byte classes from: two
    values alike in it find the same matches, the same literals (a literal's own characters are singleton sets here)
    and the same requirements. None when the pattern holds something this walk cannot read, which makes a fold on it
    unsound."""
    out, stack = [], list(_sre_p.parse(pattern))
    while stack:
        op, av = stack.pop()
        if op == _sre_c.LITERAL:
            out.append(frozenset(chr(av)))
        elif op == _sre_c.IN:
            got, wide = set(), False
            for iop, iav in av:
                if iop == _sre_c.LITERAL:
                    got.add(chr(iav))
                elif iop == _sre_c.RANGE:
                    got |= {chr(c) for c in range(iav[0], iav[1] + 1)}
                else:   # a category, a negation, a big set: one that reads more than the characters listed
                    wide = True
            if got:
                out.append(frozenset(got))
            if wide:
                out.append(_ANY)
        elif op in (_sre_c.ANY, _sre_c.CATEGORY, _sre_c.NOT_LITERAL, _sre_c.AT):
            out.append(_ANY)
        elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
            stack.extend(av[2])
        elif op == _sre_c.SUBPATTERN:
            stack.extend(av[-1])
        elif op == _sre_c.BRANCH:
            for branch in av[1]:
                stack.extend(branch)
        else:   # a big charset, a group reference, anything this walk has no reading for
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
        """What two readings share when no live pattern can tell them apart: each text's length and each character's
        classes under `mask`. A string is one text and keys to its own pair; a sequence keys to their tuple. None: not
        foldable (an unreadable partition, no mask, or a character outside the table, which is read as itself)."""
        chars, mask = self._chars, self._all if mask is None else mask
        if chars is None or mask is None:
            return None
        single = isinstance(texts, str)
        out = []
        for t in ((texts,) if single else texts):
            seq = []
            for c in t:
                b = chars.get(c)
                if b is None:
                    return None
                seq.append(b & mask)
            out.append((len(t), tuple(seq)))
        return out[0] if single else tuple(out)


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
