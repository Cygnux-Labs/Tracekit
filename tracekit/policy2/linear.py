"""A linear-time search for the patterns compile.check_pattern accepts, with RE2's semantics: what the verifiers
search a bundle's label patterns with (labels._compiled), on the standard library (a --no-deps verifier), ported to
the TypeScript verifier (sdk/typescript/src/verify/rx.ts). A Pike VM over sre's parse of the pattern: a search costs at
most its program's size times the text's length, each step counted against a Budget the caller shares, so a hostile
bundle's patterns end in a failure (Spent), never a hang, and the verdict is the same on any machine and in both
verifiers (a timeout, as the signer's fallback engine has, would depend on the machine's speed).

RE2's semantics, not Python's: `^` and `$` are the start and end of the text, `.` any character but a newline, \\d \\w
\\s \\b ASCII (\\s: tab, newline, form feed, carriage return, space), and case as written: a label pattern is
matched against the policy's own labels, never in any case."""
from tracekit.policy2.compile import PolicyError, check_pattern

try:  # Python 3.11 moved the regex parser
    from re import _constants as _c, _parser as _p
except ImportError:  # pragma: no cover - Python 3.9 / 3.10
    import sre_constants as _c, sre_parse as _p

MAX_PROGRAM = 20000   # instructions of one pattern's program; past it the pattern is refused (RE2 caps its own)
STEPS = 20_000_000    # a verification's budget for every label search (a policy's own take a few thousand)
_WORD = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_CATEGORIES = {_c.CATEGORY_DIGIT: lambda ch: "0" <= ch <= "9", _c.CATEGORY_WORD: lambda ch: ch in _WORD,
               _c.CATEGORY_SPACE: lambda ch: ch in "\t\n\f\r "}
_CATEGORIES.update({_c.CATEGORY_NOT_DIGIT: lambda ch: not "0" <= ch <= "9",
                    _c.CATEGORY_NOT_WORD: lambda ch: ch not in _WORD,
                    _c.CATEGORY_NOT_SPACE: lambda ch: ch not in "\t\n\f\r "})


class Spent(Exception):
    """The Budget ran out: the searches cost more than the verifier spends on them."""


class Budget:
    def __init__(self, steps=None):
        self.steps = self.left = STEPS if steps is None else steps

    def spend(self, n):
        self.left -= n
        if self.left < 0:
            raise Spent(f"the label patterns took more than {self.steps} steps to replay")


def _in(items):
    """A character class of sre's parse as a predicate."""
    negate = bool(items) and items[0][0] is _c.NEGATE
    tests = []
    for op, av in items[negate:]:
        if op is _c.LITERAL:
            tests.append(lambda ch, x=chr(av): ch == x)
        elif op is _c.RANGE:
            tests.append(lambda ch, lo=chr(av[0]), hi=chr(av[1]): lo <= ch <= hi)
        elif op is _c.CATEGORY and av in _CATEGORIES:
            tests.append(_CATEGORIES[av])
        else:
            raise PolicyError(f"{op} in a class is outside the RE2 subset")
    return lambda ch: any(t(ch) for t in tests) != negate


def _emit(items, prog):
    """Append the program of sre's parse `items` to `prog`: ("char", test), ("split", a, b), ("jmp", a), ("at", kind)."""
    for op, av in items:
        if len(prog) > MAX_PROGRAM:
            raise PolicyError(f"the pattern compiles to more than {MAX_PROGRAM} instructions")
        if op is _c.LITERAL:
            prog.append(("char", lambda ch, x=chr(av): ch == x))
        elif op is _c.NOT_LITERAL:
            prog.append(("char", lambda ch, x=chr(av): ch != x))
        elif op is _c.ANY:
            prog.append(("char", lambda ch: ch != "\n"))
        elif op is _c.IN:
            prog.append(("char", _in(av)))
        elif op is _c.AT:
            prog.append(("at", av))
        elif op is _c.SUBPATTERN:
            _emit(av[-1], prog)
        elif op is _c.BRANCH:
            ends, alts = [], av[1]
            for alt in alts[:-1]:
                at = len(prog)
                prog.append(None)
                _emit(alt, prog)
                ends.append(len(prog))
                prog.append(None)
                prog[at] = ("split", at + 1, len(prog))
            _emit(alts[-1], prog)
            for at in ends:
                prog[at] = ("jmp", len(prog))
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT):   # lazy or greedy: the same whether it matches
            lo, hi, item = av
            for _ in range(lo):
                _emit(item, prog)
            if hi == _c.MAXREPEAT:
                at = len(prog)
                prog.append(None)
                _emit(item, prog)
                prog.append(("jmp", at))
                prog[at] = ("split", at + 1, len(prog))
            else:
                outs = []
                for _ in range(hi - lo):
                    outs.append(len(prog))
                    prog.append(None)
                    _emit(item, prog)
                for at in outs:
                    prog[at] = ("split", at + 1, len(prog))
        else:
            raise PolicyError(f"{op} is outside the RE2 subset")


class Pattern:
    """A pattern compile.check_pattern accepts, compiled for search(); PolicyError for any other."""

    def __init__(self, pattern):
        check_pattern(pattern)
        self.prog, self.found = [], {}
        _emit(_p.parse(pattern), self.prog)
        self.prog.append(("match",))
        if len(self.prog) > MAX_PROGRAM:
            raise PolicyError(f"the pattern compiles to more than {MAX_PROGRAM} instructions")

    def _at(self, kind, text, i):
        if kind in (_c.AT_BEGINNING, _c.AT_BEGINNING_STRING):
            return i == 0
        if kind == _c.AT_END:
            return i == len(text)
        return (i > 0 and text[i - 1] in _WORD) != (i < len(text) and text[i] in _WORD)   # \b

    def _add(self, text, i, pc, seen, ready, budget):
        """Follow the threads from `pc` at position `i` to the instructions that read a character (into `ready`);
        True when one reaches the match."""
        stack = [pc]
        while stack:
            pc = stack.pop()
            if pc in seen:
                continue
            seen.add(pc)
            budget.spend(1)
            ins = self.prog[pc]
            if ins[0] == "match":
                return True
            if ins[0] == "jmp":
                stack.append(ins[1])
            elif ins[0] == "split":
                stack += (ins[2], ins[1])
            elif ins[0] == "at":
                if self._at(ins[1], text, i):
                    stack.append(pc + 1)
            else:
                ready.append(pc)
        return False

    def search(self, text, budget):
        """Whether the pattern matches somewhere in `text`, spending `budget` (Spent when it runs out); a text searched
        before is answered from then on (a run's calls carry few sets of labels)."""
        if text not in self.found:
            self.found[text] = self._search(text, budget)
        return self.found[text]

    def _search(self, text, budget):
        threads = []
        for i in range(len(text) + 1):
            seen, ready = set(), []
            for pc in threads + [0]:
                if self._add(text, i, pc, seen, ready, budget):
                    return True
            if i == len(text):
                return False
            budget.spend(len(ready))
            threads = [pc + 1 for pc in ready if self.prog[pc][1](text[i])]
        return False
