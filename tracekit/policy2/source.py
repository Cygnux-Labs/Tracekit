"""Read the calls a Browser Use 1.x `python` cell or `finish_from_repl` delivery makes, from its source.

The signer decides one call per cell. This module reads the source with `ast.parse` (never compile or exec) as a small
subset of Python: each literal helper or command call becomes the action it stands for, which the engine decides, the
cell taking the strictest. Left unread is only what computes values: a builtin called directly, an inert module's own
function, a method of plain data the cell built, and a function the cell defines, whose body is read where it is
defined trusting none of the cell's names. Everything outside the subset is held as TK-SOURCE-PARSE: rebinding a name
the reader trusts, a dunder, `:=`, exec and its kin, an import outside the list, a class with a base, a store into
anything but plain data, a callable handed on as a value, a method of anything but plain data, and a call or attribute
through a name the cell did not bind (an earlier cell's). docs/limits.md lists the subset.
"""
import ast
import builtins
import datetime
import decimal
import importlib
import re

from . import shell

MAX_SOURCE = 64 * 1024   # bytes of UTF-8; a longer cell or delivery is held, not cut
MAX_SUBJECT = 64 * 1024  # bytes of UTF-8; no literal the reader resolves is longer (the engine's subject limit)
MAX_CALLS = 256          # calls read for one decision

_MISSING = object()


def _names(prefix, names):
    return {f"{prefix}.{name}" for name in names.split()}


# The modules a cell may import (any other import is held) and, through them, the calls left unread: each public
# function or class the module defines itself, a classmethod of such a class, and os.path's path functions. A reviewed
# list; tests/test_policy2.py checks that `inspect` finds each on the running Python. Left out: what sets the clock or
# the process's time zone, decimal's context setters, json's file readers and writers, and re's cache purge.
INERT_MODULES = frozenset({"json", "re", "math", "cmath", "time", "datetime", "itertools", "collections", "string",
                           "textwrap", "unicodedata", "decimal", "os", "os.path"})
INERT_CALLS = frozenset().union(
    _names("json", "detect_encoding dumps loads"),
    _names("re", "Match Pattern RegexFlag Scanner compile error escape findall finditer fullmatch match search split "
                 "sub subn"),
    _names("math", "acos acosh asin asinh atan atan2 atanh ceil comb copysign cos cosh degrees dist erf erfc exp expm1 "
                   "fabs factorial floor fmod frexp fsum gamma gcd hypot isclose isfinite isinf isnan isqrt lcm ldexp "
                   "lgamma log log10 log1p log2 modf nextafter perm pow prod radians remainder sin sinh sqrt tan tanh "
                   "trunc ulp"),
    _names("cmath", "acos acosh asin asinh atan atanh cos cosh exp isclose isfinite isinf isnan log log10 phase polar "
                    "rect sin sinh sqrt tan tanh"),
    _names("time", "asctime ctime get_clock_info gmtime localtime mktime monotonic monotonic_ns perf_counter "
                   "perf_counter_ns process_time process_time_ns sleep strftime strptime struct_time thread_time "
                   "thread_time_ns time time_ns"),
    _names("datetime", "date date.fromisocalendar date.fromisoformat date.fromordinal date.fromtimestamp date.today "
                       "datetime datetime.combine datetime.fromisocalendar datetime.fromisoformat "
                       "datetime.fromordinal datetime.fromtimestamp datetime.now datetime.strptime datetime.today "
                       "datetime.utcfromtimestamp datetime.utcnow time time.fromisoformat timedelta timezone tzinfo"),
    _names("itertools", "accumulate chain chain.from_iterable combinations combinations_with_replacement compress "
                        "count cycle dropwhile filterfalse groupby islice permutations product repeat starmap "
                        "takewhile tee zip_longest"),
    _names("collections", "ChainMap ChainMap.fromkeys Counter Counter.fromkeys OrderedDict OrderedDict.fromkeys "
                          "UserDict UserDict.fromkeys UserList UserString defaultdict deque namedtuple"),
    _names("string", "Formatter Template capwords"),
    _names("textwrap", "TextWrapper dedent fill indent shorten wrap"),
    _names("unicodedata", "UCD bidirectional category combining decimal decomposition digit east_asian_width "
                          "is_normalized lookup mirrored name normalize numeric"),
    _names("decimal", "Clamped Context ConversionSyntax Decimal Decimal.from_float DecimalException DecimalTuple "
                      "DivisionByZero DivisionImpossible DivisionUndefined FloatOperation Inexact InvalidContext "
                      "InvalidOperation Overflow Rounded Subnormal Underflow getcontext"),
    _names("os.path", "abspath basename commonpath commonprefix dirname exists expanduser expandvars getatime getctime "
                      "getmtime getsize isabs isdir isfile islink ismount join lexists normcase normpath realpath "
                      "relpath samefile sameopenfile samestat split splitdrive splitext"))
# the inert modules' constants a cell may use as values
INERT_DATA = frozenset().union(
    _names("string", "ascii_letters ascii_lowercase ascii_uppercase digits hexdigits octdigits printable punctuation "
                     "whitespace"),
    _names("math", "e inf nan pi tau"),
    _names("cmath", "e inf infj nan nanj pi tau"),
    _names("re", "A ASCII DEBUG DOTALL I IGNORECASE L LOCALE M MULTILINE S U UNICODE VERBOSE X"),
    _names("datetime", "MAXYEAR MINYEAR date.max date.min date.resolution datetime.max datetime.min "
                       "datetime.resolution time.max time.min time.resolution timedelta.max timedelta.min "
                       "timedelta.resolution timezone.max timezone.min timezone.utc"),
    _names("decimal", "MAX_EMAX MAX_PREC MIN_EMIN MIN_ETINY ROUND_05UP ROUND_CEILING ROUND_DOWN ROUND_FLOOR "
                      "ROUND_HALF_DOWN ROUND_HALF_EVEN ROUND_HALF_UP ROUND_UP"),
    _names("time", "altzone daylight timezone tzname"),
    _names("os.path", "altsep curdir defpath devnull extsep pardir pathsep sep"),
    _names("unicodedata", "unidata_version"))
# classes a package exports from a submodule of its own: named only where they are compared against (an `except`
# clause, `isinstance`), never called or handed on
INERT_TYPES = frozenset({"json.JSONDecodeError", "json.JSONDecoder", "json.JSONEncoder"})

# What a Browser Use 1.x cell finds bound before it runs, read from browser-use 1.0.3's REPL worker
# (browser_use/repl/worker.py) and `from browser_harness.helpers import *` in browser-harness 0.1.13; a test checks it
# against the installed harness. A cell may not rebind any of these. The names the harness imported read as if the
# cell had imported them:
HARNESS_IMPORTS = {
    "base64": "base64", "importlib": "importlib", "json": "json", "math": "math", "os": "os", "time": "time",
    "urllib": "urllib", "ipc": "browser_harness._ipc", "paths": "browser_harness.paths", "Path": "pathlib.Path",
    "urlparse": "urllib.parse.urlparse", "start_recording": "browser_harness.recorder.start_recording",
    "stop_recording": "browser_harness.recorder.stop_recording",
    "recording_dir": "browser_harness.recorder.recording_dir"}
# and its own functions and objects, each of which may act: called only as a mapped helper, never handed on
HARNESS_OWN = frozenset({
    # browser_harness/helpers.py
    "AGENT_WORKSPACE", "CORE_DIR", "DEFAULT_IPC_RESPONSE_TIMEOUT_SECONDS", "INTERNAL", "IPC_CONNECT_TIMEOUT_SECONDS",
    "NAME", "REPO_ROOT", "SCREENSHOT_IPC_RESPONSE_TIMEOUT_SECONDS", "SOCK", "activate_tab", "capture_screenshot",
    "cdp", "click_at_xy", "close_tab", "current_tab", "dispatch_key", "drain_events", "ensure_real_tab", "fill_input",
    "goto_url", "http_get", "iframe_target", "js", "list_tabs", "new_tab", "page_info", "press_key", "scroll",
    "switch_tab", "type_text", "upload_file", "wait", "wait_for_element", "wait_for_load", "wait_for_network_idle",
    # browser_use/repl/worker.py
    "__bu_display", "bu", "checkpoint", "downloads", "report_issue", "screenshot", "search", "secret_names",
    "show_image", "solve_captcha", "type_secret"})
# the modules a cell reaches by name: the harness's imports, and those read only through their command and helper
# calls (SHELL, SHELL_ARGV, HELPERS), which an earlier cell may have imported
_TRUSTED_MODULES = {**HARNESS_IMPORTS, "helpers": "browser_harness.helpers", "browser_harness": "browser_harness",
                    "subprocess": "subprocess", "asyncio": "asyncio", "pty": "pty"}
_BUILTIN_NAMES = frozenset(dir(builtins))
# the names a cell may never bind, in any form: the reader reads a call through each by its name
TRUSTED = _BUILTIN_NAMES | {"__builtins__", "builtins"} | set(_TRUSTED_MODULES) | HARNESS_OWN
_IMPORTABLE = INERT_MODULES | {"browser_harness", "browser_harness.helpers"}
_MODULES = _IMPORTABLE | {"subprocess", "asyncio", "pty", "base64", "importlib", "urllib", "browser_harness._ipc",
                          "browser_harness.paths"}

REFLECTION = {"globals", "locals", "vars"}
DYNAMIC_CALLS = {"__import__", "importlib.import_module"}
SETATTR = {"setattr", "delattr"}
# code built at run time, and what stops or reads the process interactively: held wherever they are named (the
# prepass holds these and `__import__`; REFLECTION and SETATTR are held where they are called)
FORBIDDEN = frozenset({"exec", "eval", "compile", "breakpoint", "help"})
_HELD_BUILTINS = REFLECTION | SETATTR


class _Helper:
    """A browser-harness helper: its action, the source parameters in call order, which of them become the action's
    args, their defaults, and whether the value is a secret's name (written as its placeholder)."""

    def __init__(self, tool, params, out, defaults=None, secret=False):
        self.tool, self.params, self.out = tool, params, out
        self.defaults, self.secret = defaults or {}, secret


HELPERS = {
    "goto_url": _Helper("browser_use:navigate", ("url",), {"url": "url"}),
    "new_tab": _Helper("browser_use:new_tab", ("url",), {"url": "url"}, {"url": "about:blank"}),
    "js": _Helper("browser_use:evaluate", ("expression",), {"expression": "code"}),
    "upload_file": _Helper("browser_use:upload_file", ("selector", "path"), {"path": "path"}),
    "type_text": _Helper("browser_use:input", ("text",), {"text": "text"}),
    "type_secret": _Helper("browser_use:input", ("name",), {"name": "text"}, secret=True),
    "fill_input": _Helper("browser_use:input", ("selector", "text"), {"text": "text"}),
    "press_key": _Helper("browser_use:send_keys", ("key",), {"key": "key"}),
    "click_at_xy": _Helper("browser_use:click", ("x", "y"), {}),
    "http_get": _Helper("http_get", ("url",), {"url": "url"}),
}

# a dotted name -> the argument that holds its command. All but subprocess's argv/exec calls run a shell line.
SHELL = {
    "subprocess.run": "args", "subprocess.call": "args", "subprocess.check_call": "args",
    "subprocess.check_output": "args", "subprocess.Popen": "args",
    "subprocess.getoutput": "cmd", "subprocess.getstatusoutput": "cmd",
    "os.system": "command", "os.popen": "cmd",
    "asyncio.create_subprocess_shell": "cmd",
}
_SPAWNL = {"os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe"}
_SPAWNV = {"os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe"}
_EXECL = {"os.execl", "os.execle", "os.execlp", "os.execlpe"}   # (path, arg0, arg1, ...): no mode, argv inline
# calls that run a program from an argv list, which no shell rule reads through the action's own line
SHELL_ARGV = {
    "asyncio.create_subprocess_exec",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.posix_spawn", "os.posix_spawnp",
    "pty.spawn",
} | _SPAWNL | _SPAWNV | _EXECL
# the two Browser Use 1.x actions whose source this reads: the action -> (its argument, its parse mode)
CELLS = {"browser_use:python": ("code", "exec"), "browser_use:finish_from_repl": ("expression", "eval")}


class _Iter:
    """A view of or an iterator over plain data (`d.items()`, `zip(...)`): no methods of its own."""


# Plain data: a value whose exact type is one of these, built in the cell. Each type's own methods below read or change
# that value and nothing else (`append` and `sort` change only the cell's own list), so a call through one is unread.
PLAIN_METHODS = {kind: frozenset(names.split()) for kind, names in {
    str: "capitalize casefold center count encode endswith expandtabs find format format_map index isalnum isalpha "
         "isascii isdecimal isdigit isidentifier islower isnumeric isprintable isspace istitle isupper join ljust "
         "lower lstrip partition removeprefix removesuffix replace rfind rindex rjust rpartition rsplit rstrip split "
         "splitlines startswith strip swapcase title translate upper zfill",
    bytes: "capitalize center count decode endswith expandtabs find hex index isalnum isalpha isascii isdigit "
           "islower isspace istitle isupper join ljust lower lstrip partition removeprefix removesuffix replace rfind "
           "rindex rjust rpartition rsplit rstrip split splitlines startswith strip swapcase title translate upper "
           "zfill",
    list: "append clear copy count extend index insert pop remove reverse sort",
    dict: "clear copy get items keys pop popitem setdefault update values",
    set: "add clear copy difference difference_update discard intersection intersection_update isdisjoint issubset "
         "issuperset pop remove symmetric_difference symmetric_difference_update union update",
    tuple: "count index",
    int: "as_integer_ratio bit_length conjugate to_bytes",
    bool: "as_integer_ratio bit_length conjugate to_bytes",
    float: "as_integer_ratio conjugate hex is_integer",
    type(None): "",
    _Iter: "",
    re.Match: "end expand group groupdict groups span start",
    re.Pattern: "findall finditer fullmatch match search split sub subn",
    datetime.datetime: "astimezone ctime date dst isocalendar isoformat isoweekday replace strftime time timestamp "
                       "timetuple timetz toordinal tzname utcoffset utctimetuple weekday",
    datetime.date: "ctime isocalendar isoformat isoweekday replace strftime timetuple toordinal weekday",
    datetime.time: "dst isoformat replace strftime tzname utcoffset",
    datetime.timedelta: "total_seconds",
    datetime.timezone: "dst fromutc tzname utcoffset",
    decimal.Decimal: "adjusted as_integer_ratio as_tuple canonical compare compare_signal compare_total "
                     "compare_total_mag conjugate copy_abs copy_negate copy_sign exp fma is_canonical is_finite "
                     "is_infinite is_nan is_normal is_qnan is_signed is_snan is_subnormal is_zero ln log10 logb "
                     "logical_and logical_invert logical_or logical_xor max max_mag min min_mag next_minus next_plus "
                     "next_toward normalize number_class quantize radix remainder_near rotate same_quantum scaleb "
                     "shift sqrt to_eng_string to_integral to_integral_exact to_integral_value",
}.items()}
# and the data attributes a cell may read off plain data
PLAIN_DATA = {kind: frozenset(names.split()) for kind, names in {
    int: "denominator imag numerator real", bool: "denominator imag numerator real", float: "imag real",
    re.Match: "endpos lastgroup lastindex pos re regs", re.Pattern: "flags groupindex groups",
    datetime.datetime: "day fold hour microsecond minute month second tzinfo year",
    datetime.date: "day month year", datetime.time: "fold hour microsecond minute second tzinfo",
    datetime.timedelta: "days microseconds seconds", decimal.Decimal: "imag real",
}.items()}
ANY = frozenset(PLAIN_METHODS)
# methods that put their arguments inside the value: plain data holding only plain data stays so only if they are
_INSERTING = frozenset("add append extend insert setdefault symmetric_difference_update update".split())
# methods that return an element of the value (plain only when the value holds plain data only), and views of it
_ELEMENT = frozenset({"get", "pop", "popitem", "setdefault"})
_VIEWS = frozenset({"items", "keys", "values", "finditer"})

# calls whose result is new plain data whatever their positional arguments (a keyword's value must be plain: json's
# hooks and encoder class are keywords)
FRESH_CALLS = frozenset({
    "bin", "bool", "callable", "chr", "hex", "input", "isinstance", "issubclass", "len", "oct", "ord", "print",
    "json.dumps", "json.loads", "re.compile", "re.findall", "re.finditer", "re.fullmatch", "re.match", "re.search",
    "re.split"})
# builtins that build a container of their arguments' items: plain, and holding plain data only when those are
_BUILT = {"dict": dict, "list": list, "set": set, "sorted": list, "tuple": tuple,
          "enumerate": _Iter, "range": _Iter, "reversed": _Iter, "zip": _Iter}
# calls whose result is plain data when every argument is
PURE_CALLS = frozenset({
    "abs", "divmod", "float", "format", "int", "max", "min", "pow", "repr", "round", "str", "sum",
    "re.escape", "re.sub", "re.subn", "string.capwords", "textwrap.dedent", "textwrap.fill", "textwrap.indent",
    "textwrap.shorten", "textwrap.wrap", "time.asctime", "time.ctime", "time.mktime", "time.monotonic",
    "time.perf_counter", "time.strftime", "time.time", "time.time_ns", "decimal.Decimal", "decimal.Decimal.from_float",
    "datetime.date", "datetime.datetime", "datetime.time", "datetime.timedelta", "datetime.timezone"} | {
    name for name in INERT_CALLS if name.startswith(("math.", "os.path.", "unicodedata.", "datetime.date.",
                                                     "datetime.datetime.", "datetime.time."))} - {"unicodedata.UCD"})
# where a callee calls what it is handed: only a function the cell defines, or plain data, may stand there
_CALLS_ARGS = {
    "map": (0,), "filter": (0,), "iter": (0,), "sorted": ("key",), "min": ("key",), "max": ("key",),
    "property": (0, 1, 2, "fget", "fset", "fdel"), "classmethod": (0,), "staticmethod": (0,),
    "re.sub": (1, "repl"), "re.subn": (1, "repl"), "re.Scanner": (0, "lexicon"),
    "itertools.accumulate": (1, "func"), "itertools.dropwhile": (0,), "itertools.filterfalse": (0,),
    "itertools.groupby": (1, "key"), "itertools.starmap": (0,), "itertools.takewhile": (0,),
    "collections.defaultdict": (0, "default_factory"),
    "textwrap.indent": (2, "predicate"),
    "json.loads": ("cls", "object_hook", "object_pairs_hook", "parse_constant", "parse_float", "parse_int"),
    "json.dumps": ("cls", "default")}
_METHOD_CALLS_ARGS = {"sort": ("key",), "sub": (0, "repl"), "subn": (0, "repl")}
_TYPE_ARGS = {"isinstance": 1, "issubclass": 1}
# a builtin type's own functions a cell may call through the type
BUILTIN_ATTRS = frozenset({"bytes.fromhex", "bytes.maketrans", "dict.fromkeys", "float.fromhex", "int.from_bytes",
                           "str.join", "str.maketrans"})
_DECORATORS = frozenset({"classmethod", "property", "staticmethod"})
_READ_MODES = frozenset({"r", "rt", "tr", "rb", "br"})
_TRY = tuple(c for c in (ast.Try, getattr(ast, "TryStar", None)) if c is not None)
_MATCH = getattr(ast, "Match", None)
_TYPE_ALIAS = getattr(ast, "TypeAlias", None)
_CAPTURES = tuple(getattr(ast, n) for n in ("MatchAs", "MatchStar") if hasattr(ast, n))
_REFERENCES = (ast.Name, ast.Attribute, ast.Subscript, ast.BoolOp, ast.IfExp)   # each evaluates to an existing value

# What an expression evaluates to, as the reader follows it: ("lit", value); ("plain", types, deep) plain data of one
# of the types, `deep` when it holds plain data only (State.deep); ("func",) a function, class or generator the cell
# defines, its body read; ("module", dotted); ("known", dotted) a callable the reader knows by name; ("builtin", name);
# ("harness", name); ("unknown",); ("unbound", name) a name the cell has not bound, an earlier cell's.
UNKNOWN = ("unknown",)
FUNC = ("func",)
_NOT_VALUES = frozenset({"module", "known", "builtin", "harness"})


def _dunder(name):
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _plain(v):
    """(types, deep) when `v` is plain data, else None."""
    if v[0] == "lit":
        return frozenset({type(v[1])}), True
    if v[0] == "plain":
        return v[1], v[2]
    return None


def _deep(v):
    p = _plain(v)
    return bool(p and p[1])


def _item(v):
    """An item of `v`: plain data holding plain data only when `v` holds plain data only."""
    return ("plain", ANY, True) if _deep(v) else UNKNOWN


def _allowed(table, types, name):
    """`name` is in the table of each of the types that has it, and of one of them at least."""
    found = False
    for kind in types:
        if name in table.get(kind, ()):
            found = True
        elif hasattr(kind, name):
            return False
    return found


def _of(value):
    for kind in type(value).__mro__:
        if kind in PLAIN_METHODS:
            return ("plain", frozenset({kind}), True)
    return UNKNOWN


def _data_value(dotted):
    module = "os.path" if dotted.startswith("os.path.") else dotted.split(".", 1)[0]
    value = importlib.import_module(module)
    for part in dotted[len(module) + 1:].split("."):
        value = getattr(value, part, _MISSING)
    return UNKNOWN if value is _MISSING else _of(value)


_DATA = {dotted: _data_value(dotted) for dotted in INERT_DATA | _names("subprocess", "DEVNULL PIPE STDOUT")}


def _helper(dotted):
    prefix = "browser_harness.helpers."
    return HELPERS.get(dotted[len(prefix):]) if dotted.startswith(prefix) else None


def _resolve(dotted):
    """What a dotted name under a module stands for: a module, an inert constant, or a name the reader knows."""
    if dotted in _MODULES:
        return ("module", dotted)
    return _DATA.get(dotted, ("known", dotted))


class _State:
    """What one reading shares: the calls found, the call counter, the stop flag and the budget; whether plain data
    may hold plain data only (`deep`), and whether the cell put anything else into a container (`mixed`)."""

    def __init__(self, work=None, deep=True):
        self.calls = []
        self.count = 0
        self.stop = False
        self.work = [0] if work is None else work
        self.deep, self.mixed = deep, False


def read(code, mode="exec", work=None):
    """(the calls a source names, why it is held or None): [(tool, args)]. Parse only; never run the source.

    A container holds plain data only when it was built from plain data only (`json.loads`, `str.split`, a `re`
    result, a literal of such values) and nothing in the whole cell puts anything else into a container: a store or a
    method that puts in a value the reader can't follow makes the cell read again with no container holding plain data
    only, so no second name for a container ever matters."""
    state = _State(work)
    reading = Reader(code, mode, state=state).run()
    if state.mixed:
        state = _State(state.work, deep=False)
        reading = Reader(code, mode, state=state).run()
    return reading


class _Reading:
    def __init__(self, calls, held):
        self.calls, self.held = calls, held


class _Env:
    """The literal values names hold where the reader is: what `lit` resolves a name to."""

    def __init__(self, reader):
        self.reader = reader

    def get(self, name, default=None):
        v = self.reader.lookup(name)
        return v[1] if v[0] == "lit" else default


class Reader:
    def __init__(self, code, mode="exec", state=None):
        self.code, self.mode, self.state = code, mode, state or _State()
        self.held = None
        self.scope, self.frames, self.deferred = {}, [], False
        self.bound_anywhere, self.globals = set(), set()
        self.env = _Env(self)

    @property
    def calls(self):
        return self.state.calls

    def run(self):
        size = len(self.code.encode("utf-8", "surrogatepass"))
        if size > MAX_SOURCE:
            self.hold("size")
            return _Reading(self.state.calls, self.held)
        if not self._charge(size):
            return _Reading(self.state.calls, self.held)
        try:
            tree = ast.parse(self.code, mode=self.mode)
        except Exception as exc:   # SyntaxError, ValueError (a null byte), MemoryError, RecursionError: unread, never raised
            self.hold("syntax" if isinstance(exc, SyntaxError) else "unreadable")
            return _Reading(self.state.calls, self.held)
        try:
            self.prepass(tree)
            self.visit(tree)
        except Exception:   # a nesting too deep or an unusual node: held, never raised into the signer
            self.hold("unreadable")
        return _Reading(self.state.calls, self.held)

    def visit(self, tree):
        if isinstance(tree, ast.Expression):
            self.value(tree.body)
        else:
            self.block(tree.body)

    def hold(self, cause):
        if self.held is None:
            self.held = cause

    def _charge(self, n):
        """Spend the decision's budget; a spent budget holds the source and stops the whole read."""
        try:
            shell.charge(self.state.work, n)
        except shell.ParseError:
            self.hold("budget")
            self.state.stop = True
            return False
        return True

    # --- before reading: what the cell binds, and what it reaches outside the subset ---
    def prepass(self, tree):
        """Hold a cell that binds a name the reader trusts (a builtin, a harness name, a module or a name an import
        binds, `__builtins__`) in any form but its own import, uses a dunder name, `builtins`, `:=` or a FORBIDDEN
        name anywhere, or imports outside the list; and note every name the cell binds anywhere, which a body that
        runs later never trusts. (A dunder attribute is held where it is read.)"""
        local, imported = set(), {}
        for sub in ast.walk(tree):
            if not self._charge(1):
                return
            if isinstance(sub, ast.comprehension):   # the comprehension's targets are its own
                local.update(id(n) for n in ast.walk(sub.target) if isinstance(n, ast.Name))
            elif isinstance(sub, (ast.Import, ast.ImportFrom)):
                for name, target in self.imports(sub):
                    imported.setdefault(name, set()).add(target)
            elif isinstance(sub, ast.Name) and sub.id != "__name__" \
                    and (sub.id in ("__builtins__", "builtins") or _dunder(sub.id)):
                self.hold("builtins" if "builtins" in sub.id else sub.id if sub.id in DYNAMIC_CALLS else "dunder")
            elif isinstance(sub, ast.Name) and sub.id in FORBIDDEN:
                self.hold(sub.id)
            elif isinstance(sub, ast.NamedExpr):
                self.hold("walrus")   # a binding inside an expression, which may not run all its parts
            elif isinstance(sub, (ast.Global, ast.Nonlocal)):
                self.globals.update(sub.names)
        for name, targets in imported.items():
            self.bound_anywhere.add(name)
            if len(targets) > 1 or name in TRUSTED and targets != {_TRUSTED_MODULES.get(name)}:
                self.hold("bind")
        for sub in ast.walk(tree):
            for name, own_scope in _bindings(sub, local):
                self.bound_anywhere.add(name)
                if not own_scope and (name in TRUSTED or name in imported):
                    self.hold("bind")

    def imports(self, node):
        """(name, what it binds) for each name an import binds; an import outside the list is held."""
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in _IMPORTABLE:
                    self.hold("import")
                    continue
                root = a.name.split(".")[0]
                yield (a.asname, a.name) if a.asname else (root, root)
            return
        base = node.module or ""
        if node.level or base not in _IMPORTABLE:
            self.hold("import")
            return
        for a in node.names:
            target = f"{base}.{a.name}"
            if a.name == "*" or _resolve(target)[0] == "known" and not (
                    target in INERT_CALLS or target in INERT_TYPES or target in SHELL or target in SHELL_ARGV
                    or _helper(target)):
                self.hold("import")
                continue
            yield a.asname or a.name, target

    # --- names ---
    def lookup(self, name):
        for frame in reversed(self.frames):
            if name in frame:
                return frame[name]
        if self.deferred:
            if name in self.bound_anywhere:
                return UNKNOWN   # a body that runs later trusts none of the cell's names: any may be rebound first
        elif name in self.globals:
            return UNKNOWN
        elif name in self.scope:
            return self.scope[name]
        if name == "__name__":
            return ("plain", frozenset({str}), True)
        if name in _BUILTIN_NAMES:
            return ("builtin", name)
        if name in _TRUSTED_MODULES:
            return _resolve(_TRUSTED_MODULES[name])
        if name in HARNESS_OWN:
            return ("harness", name)
        return ("unbound", name)

    def made(self, types, deep):
        """Plain data the cell builds: holding plain data only when what it is built from does, and no store in the
        cell puts anything else into a container (State.deep)."""
        return ("plain", types, deep and self.state.deep)

    def bind(self, name, v):
        if not self.deferred:
            self.scope[name] = v

    def snapshot(self):
        self._charge(len(self.scope))
        return dict(self.scope)

    def forget(self, nodes):
        """After a block that may run or not, or run again, each name it binds holds a value the reader can't
        follow."""
        if self.deferred:
            return
        names = set()
        for sub in (s for node in nodes for s in ast.walk(node)):
            if not self._charge(1):
                return
            names.update(name for name, _ in _bindings(sub, ()))
            if isinstance(sub, ast.alias):
                names.add((sub.asname or sub.name).split(".")[0])
        for name in names:
            self.scope[name] = UNKNOWN

    # --- statements: read in the order they run, so a name holds the value last assigned before it is read ---
    def block(self, body):
        for node in body:
            if self.state.stop or not self._charge(1):
                return
            self.stmt(node)

    def stmt(self, node):
        if isinstance(node, ast.Expr):
            self.value(node.value)
        elif isinstance(node, ast.Assign):
            self.assign(node.targets, node.value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.assign([node.target], node.value)
            elif not isinstance(node.target, ast.Name):
                self.value(node.target.value, use=False)   # a non-simple target is evaluated even without a value
                if isinstance(node.target, ast.Subscript):
                    self.value(node.target.slice)
            self.types(node.annotation)
        elif isinstance(node, ast.AugAssign):
            self.aug_assign(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.function(node)
        elif isinstance(node, ast.ClassDef):
            self.class_def(node)
        elif isinstance(node, ast.If):
            test = lit(node.test, self.env)
            self.value(node.test)
            if test is True or test is False:
                self.block(node.body if test else node.orelse)
                return
            before = self.snapshot()
            self.block(node.body)
            self.scope = dict(before)
            self.block(node.orelse)
            self.scope = before
            self.forget(node.body + node.orelse)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            items = self.value(node.iter)
            self.forget([node])   # a run starts with what the last one left
            start = self.snapshot()
            self.store(node.target, _item(items))
            self.block(node.body)
            self.scope = start
            self.block(node.orelse)
            self.forget([node])
        elif isinstance(node, ast.While):
            self.forget([node])
            test = lit(node.test, self.env)
            start = self.snapshot()
            self.value(node.test)
            if test is not False:
                self.block(node.body)
            self.scope = start
            self.block(node.orelse)   # runs once the test is false
            self.forget([node])
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.value(item.context_expr)
                if item.optional_vars is not None:
                    self.store(item.optional_vars, UNKNOWN)
            self.block(node.body)
            self.forget(node.body)   # a context manager may end the block early
        elif isinstance(node, _TRY):
            before = self.snapshot()
            self.block(node.body)
            self.scope = before
            self.forget(node.body)
            after = self.snapshot()
            for handler in node.handlers:
                self.scope = dict(after)
                if handler.type is not None:
                    self.types(handler.type)
                if handler.name:
                    self.bind(handler.name, UNKNOWN)
                self.block(handler.body)
            self.scope = dict(after)
            self.block(node.orelse)
            self.scope = after
            self.forget(node.handlers + node.orelse)
            self.block(node.finalbody)
        elif _MATCH is not None and isinstance(node, _MATCH):
            self.value(node.subject)
            before = self.snapshot()
            for case in node.cases:
                self.scope = dict(before)
                self.pattern(case.pattern)
                if case.guard is not None:
                    self.value(case.guard)
                self.block(case.body)
            self.scope = before
            self.forget([node])
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for name, target in self.imports(node):
                self.bind(name, _resolve(target))
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if not self.deferred:
                        self.scope.pop(target.id, None)
                else:
                    self.store(target, UNKNOWN, removes=True)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.value(node.value)
        elif isinstance(node, ast.Raise):
            for part in (node.exc, node.cause):
                if part is not None:
                    self.types(part)
        elif _TYPE_ALIAS is not None and isinstance(node, _TYPE_ALIAS):
            self.type_params(node)
            self.types(node.value)
            self.bind(node.name.id, UNKNOWN)
        elif not isinstance(node, (ast.Global, ast.Nonlocal, ast.Pass, ast.Break, ast.Continue)):
            for child in ast.iter_child_nodes(node):   # Assert, a `type` alias and the like
                if isinstance(child, ast.expr):
                    self.value(child)

    def pattern(self, pattern):
        for sub in ast.walk(pattern):
            if isinstance(sub, _CAPTURES) and sub.name:
                self.bind(sub.name, UNKNOWN)
            elif isinstance(sub, ast.MatchMapping) and sub.rest:
                self.bind(sub.rest, UNKNOWN)
            elif isinstance(sub, ast.MatchValue):
                self.value(sub.value)
            elif isinstance(sub, ast.MatchClass):
                self.types(sub.cls)

    def assign(self, targets, source):
        if len(targets) == 1 and isinstance(targets[0], (ast.Tuple, ast.List)) \
                and isinstance(source, (ast.Tuple, ast.List)) and len(source.elts) == len(targets[0].elts) \
                and not any(isinstance(e, ast.Starred) for e in source.elts + targets[0].elts):
            values = [self.value(e) for e in source.elts]
            for target, v, part in zip(targets[0].elts, values, source.elts):
                self.store(target, v, part)
            return
        v = self.value(source)
        for target in targets:
            self.store(target, v, source)

    def store(self, target, v, source=None, removes=False):
        """Bind or store `v`. A name may be bound to plain data, a function the cell defines or a call's result, not
        made another name for a value the reader can't follow; only plain data may be stored into, and plain data
        holding plain data only takes plain data only. Anything else is held."""
        reference = isinstance(source, _REFERENCES) and v[0] != "func" and not _plain(v)
        if isinstance(target, ast.Name):
            if reference:
                self.hold("value")
            self.bind(target.id, v)
        elif isinstance(target, (ast.Tuple, ast.List)):
            if reference:
                self.hold("value")
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    self.store(elt.value, self.made(frozenset({list}), _deep(v)))
                else:
                    self.store(elt, _item(v))
        elif isinstance(target, ast.Starred):
            self.store(target.value, v, source)
        elif isinstance(target, ast.Subscript):
            base = self.value(target.value)
            self.value(target.slice)
            if not _plain(base):
                self.hold("store")
            elif not removes and not _deep(v):
                self.state.mixed = True
        else:   # an attribute
            self.value(target.value, use=False)
            self.hold("store")

    def aug_assign(self, node):
        target = node.target
        v = self.value(node.value)
        if not isinstance(target, ast.Name):
            self.store(target, v)
            return
        current = self.lookup(target.id)
        folded = lit(ast.BinOp(left=ast.Constant(current[1]), op=node.op, right=node.value), self.env) \
            if current[0] == "lit" else _MISSING
        if folded is not _MISSING:
            self.bind(target.id, ("lit", folded))
            return
        if not _deep(v):
            self.state.mixed = True   # `items += [x]` puts x inside the list
        plain = _plain(current) and _plain(v)
        self.bind(target.id, self.made(ANY, _deep(current) and _deep(v)) if plain else UNKNOWN)

    def function(self, node):
        for d in node.decorator_list:
            self.decorator(d)
        self.defaults(node.args)
        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, node.args.vararg,
                    node.args.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.types(arg.annotation)
        if node.returns is not None:
            self.types(node.returns)
        self.type_params(node)
        self.later(lambda: self.block(node.body))
        self.bind(node.name, FUNC)

    def class_def(self, node):
        """Only a plain class: no decorator, keyword or type parameter, no base but `object`, and a body of plain
        `def`s. A base's methods, a metaclass or a decorator run code the class names but the reader does not."""
        plain = not node.decorator_list and not node.keywords and not getattr(node, "type_params", None) \
            and all(isinstance(b, ast.Name) and b.id == "object" for b in node.bases) \
            and all(isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and not stmt.decorator_list
                    or isinstance(stmt, ast.Pass)
                    or isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) for stmt in node.body)
        if not plain:
            self.hold("class")
        for part in node.decorator_list + node.bases + [kw.value for kw in node.keywords]:
            self.value(part, use=False)
        self.type_params(node)
        outer = self.scope
        self.scope = self.snapshot()   # the body runs now, in a namespace of its own that ends with the class
        try:
            self.block(node.body)
        finally:
            self.scope = outer
        self.bind(node.name, FUNC)

    def type_params(self, node):
        """PEP 695 bounds and defaults are lazy, but a cell can force them through `__bound__`; read them."""
        for param in getattr(node, "type_params", ()):
            for part in (getattr(param, "bound", None), getattr(param, "default_value", None)):
                if part is not None:
                    self.types(part)

    def defaults(self, args):
        for d in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
            self.value(d)

    def decorator(self, node):
        """A decorator is called with what it decorates: only a builtin wrapper or a function the cell defines."""
        v = self.callee(node) if isinstance(node, (ast.Name, ast.Attribute)) else self.value(node)
        if not (v[0] == "func" or v[0] == "builtin" and v[1] in _DECORATORS):
            self.hold("value")

    def later(self, read):
        """Read a body that runs later (a function, lambda or generator): it trusts none of the cell's names."""
        saved = self.scope, self.frames, self.deferred
        self.scope, self.frames, self.deferred = {}, [], True
        try:
            read()
        finally:
            self.scope, self.frames, self.deferred = saved

    def types(self, node):
        """A class an `except` clause, `isinstance`, an annotation, a base or `raise` names: it is compared, stored
        or raised, not handed to something that calls it."""
        if isinstance(node, ast.Tuple):
            for elt in node.elts:
                self.types(elt)
        elif isinstance(node, ast.Name):
            if self.lookup(node.id)[0] == "harness":
                self.hold("value")
        elif isinstance(node, ast.Attribute):
            v = self.callee(node)
            if not (v[0] == "known" and (v[1] in INERT_CALLS or v[1] in INERT_TYPES)):
                self.hold("value")
        elif isinstance(node, ast.Subscript):
            self.types(node.value)
            self.types(node.slice)
        elif isinstance(node, ast.BinOp):
            self.types(node.left)
            self.types(node.right)
        elif not isinstance(node, ast.Constant):
            self.value(node)

    # --- expressions ---
    def value(self, node, use=True):
        """Read an expression in the order it runs and return what it evaluates to. `use`: the value is handed on
        (passed, stored, returned, compared), so a callable the reader knows, a module or a harness object is held."""
        if not self._charge(1):
            return UNKNOWN
        v = self._value(node)
        if use and v[0] in _NOT_VALUES:
            self.hold("value")
        return v

    def _value(self, node):
        if isinstance(node, ast.Constant):
            folded = lit(node, self.env)
            return _of(node.value) if folded is _MISSING else ("lit", folded)
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, ast.Attribute):
            return self.attribute(node)
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.Subscript):
            base = self.value(node.value)
            self.value(node.slice)
            p = _plain(base)
            if p and isinstance(node.slice, ast.Slice):
                return ("plain", p[0], p[1])   # a slice of plain data is plain data of its type
            return _item(base)
        if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr)):
            return self.operation(node)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [self.value(e.value if isinstance(e, ast.Starred) else e) for e in node.elts]
            kind = list if isinstance(node, ast.List) else tuple if isinstance(node, ast.Tuple) else set
            return self.made(frozenset({kind}), all(map(_deep, values)))
        if isinstance(node, ast.Dict):
            values = [self.value(k) for k in node.keys if k is not None] + [self.value(v) for v in node.values]
            return self.made(frozenset({dict}), all(map(_deep, values)))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return self.comprehension(node)
        if isinstance(node, ast.Lambda):
            self.defaults(node.args)
            self.later(lambda: self.value(node.body))
            return FUNC
        for child in ast.iter_child_nodes(node):   # Starred, Await, Yield, Slice and the like
            if isinstance(child, ast.expr):
                self.value(child)
        return UNKNOWN

    def operation(self, node):
        if isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    parts.append(self.value(part.value))
                    if part.format_spec is not None:
                        self.value(part.format_spec)
            folded = lit(node, self.env)
            if folded is not _MISSING:
                return ("lit", folded)
            return ("plain", frozenset({str}), True) if all(map(_plain, parts)) else UNKNOWN
        if isinstance(node, ast.Compare):
            parts = [self.value(node.left)] + [self.value(c) for c in node.comparators]
            return ("plain", frozenset({bool}), True) if all(map(_plain, parts)) else UNKNOWN
        if isinstance(node, (ast.BoolOp, ast.IfExp)):
            # the result is one of the operands, the same object: plain only when each operand holds plain data only
            if isinstance(node, ast.IfExp):
                self.value(node.test)
            parts = [self.value(v) for v in (node.values if isinstance(node, ast.BoolOp) else (node.body, node.orelse))]
            if not all(map(_deep, parts)):
                return UNKNOWN
            return ("plain", frozenset().union(*(_plain(p)[0] for p in parts)), True)
        parts = [self.value(node.operand)] if isinstance(node, ast.UnaryOp) else [self.value(node.left),
                                                                                  self.value(node.right)]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return ("plain", frozenset({bool}), True)
        folded = lit(node, self.env)
        if folded is not _MISSING:
            return ("lit", folded)
        plains = [_plain(p) for p in parts]
        return self.made(ANY, all(p[1] for p in plains)) if all(plains) else UNKNOWN

    def chain(self, node):
        """A name's or an attribute chain's value, not yet handed on."""
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, ast.Attribute):
            return self.attribute(node)
        return self.value(node, use=False)

    def attribute(self, node):
        """`base.name` read, not called: a module's name or constant, or plain data's data attribute."""
        if not self._charge(1):
            return UNKNOWN
        base = self.chain(node.value)
        if _dunder(node.attr):
            self.hold("dunder")
            return UNKNOWN
        if base[0] in ("module", "known"):
            return _resolve(f"{base[1]}.{node.attr}")
        if base[0] == "builtin":
            return ("builtin", f"{base[1]}.{node.attr}")
        p = _plain(base)
        if p and _allowed(PLAIN_DATA, p[0], node.attr):
            return _item(base)   # what it holds: plain only when the value holds plain data only (a datetime's tzinfo)
        self.hold("value")   # a method taken as a value, or an attribute of anything but plain data or a module
        return UNKNOWN

    def comprehension(self, node):
        """A list, set or dict comprehension runs here and now; a generator expression runs later, so past its first
        iterable it trusts none of the cell's names. Its targets are its own, plain when what they come from is."""
        generators = node.generators
        first = self.value(generators[0].iter)   # the first iterable is evaluated here, at once
        saved = self.deferred
        if isinstance(node, ast.GeneratorExp):
            self.deferred = True
        frame = {}
        self.frames.append(frame)
        try:
            for i, gen in enumerate(generators):
                items = first if i == 0 else self.value(gen.iter)
                self.target(gen.target, _item(items), frame)
                for condition in gen.ifs:
                    self.value(condition)
            if isinstance(node, ast.DictComp):
                parts = [self.value(node.key), self.value(node.value)]
            else:
                parts = [self.value(node.elt)]
        finally:
            self.frames.pop()
            self.deferred = saved
        if isinstance(node, ast.GeneratorExp):
            return FUNC
        kind = list if isinstance(node, ast.ListComp) else set if isinstance(node, ast.SetComp) else dict
        return self.made(frozenset({kind}), all(map(_deep, parts)))

    def target(self, target, item, frame):
        """Bind a comprehension's own target; a subscript or attribute target is a store like any other."""
        if isinstance(target, ast.Name):
            frame[target.id] = item
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.target(elt, item, frame)
        elif isinstance(target, ast.Starred):
            self.target(target.value, self.made(frozenset({list}), _deep(item)), frame)
        else:
            self.store(target, item)

    # --- calls: one decision table ---
    def callee(self, func):
        """What a call's callee stands for, reading what it evaluates: a name's value, a module's or a known
        callable's attribute, a builtin type's function, a method of plain data, or ("other", base)."""
        if isinstance(func, ast.Name):
            return self.lookup(func.id)
        if isinstance(func, ast.Attribute):
            base = self.chain(func.value)
            if _dunder(func.attr):
                self.hold("dunder")
                return UNKNOWN
            if base[0] in ("module", "known"):
                return _resolve(f"{base[1]}.{func.attr}")
            if base[0] == "builtin":
                return ("builtin", f"{base[1]}.{func.attr}")
            if _plain(base):
                return ("method", base, func.attr)
            return ("other", base)
        if isinstance(func, ast.Call) and isinstance(func.func, ast.Name) \
                and self.lookup(func.func.id) == ("builtin", "getattr"):
            name = lit(func.args[1], self.env) if len(func.args) == 2 else _MISSING
            if not isinstance(name, str) or func.keywords or isinstance(func.args[0], ast.Starred):
                return self.value(func, use=False)   # a name picked at run time: `getattr` holds it
            return self.callee(ast.Attribute(value=func.args[0], attr=name, ctx=ast.Load()))
        self.hold("call")   # a callee built at run time: a call's result, a subscript, ...
        self.value(func, use=False)
        return UNKNOWN

    def call(self, node):
        """Read one call: decide an action, leave a computation unread, or hold. Returns what it evaluates to."""
        self.state.count += 1
        if self.state.count > MAX_CALLS:
            self.hold("calls")
            self.state.stop = True
            return UNKNOWN
        if not self._charge(1):
            return UNKNOWN
        folded = lit(node, self.env)
        if isinstance(folded, str):
            return ("lit", folded)   # a literal join
        c = self.callee(node.func)
        kind = c[0]
        if kind == "builtin":
            return self.builtin_call(c[1], node)
        if kind == "known":
            return self.known_call(c[1], node)
        if kind == "method":
            return self.method_call(c[1], c[2], node)
        if kind == "harness" and c[1] in HELPERS:
            self.helper_call(HELPERS[c[1]], node)
        elif kind != "func":   # a function the cell defines: its body is read where it is defined
            self.hold("callee" if kind in ("harness", "unbound") else "call")
        self.arguments(node)
        return UNKNOWN

    def known_call(self, dotted, node):
        if dotted in DYNAMIC_CALLS:
            self.hold(dotted)
        elif dotted in SHELL_ARGV:
            self.argv_call(dotted, node)
        elif dotted in SHELL:
            self.shell_call(dotted, node)
        elif _helper(dotted) is not None:
            self.helper_call(_helper(dotted), node)
        elif dotted in INERT_CALLS and not self.deferred:
            return self.result(dotted, *self.arguments(node, _CALLS_ARGS.get(dotted, ())))
        else:
            self.hold("call")   # outside the inert list, or a module call in a body that runs later
        self.arguments(node)
        return UNKNOWN

    def builtin_call(self, name, node):
        if "." in name:   # a builtin type's own function, `str.join`
            if name not in BUILTIN_ATTRS:
                self.hold("call")
            pos, kws = self.arguments(node)
            return self.made(ANY, True) if all(map(_deep, pos + list(kws.values()))) else UNKNOWN
        if name in ("getattr", "hasattr"):
            return self.reflection(name, node)
        if name in _HELD_BUILTINS:
            self.hold(name)
        elif name == "open" and not self.reads_only(node):
            self.hold("open")
        elif name == "print" and any(kw.arg in ("file", None) for kw in node.keywords):
            self.hold("print")   # print writes to the file it is handed
        return self.result(name, *self.arguments(node, _CALLS_ARGS.get(name, ()), _TYPE_ARGS.get(name)))

    def method_call(self, base, name, node):
        types, deep = _plain(base)
        if not _allowed(PLAIN_METHODS, types, name):
            self.hold("call")   # not one of the plain type's own methods
            self.arguments(node)
            return UNKNOWN
        positions = _METHOD_CALLS_ARGS.get(name, ())
        pos, kws = self.arguments(node, positions)
        handed = [v for i, v in enumerate(pos) if i not in positions] + [
            v for k, v in kws.items() if k not in positions]
        args_deep = all(map(_deep, handed))
        if name in _INSERTING and not args_deep:
            self.state.mixed = True   # puts a value the reader can't follow inside a container
        if name in _ELEMENT:
            return ("plain", ANY, True) if deep and args_deep else UNKNOWN
        if name in _VIEWS:
            return self.made(frozenset({_Iter}), deep and args_deep)
        return self.made(ANY, deep and args_deep)

    def arguments(self, node, positions=(), types_at=None):
        """Read a call's arguments as values handed on; where the callee calls what it is handed, only a function the
        cell defines or plain data may stand. Returns (positional values, keyword values)."""
        pos, kws = [], {}
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Starred):
                if positions:
                    self.hold("value")
                pos.append(self.value(arg.value))
            elif i == types_at:
                self.types(arg)
                pos.append(UNKNOWN)
            else:
                pos.append(self.callable_arg(arg) if i in positions else self.value(arg))
        for kw in node.keywords:
            if kw.arg is None and positions:
                self.hold("value")
            kws[kw.arg] = self.callable_arg(kw.value) if kw.arg in positions else self.value(kw.value)
        return pos, kws

    def callable_arg(self, node):
        if isinstance(node, (ast.List, ast.Tuple)):   # a lexicon of (pattern, action) pairs
            for elt in node.elts:
                self.callable_arg(elt)
            return ("plain", frozenset({list}), False)
        v = self.value(node)
        if v[0] != "func" and not _plain(v):
            self.hold("value")   # a callable the reader can't follow, handed to something that calls it
        return v

    def result(self, name, pos, kws):
        keywords = all(k is not None and _deep(v) for k, v in kws.items())
        if name in FRESH_CALLS:
            return self.made(ANY, True) if keywords else UNKNOWN
        if name in _BUILT:
            items = pos + [v for k, v in kws.items() if k not in ("key", "reverse")]
            return self.made(frozenset({_BUILT[name]}), all(map(_deep, items)))
        if name in PURE_CALLS:
            return self.made(ANY, True) if keywords and all(map(_deep, pos)) else UNKNOWN
        return UNKNOWN

    def reads_only(self, node):
        """`open` with a literal read mode and no opener: it reads, and writes nothing."""
        mode = node.args[1] if len(node.args) > 1 else next((kw.value for kw in node.keywords if kw.arg == "mode"),
                                                            None)
        return len(node.args) <= 2 and not any(isinstance(a, ast.Starred) for a in node.args) \
            and all(kw.arg in ("encoding", "errors", "newline", "mode") for kw in node.keywords) \
            and (mode is None or lit(mode, self.env) in _READ_MODES)

    def reflection(self, name, node):
        """`getattr(base, "name")` reads as `base.name`; a name picked at run time is held."""
        attr = lit(node.args[1], self.env) if len(node.args) > 1 else _MISSING
        if not isinstance(attr, str) or len(node.args) > 3 or node.keywords \
                or any(isinstance(a, ast.Starred) for a in node.args):
            self.hold("getattr")
            self.arguments(node)
            return UNKNOWN
        v = self.value(ast.Attribute(value=node.args[0], attr=attr, ctx=ast.Load()), use=name == "getattr")
        for arg in node.args[2:]:
            self.value(arg)
        return ("plain", frozenset({bool}), True) if name == "hasattr" else v

    def argv_call(self, dotted, node):
        argv = self._argv(dotted, node)
        if argv is None:
            self.hold("argv")
            return
        self.calls.append(("shell", {"command": argv}))

    def _argv(self, dotted, node):
        if node.keywords or any(isinstance(a, ast.Starred) for a in node.args):
            return None
        args = node.args
        program = None   # the path the call runs, where it is separate from the argv list
        if dotted in _SPAWNL:
            program = lit(args[1], self.env) if len(args) > 1 else _MISSING
            nodes = args[2:]
        elif dotted in _EXECL:
            program = lit(args[0], self.env) if args else _MISSING
            nodes = args[1:]
        elif dotted in _SPAWNV:
            program = lit(args[1], self.env) if len(args) > 1 else _MISSING
            nodes = args[2:3]
        elif dotted == "asyncio.create_subprocess_exec":
            nodes = args
        elif dotted == "pty.spawn":
            nodes = args[:1]
        else:   # exec*, posix_spawn*
            program = lit(args[0], self.env) if args else _MISSING
            nodes = args[1:2]
        if program is not None and not isinstance(program, str):
            return None   # the program the argv runs is not the literal the reader saw
        if len(nodes) == 1 and isinstance(nodes[0], (ast.List, ast.Tuple)):
            nodes = nodes[0].elts
        values = [lit(e, self.env) for e in nodes]
        if not values or any(not isinstance(v, str) for v in values):
            return None
        if program is not None:
            values = [program] + values[1:]   # the path, not a caller-chosen argv[0], is what runs
        return values

    def helper_call(self, helper, node):
        args = self.bind_args(node, helper)
        if args is None:
            return
        if helper.secret:
            args["text"] = f"<secret>{args['text']}</secret>"
        if helper.tool.startswith("browser_use:"):
            args["page_url"] = ""
        self.calls.append((helper.tool, args))

    def bind_args(self, node, helper):
        values = {}
        for i, param in enumerate(helper.params):
            if i < len(node.args):
                if isinstance(node.args[i], ast.Starred):
                    self.hold("arg")
                    return None
                values[param] = node.args[i]
        for kw in node.keywords:
            if kw.arg is None or kw.arg not in helper.params or kw.arg in values:
                self.hold("arg")
                return None
            values[kw.arg] = kw.value
        for param in helper.params:
            if param not in values and param in helper.defaults:
                values[param] = helper.defaults[param]
        args = {}
        for param, name in helper.out.items():
            value = values.get(param, _MISSING)
            value = lit(value, self.env) if isinstance(value, ast.AST) else value
            if value is _MISSING or not isinstance(value, str):
                self.hold("arg")
                return None
            args[name] = value
        return args

    def shell_call(self, dotted, node):
        key = SHELL[dotted]
        arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == key), None)
        if arg is None or isinstance(arg, ast.Starred) \
                or any(kw.arg is None or (node.args and kw.arg == key) for kw in node.keywords):
            self.hold("arg")
            return
        shell = True
        if dotted.startswith("subprocess.") and dotted not in ("subprocess.getoutput", "subprocess.getstatusoutput"):
            shell_node = next((kw.value for kw in node.keywords if kw.arg == "shell"), None)
            shell = lit(shell_node, self.env) if shell_node is not None else False
            if not isinstance(shell, bool):
                self.hold("arg")
                return
        if isinstance(arg, (ast.List, ast.Tuple)):
            argv = [lit(e, self.env) for e in arg.elts]
            if not argv or any(not isinstance(v, str) for v in argv):
                self.hold("argv")
                return
            self.calls.append(("shell", {"command": argv}))
            return
        command = lit(arg, self.env)
        if not isinstance(command, str):
            self.hold("command")
            return
        if dotted.startswith("subprocess.") and not shell:
            self.hold("program")
            return
        self.calls.append(("shell", {"command": command}))


def _bindings(node, local):
    """(name, in a scope of its own) for each name `node` binds outside an import: a parameter or a comprehension
    target binds in its own scope only."""
    if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
        yield node.id, id(node) in local
    elif isinstance(node, ast.arg):
        yield node.arg, True
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        yield node.name, False
    elif isinstance(node, ast.ExceptHandler) and node.name or isinstance(node, _CAPTURES) and node.name:
        yield node.name, False
    elif _MATCH is not None and isinstance(node, ast.MatchMapping) and node.rest:
        yield node.rest, False
    elif isinstance(node, (ast.Global, ast.Nonlocal)):
        for name in node.names:
            yield name, False


def _over(value):
    """A literal longer than MAX_SUBJECT bytes: the reader stops resolving it, so no value grows past the limit."""
    return len(value) > MAX_SUBJECT or (len(value) > MAX_SUBJECT // 4
                                        and len(value.encode("utf-8", "surrogatepass")) > MAX_SUBJECT)


def lit(node, env):
    """The literal value `node` evaluates to without running code, or _MISSING. Names resolve only to values assigned
    before the call was reached; a value longer than MAX_SUBJECT is not resolved."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, (str, int, float, bool, type(None))) else _MISSING
    if isinstance(node, ast.Name):
        return env.get(node.id, _MISSING)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = lit(node.left, env), lit(node.right, env)
        if a is not _MISSING and b is not _MISSING and type(a) is type(b) and isinstance(a, (str, int, float)):
            value = a + b
            return _MISSING if isinstance(value, str) and _over(value) else value
        return _MISSING
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        v = lit(node.operand, env)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return -v if isinstance(node.op, ast.USub) else v
        return _MISSING
    if isinstance(node, ast.JoinedStr):
        parts, size = [], 0
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return _MISSING
                value = value.value
            v = lit(value, env)
            if not isinstance(v, str):
                return _MISSING
            size += len(v.encode("utf-8", "surrogatepass"))
            if size > MAX_SUBJECT:
                return _MISSING
            parts.append(v)
        return "".join(parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
        sep = lit(node.func.value, env)
        values = [lit(e, env) for e in node.args[0].elts]
        if isinstance(sep, str) and all(isinstance(v, str) for v in values):
            size = sum(len(v.encode("utf-8", "surrogatepass")) for v in values) \
                + len(sep.encode("utf-8", "surrogatepass")) * max(0, len(values) - 1)
            if size > MAX_SUBJECT:
                return _MISSING
            return sep.join(values)
    return _MISSING
