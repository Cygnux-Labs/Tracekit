"""Read the calls a Browser Use 1.x `python` cell or `finish_from_repl` delivery makes, from its source.

The signer decides one call per cell. This module reads the source with `ast.parse` (never compile or exec), maps
each literal helper or command call to the action it stands for, and leaves the engine to decide each and take the
strictest; a function or lambda body is read where it is defined. A source it cannot follow, a name the cell can rebind
or reach indirectly, and an unmapped network, process or FFI import are held as TK-SOURCE-PARSE. Ordinary Python the policy has no action for
(`open`, a plain stdlib call) is left unread; docs/limits.md says what that leaves out.
"""
import ast
import builtins

from . import shell

MAX_SOURCE = 64 * 1024   # bytes of UTF-8; a longer cell or delivery is held, not cut
MAX_SUBJECT = 64 * 1024  # bytes of UTF-8; no literal the reader resolves is longer (the engine's subject limit)
MAX_CALLS = 256          # calls read for one decision; nested readers share this counter
MAX_DEPTH = 3            # nested exec/eval: the cell, then three levels of literal code

_MISSING = object()
REFLECTION = {"globals", "locals", "vars"}
DYNAMIC_CALLS = {"__import__", "importlib.import_module"}
SETATTR = {"setattr", "delattr"}
# an import of one of these, used or not, leaves what it can run out of the reader's sight (requests and httpx are
# third-party; the rest are standard library and still held, to keep the set closed)
HELD_IMPORTS = {"urllib", "http", "socket", "requests", "httpx", "aiohttp", "ctypes", "multiprocessing"}
_BUILTINS = frozenset(dir(builtins))
_HELPER_MODULES = ("browser_harness.helpers.", "helpers.")


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


_TRY = tuple(c for c in (ast.Try, getattr(ast, "TryStar", None)) if c is not None)
_MATCH = getattr(ast, "Match", None)


class _State:
    """What every reader of one decision shares: the calls found, the call counter, the stop flag, and the budget."""

    def __init__(self, work=None):
        self.calls = []
        self.count = 0
        self.stop = False
        self.work = [0] if work is None else work


def read(code, mode="exec", depth=0, work=None):
    """(the calls a source names, why it is held or None): [(tool, args)]. Parse only; never run the source."""
    return Reader(code, mode, depth, state=_State(work)).run()


class _Reading:
    def __init__(self, calls, held):
        self.calls, self.held = calls, held


class Reader(ast.NodeVisitor):
    def __init__(self, code, mode="exec", depth=0, state=None, scope=None, force_conditional=False):
        self.code, self.mode, self.depth, self.state = code, mode, depth, state or _State()
        if scope is None:
            self.env, self.aliases = {}, {}
            self.defined, self.dynamic, self.shadowed, self.never = set(), set(), set(), set()
        else:
            self.env, self.aliases, self.defined, self.dynamic, self.shadowed, self.never = scope
        self.held = None
        self.force_conditional = force_conditional
        self.in_conditional = force_conditional

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
        # `global`/`nonlocal`: a name that may be written from a function is never a literal or an alias
        for sub in ast.walk(tree):
            if isinstance(sub, (ast.Global, ast.Nonlocal)):
                self.never.update(sub.names)
        for name in self.never:
            self._forget(name)
        try:
            self.visit(tree)
        except Exception:   # a nesting too deep or an unusual node: held, never raised into the signer
            self.hold("unreadable")
        return _Reading(self.state.calls, self.held)

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

    def _save(self):
        return self.env, self.aliases, self.defined, self.dynamic, self.shadowed, self.never

    def _scope(self):
        """Copy the names into a scope of its own (a function, a class body, a comprehension), on the budget: each
        copy costs the names it copies, so many scopes over many names hold the source rather than stall it."""
        saved = self._save()
        if not self._charge(sum(map(len, saved))):
            return None
        self.env, self.aliases = dict(self.env), dict(self.aliases)
        self.defined, self.dynamic, self.shadowed, self.never = (set(self.defined), set(self.dynamic),
                                                                 set(self.shadowed), set(self.never))
        return saved

    def _restore(self, saved):
        self.env, self.aliases, self.defined, self.dynamic, self.shadowed, self.never = saved

    # --- statements: read calls in the order they run, so a name only resolves to a value assigned before it ---
    def visit_Module(self, node):
        self.stmts(node.body)

    def visit_Expression(self, node):
        self.visit(node.body)

    def stmts(self, body, conditional=False):
        saved = self.in_conditional
        self.in_conditional = self.in_conditional or conditional
        try:
            for stmt in body:
                if self.state.stop:
                    return
                self.stmt(stmt, conditional)
        finally:
            self.in_conditional = saved

    def stmt(self, node, conditional=False):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self.bind_import(node)
        elif isinstance(node, ast.Assign):
            if not self._alias_value(node.value):
                self.visit(node.value)
            self.bind_targets(node.targets, node.value, conditional)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                if not self._alias_value(node.value):
                    self.visit(node.value)
                self.bind_targets([node.target], node.value, conditional)
            else:
                self.visit_target(node.target)   # a non-simple target is evaluated even without a value
            self.visit(node.annotation)   # a module or class annotation is evaluated, so its calls are the cell's
        elif isinstance(node, ast.AugAssign):
            self.visit(node.value)
            self.aug_assign(node, conditional)
        elif isinstance(node, ast.Expr):
            self.visit(node.value)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.visit_FunctionDef(node)
        elif isinstance(node, ast.ClassDef):
            self.visit_ClassDef(node)
        elif isinstance(node, ast.If):
            test = lit(node.test, self.env)
            self.visit(node.test)
            if test is True:
                self.stmts(node.body, conditional)
            elif test is False:
                self.stmts(node.orelse, conditional)
            else:
                self.stmts(node.body, True)
                self.stmts(node.orelse, True)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.visit(node.iter)
            self.bind_targets([node.target], None, True)
            self.stmts(node.body, True)
            self.stmts(node.orelse, True)
        elif isinstance(node, ast.While):
            test = lit(node.test, self.env)
            self.visit(node.test)
            if test is not False:
                self.stmts(node.body, True)
            self.stmts(node.orelse, True if test is not False else conditional)   # runs once the test is false
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.visit(item.context_expr)
                if item.optional_vars is not None:
                    self.bind_targets([item.optional_vars], None, True)
            self.stmts(node.body, True)
        elif isinstance(node, _TRY):
            self.stmts(node.body, True)
            for handler in node.handlers:
                if handler.type is not None:
                    self.visit(handler.type)
                if handler.name:
                    self.dynamic.add(handler.name)
                self.stmts(handler.body, True)
            self.stmts(node.orelse, True)
            self.stmts(node.finalbody, True)
        elif _MATCH is not None and isinstance(node, _MATCH):
            self.visit(node.subject)
            for case in node.cases:
                self._forget_pattern(case.pattern)
                if case.guard is not None:
                    self.visit(case.guard)
                self.stmts(case.body, True)
        elif isinstance(node, ast.Delete):
            self.bind_targets(node.targets, None, True)
        else:
            self.generic_visit(node)   # Return, Yield, Assert, Raise, ...: read the calls their expressions name

    def visit_defaults(self, args):
        for d in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
            self.visit(d)

    def bind_import(self, node):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in HELD_IMPORTS:
                    self.hold("import")
                name = a.asname or a.name.split(".")[0]
                self.aliases[name] = a.name if a.asname else a.name.split(".")[0]
                self._clear(name)
        else:
            base = node.module or ""
            if base.split(".")[0] in HELD_IMPORTS:
                self.hold("import")
            for a in node.names:
                if a.name == "*":
                    continue
                name = a.asname or a.name
                self.aliases[name] = f"{base}.{a.name}" if base else a.name
                self.env.pop(name, None)
                self._clear(name)

    def _clear(self, name):
        self.dynamic.discard(name)
        self.defined.discard(name)
        self.shadowed.discard(name)

    def _forget(self, name):
        """A name whose value the reader cannot follow: never a literal, never an alias."""
        self.dynamic.add(name)
        self.env.pop(name, None)
        self.aliases.pop(name, None)
        self.shadowed.add(name)

    def _forget_pattern(self, pattern):
        for sub in ast.walk(pattern):
            name = (sub.name if isinstance(sub, (ast.MatchAs, ast.MatchStar)) else
                    sub.rest if isinstance(sub, ast.MatchMapping) else None)
            if name:
                self._forget(name)

    def _alias_value(self, value):
        """A plain `name = helper` or `name = module.helper` keeps the helper readable under its new name."""
        return isinstance(value, (ast.Name, ast.Attribute)) and self.alias_of(value) is not None

    def bind_targets(self, targets, value, conditional):
        for target in targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                values = sequence(value, self.env) if value is not None else None
                if values is None or len(values) != len(target.elts) or any(isinstance(e, ast.Starred)
                                                                             for e in target.elts):
                    for elt in target.elts:
                        self.forget_target(elt)
                else:
                    for elt, v in zip(target.elts, values):
                        if isinstance(elt, ast.Name):
                            self.bind(elt.id, v, conditional, literal=True)
                        else:
                            self.forget_target(elt)
            elif isinstance(target, ast.Name):
                self.bind(target.id, value, conditional)
            else:
                self.forget_target(target)

    def visit_target(self, target):
        """Read the expressions a target evaluates without binding or forgetting anything."""
        if isinstance(target, ast.Starred):
            self.visit_target(target.value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.visit_target(elt)
        elif isinstance(target, ast.Attribute):
            self.visit(target.value)
        elif isinstance(target, ast.Subscript):
            self.visit(target.value)
            self.visit(target.slice)

    def forget_target(self, target):
        """Forget the names a target binds and read the expressions it evaluates: a subscript's base and index and
        an attribute's base run before the store, so a call inside one is a call the cell makes."""
        if isinstance(target, ast.Starred):
            self.forget_target(target.value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.forget_target(elt)
        elif isinstance(target, ast.Name):
            self.bind(target.id, None, True)
        elif isinstance(target, ast.Attribute):
            # `helpers.press_key = ...` rebinds what the dotted name reaches, and the helper it names
            dotted = self.name(target)
            if dotted:
                self._forget_dotted(dotted)
            self.visit(target.value)
        elif isinstance(target, ast.Subscript):
            self.visit(target.value)
            self.visit(target.slice)

    def _forget_dotted(self, dotted):
        self._forget(dotted)
        for prefix in _HELPER_MODULES:
            if dotted.startswith(prefix):
                self._forget(dotted[len(prefix):])

    def bind(self, name, value, conditional=False, literal=False):
        self.defined.discard(name)
        if name in self.never or conditional or self.force_conditional:
            self._forget(name)
            return
        if value is None:
            self._forget(name)
            return
        if isinstance(value, ast.Lambda):
            self.bind_defined(name)
            return
        alias = self.alias_of(value) if not literal else None
        if alias is not None:
            self.aliases[name] = alias
            self.env.pop(name, None)
            self._clear(name)
            return
        v = value if literal else lit(value, self.env)
        if v is not _MISSING and not isinstance(v, (list, tuple, dict, set)):
            self.env[name] = v
            self.aliases.pop(name, None)
            self.dynamic.discard(name)
            self.shadowed.add(name)
        else:
            self._forget(name)

    def bind_defined(self, name):
        self.defined.add(name)
        self.dynamic.discard(name)
        self.env.pop(name, None)
        self.aliases.pop(name, None)
        self.shadowed.add(name)

    def aug_assign(self, node, conditional):
        if isinstance(node.target, ast.Attribute):
            dotted = self.name(node.target)
            if dotted:
                self._forget_dotted(dotted)
            self.visit(node.target.value)
            return
        if isinstance(node.target, ast.Subscript):
            self.visit(node.target.value)
            self.visit(node.target.slice)
            return
        if not isinstance(node.target, ast.Name):
            return
        name = node.target.id
        if not conditional and isinstance(node.op, ast.Add) and name in self.env and name not in self.never:
            v = lit(ast.BinOp(left=ast.Constant(self.env[name]), op=ast.Add(), right=node.value), self.env)
            if v is not _MISSING and not isinstance(v, (list, tuple, dict, set)):
                self.env[name] = v
                return
        self.bind(name, None, True)

    def alias_of(self, node):
        dotted = self.name(node)
        if dotted is None or dotted in self.dynamic or dotted in self.defined or dotted in self.never:
            return None
        return dotted if self.known(dotted) else None

    # --- expressions: calls ---
    def visit_Call(self, node):
        consumed = self.call(node)
        if self.state.stop:
            return
        if not consumed:
            self.generic_visit(node)
            return
        for arg in node.args:
            self.visit(arg)
        for kw in node.keywords:
            self.visit(kw.value)

    def visit_Name(self, node):
        dotted = self.name(node)
        if dotted is not None and dotted not in self.defined and not self.is_dynamic(dotted) \
                and self.known(dotted):
            self.hold("value")   # a helper or command used as a value, not as the callee of this call

    def visit_Attribute(self, node):
        dotted = self.name(node)
        for candidate in (dotted, self.name(node.value)):
            if candidate is not None and candidate not in self.defined and not self.is_dynamic(candidate) \
                    and self.known(candidate):
                self.hold("value")
                return
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.bind(node.target.id, None, True)

    def _function_scope(self, args, body):
        saved = self._scope()
        if saved is None:
            return
        self.env = {}
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
            self.bind(arg.arg, None, True)
        for arg in (args.vararg, args.kwarg):
            if arg is not None:
                self.bind(arg.arg, None, True)
        try:
            body()
        finally:
            self._restore(saved)

    def _type_params(self, node):
        """PEP 695 bounds and defaults are lazy, but a cell can force them through `__bound__`; read them."""
        for param in getattr(node, "type_params", ()):
            for part in (getattr(param, "bound", None), getattr(param, "default_value", None)):
                if part is not None:
                    self.visit(part)

    def _annotations(self, args, returns):
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.visit(arg.annotation)
        if returns is not None:
            self.visit(returns)

    def visit_FunctionDef(self, node):
        self.bind_defined(node.name)
        for d in node.decorator_list:
            self.visit(d)
        self.visit_defaults(node.args)
        self._annotations(node.args, node.returns)   # evaluated at `def`, in the enclosing names
        self._type_params(node)
        # the body runs when called: its calls are read whether or not this cell calls it
        self._function_scope(node.args, lambda: self.stmts(node.body))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bind_defined(node.name)
        for d in node.decorator_list + node.bases + [k.value for k in node.keywords]:
            self.visit(d)
        self._type_params(node)
        # the body runs at definition time, in a namespace of its own that ends with the class
        saved = self._scope()
        if saved is None:
            return
        try:
            self.stmts(node.body)
        finally:
            self._restore(saved)

    def visit_Lambda(self, node):
        self.visit_defaults(node.args)
        self._function_scope(node.args, lambda: self.visit(node.body))

    def _comprehension(self, node, elts):
        generators = node.generators
        self.visit(generators[0].iter)   # the first iterable runs in the enclosing scope
        saved = self._scope()
        if saved is None:
            return
        try:
            for i, gen in enumerate(generators):
                if i:
                    self.visit(gen.iter)
                self.bind_targets([gen.target], None, True)
                for condition in gen.ifs:
                    self.visit(condition)
            for elt in elts:
                self.visit(elt)
        finally:
            self._restore(saved)
        for sub in ast.walk(node):   # `:=` in a comprehension binds in the enclosing scope (PEP 572)
            if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                self.bind(sub.target.id, None, True)

    def visit_ListComp(self, node):
        self._comprehension(node, [node.elt])

    def visit_SetComp(self, node):
        self._comprehension(node, [node.elt])

    def visit_GeneratorExp(self, node):
        self._comprehension(node, [node.elt])

    def visit_DictComp(self, node):
        self._comprehension(node, [node.key, node.value])

    def call(self, node):
        """Read one call; True when its callee was taken (mapped, held, or a builtin/defined name to leave unread)."""
        self.state.count += 1
        if self.state.count > MAX_CALLS:
            self.hold("calls")
            self.state.stop = True
            return True
        if not self._charge(1):
            return True
        if isinstance(lit(node, self.env), str):
            return True   # a literal string expression (a `sep.join` of literals): its value is read where it is used
        func = node.func
        if isinstance(func, ast.Call):
            self.indirect(node, func)
            return True
        if isinstance(func, ast.Subscript):
            self.hold("call")
            return True
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
            return False   # a method on a call result (open(path).write(text)): ordinary Python, its inner call is read
        dotted = self.name(func)
        if dotted is None:
            self.hold("call")
            return True
        dotted = self.normalize(dotted)
        if self.is_dynamic(dotted):
            self.hold("call")
            return True
        if dotted == "getattr":
            self.reflection(node)
            return True
        if dotted in REFLECTION:
            self.hold(dotted)
            return True
        if dotted in SETATTR:
            self.hold(dotted)
            return True
        if dotted in ("exec", "eval"):
            self.nested(dotted, node)
            return True
        if dotted in DYNAMIC_CALLS:
            self.hold(dotted)
            return True
        if dotted in SHELL_ARGV:
            self.argv_call(dotted, node)
            return True
        if dotted in SHELL:
            self.shell_call(dotted, node)
            return True
        helper = self.helper(dotted)
        if helper is not None:
            self.helper_call(helper, node)
            return True
        if "." not in dotted:
            if dotted in self.defined or dotted in self.aliases or dotted in _BUILTINS:
                return True   # a builtin, or a function the cell defines and this reader already read
            self.hold("callee")   # a helper or action under a name this cell did not define: not followed
            return True
        return False   # an ordinary library call: left unread (its arguments are still read)

    def dispatch(self, dotted, node):
        """Read or hold a resolved literal callee; a name with no mapped action is ordinary Python, left unread."""
        if dotted in ("exec", "eval"):
            self.nested(dotted, node)
        elif dotted in DYNAMIC_CALLS or dotted in SETATTR:
            self.hold(dotted)
        elif dotted in SHELL_ARGV:
            self.argv_call(dotted, node)
        elif dotted in SHELL:
            self.shell_call(dotted, node)
        else:
            helper = self.helper(dotted)
            if helper is not None:
                self.helper_call(helper, node)

    def indirect(self, node, inner):
        """A call on a call result: `getattr(base, "name")(...)` is read when the name is literal; any other target
        built at run time is held."""
        if isinstance(inner.func, ast.Name) and self.name(inner.func) == "getattr":
            base = self.name(inner.args[0]) if inner.args else None
            name = lit(inner.args[1], self.env) if len(inner.args) > 1 else _MISSING
            if not isinstance(name, str) or not base:
                self.hold("getattr")
                return
            dotted = name if self.known(name) else f"{base}.{name}"
            dotted = self.normalize(dotted)
            if self.is_dynamic(dotted):
                self.hold("call")
                return
            if not self.known(dotted) and self.known(base):
                self.hold("value")   # an attribute of a helper or command, taken as a value
                return
            self.dispatch(dotted, node)
            return
        self.hold("call")

    def reflection(self, node):
        base = node.args[0] if node.args else None
        name = lit(node.args[1], self.env) if len(node.args) > 1 else _MISSING
        if not (isinstance(name, str) and base is not None and self.name(base)):
            self.hold("getattr")

    def nested(self, dotted, node):
        code = lit(node.args[0], self.env) if node.args else _MISSING
        if not isinstance(code, str):
            self.hold(dotted)
            return
        if node.keywords or len(node.args) > 1:
            self.hold("namespace")   # a namespace of its own: its names are not the cell's
            return
        if self.depth >= MAX_DEPTH:
            self.hold("depth")
            return
        # no namespace: the code runs in the cell's own names, and its assignments stay visible after the call
        nested = Reader(code, "exec" if dotted == "exec" else "eval", self.depth + 1, state=self.state,
                        scope=self._save(), force_conditional=self.in_conditional)
        reading = nested.run()
        if reading.held is not None:
            self.hold(reading.held)

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

    # --- names and literals ---
    def name(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.name(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def known(self, dotted):
        return self.helper(dotted) is not None or dotted in SHELL or dotted in SHELL_ARGV \
            or dotted in DYNAMIC_CALLS or dotted in SETATTR or dotted in ("exec", "eval", "getattr")

    def normalize(self, dotted):
        """A builtin spelled through the `builtins` module or the `__builtins__` dunder (`builtins.exec`,
        `__builtins__.exec`, or their aliases) reads as the builtin, unless the cell shadowed the name."""
        for prefix in ("builtins.", "__builtins__."):
            if dotted.startswith(prefix) and prefix[:-1] not in self.shadowed \
                    and prefix[:-1] not in self.defined and not self.is_dynamic(prefix[:-1]):
                return dotted[len(prefix):]
        return dotted

    def helper(self, dotted):
        if dotted in self.defined or dotted in self.shadowed:
            return None
        parts = dotted.split(".")
        if any(".".join(parts[:i + 1]) in self.shadowed for i in range(len(parts) - 1)):
            return None
        for prefix in _HELPER_MODULES:
            if dotted.startswith(prefix):
                name = dotted[len(prefix):]
                return HELPERS.get(name)
        return HELPERS.get(dotted)

    def is_dynamic(self, dotted):
        parts = dotted.split(".")
        return any(".".join(parts[:i + 1]) in self.dynamic for i in range(len(parts)))


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


def sequence(node, env):
    """The literal values of a list or tuple literal, or None when any element is not one."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values = [lit(e, env) for e in node.elts]
    return None if any(v is _MISSING for v in values) else values
