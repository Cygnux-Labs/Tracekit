"""Read the calls a Browser Use 1.x `python` cell or `finish_from_repl` delivery makes, from its source.

The signer decides one call per cell. This module reads the source with `ast.parse` (never compile or exec), maps
each literal helper or command call to the action it stands for, and leaves the engine to decide each and take the
strictest. A source it cannot follow is held as TK-SOURCE-PARSE. Ordinary Python the policy has no action for
(`open`, a third-party library, a function defined in the cell and called by name) is left unread; docs/limits.md
says what that leaves out.
"""
import ast

MAX_SOURCE = 64 * 1024   # bytes of UTF-8; a longer cell or delivery is held, not cut
MAX_CALLS = 256          # calls read from one source; a nested source is capped on its own
MAX_DEPTH = 3            # nested exec/eval: the cell, then three levels of literal code

_MISSING = object()
REFLECTION = {"globals", "locals", "vars"}
DYNAMIC_CALLS = {"__import__", "importlib.import_module"}
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
SHELL_ARGV = {"asyncio.create_subprocess_exec"}   # an argv list, which no shell rule reads
# the two Browser Use 1.x actions whose source this reads: the action -> (its argument, its parse mode)
CELLS = {"browser_use:python": ("code", "exec"), "browser_use:finish_from_repl": ("expression", "eval")}


_TRY = tuple(c for c in (ast.Try, getattr(ast, "TryStar", None)) if c is not None)
_MATCH = getattr(ast, "Match", None)


def read(code, mode="exec", depth=0):
    """(the calls a source names, why it is held or None): [(tool, args)]. Parse only; never run the source."""
    return Reader(code, mode, depth).run()


class _Reading:
    def __init__(self, calls, held):
        self.calls, self.held = calls, held


class Reader(ast.NodeVisitor):
    def __init__(self, code, mode="exec", depth=0, aliases=None, env=None):
        self.code, self.mode, self.depth = code, mode, depth
        self.aliases, self.env = dict(aliases or {}), dict(env or {})
        self.calls, self.held = [], None
        self.count = 0
        self.stop = False
        self.defined, self.dynamic, self.shadowed = set(), set(), set()

    def run(self):
        if not isinstance(self.code, str):
            self.hold("text")
            return _Reading(self.calls, self.held)
        if len(self.code.encode("utf-8", "surrogatepass")) > MAX_SOURCE:
            self.hold("size")
            return _Reading(self.calls, self.held)
        try:
            tree = ast.parse(self.code, mode=self.mode)
        except Exception as exc:   # SyntaxError, ValueError (a null byte), MemoryError, RecursionError: unread, never raised
            self.hold("syntax" if isinstance(exc, SyntaxError) else "unreadable")
            return _Reading(self.calls, self.held)
        try:
            self.visit(tree)
        except Exception:   # a nesting too deep or an unusual node: held, never raised into the signer
            self.hold("unreadable")
        return _Reading(self.calls, self.held)

    def hold(self, cause):
        if self.held is None:
            self.held = cause

    # --- statements: read calls in the order they run, so a name only resolves to a value assigned before it ---
    def visit_Module(self, node):
        self.stmts(node.body)

    def visit_Expression(self, node):
        self.visit(node.body)

    def stmts(self, body, conditional=False):
        for stmt in body:
            if self.stop:
                return
            self.stmt(stmt, conditional)

    def stmt(self, node, conditional=False):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self.bind_import(node)
        elif isinstance(node, ast.Assign):
            self.visit(node.value)
            self.bind_targets(node.targets, node.value, conditional)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.visit(node.value)
                self.bind_targets([node.target], node.value, conditional)
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
                self.stmts(node.orelse, True)
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
                name = a.asname or a.name.split(".")[0]
                self.aliases[name] = a.name if a.asname else a.name.split(".")[0]
                self._clear(name)
        else:
            base = node.module or ""
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

    def bind_targets(self, targets, value, conditional):
        for target in targets:
            if isinstance(target, (ast.Tuple, ast.List)):
                values = sequence(value, self.env) if value is not None else None
                if values is None or len(values) != len(target.elts) or any(isinstance(e, ast.Starred)
                                                                             for e in target.elts):
                    for elt in target.elts:
                        name = elt.value if isinstance(elt, ast.Starred) else elt
                        if isinstance(name, ast.Name):
                            self.bind(name.id, None, True)
                else:
                    for elt, v in zip(target.elts, values):
                        if isinstance(elt, ast.Name):
                            self.bind(elt.id, v, conditional, literal=True)
            elif isinstance(target, ast.Name):
                self.bind(target.id, value, conditional)
            # an attribute or subscript writes an object the reader does not follow

    def bind(self, name, value, conditional=False, literal=False):
        self.defined.discard(name)
        if conditional:
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
        if not isinstance(node.target, ast.Name):
            return
        name = node.target.id
        if not conditional and isinstance(node.op, ast.Add) and name in self.env:
            v = lit(ast.BinOp(left=ast.Constant(self.env[name]), op=ast.Add(), right=node.value), self.env)
            if v is not _MISSING and not isinstance(v, (list, tuple, dict, set)):
                self.env[name] = v
                return
        self.bind(name, None, True)

    def alias_of(self, node):
        dotted = self.name(node)
        if dotted is None or dotted in self.dynamic or dotted in self.defined:
            return None
        return dotted if self.known(dotted) else None

    # --- expressions: calls ---
    def visit_Call(self, node):
        self.call(node)
        if not self.stop:
            self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.bind(node.target.id, None, True)

    def visit_FunctionDef(self, node):
        self.bind_defined(node.name)
        for d in node.decorator_list:
            self.visit(d)
        self.visit_defaults(node.args)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bind_defined(node.name)
        for d in node.decorator_list + node.bases + [k.value for k in node.keywords]:
            self.visit(d)
        # the body runs at definition time, in a namespace of its own that ends with the class
        saved = self.env, self.aliases, self.dynamic, self.defined, self.shadowed
        self.env, self.aliases = dict(self.env), dict(self.aliases)
        self.dynamic, self.defined, self.shadowed = set(self.dynamic), set(self.defined), set(self.shadowed)
        self.stmts(node.body)
        self.env, self.aliases, self.dynamic, self.defined, self.shadowed = saved

    def visit_Lambda(self, node):
        # a lambda body runs only when called; a call on a lambda literal is held by call()
        self.visit_defaults(node.args)

    def call(self, node):
        self.count += 1
        if self.count > MAX_CALLS:
            self.hold("calls")
            self.stop = True
            return
        if isinstance(lit(node, self.env), str):
            return   # a literal string expression (a `sep.join` of literals): its value is read where it is used
        func = node.func
        if isinstance(func, ast.Call):
            self.indirect(node, func)
            return
        if isinstance(func, (ast.Subscript, ast.Lambda)):
            self.hold("call")
            return
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
            return   # a method on a call result (open(path).write(text)): ordinary Python, its inner call is read
        dotted = self.name(func)
        if dotted is None:
            self.hold("call")
            return
        dotted = self.normalize(dotted)
        if self.is_dynamic(dotted):
            self.hold("call")
            return
        if dotted == "getattr":
            self.reflection(node)
        elif dotted in REFLECTION:
            self.hold(dotted)
        else:
            self.dispatch(dotted, node)

    def dispatch(self, dotted, node):
        """Read or hold a resolved literal callee; a name with no mapped action is ordinary Python, left unread."""
        if dotted in ("exec", "eval"):
            self.nested(dotted, node)
        elif dotted in DYNAMIC_CALLS:
            self.hold(dotted)
        elif dotted in SHELL_ARGV:
            self.hold("argv")
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
        if self.depth >= MAX_DEPTH:
            self.hold("depth")
            return
        nested = Reader(code, "exec" if dotted == "exec" else "eval", self.depth + 1, self.aliases, self.env)
        reading = nested.run()
        self.calls.extend(reading.calls)
        if reading.held is not None:
            self.hold(reading.held)

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
            elif param in helper.defaults:
                values[param] = helper.defaults[param]
            elif param in helper.out:
                self.hold("arg")
                return None
        for kw in node.keywords:
            if kw.arg is None or kw.arg in values and kw.arg in helper.params:
                self.hold("arg")
                return None
            if kw.arg in helper.params:
                values[kw.arg] = kw.value
        args = {}
        for param, name in helper.out.items():
            value = values[param] if not isinstance(values.get(param), ast.AST) else lit(values[param], self.env)
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
            self.hold("argv" if dotted.startswith("subprocess.") or shell else "command")
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
        return self.helper(dotted) is not None or dotted in SHELL or dotted in SHELL_ARGV or dotted in DYNAMIC_CALLS \
            or dotted in ("exec", "eval", "getattr")

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


def lit(node, env):
    """The literal value `node` evaluates to without running code, or _MISSING. Names resolve only to values assigned
    before the call was reached; no call is evaluated except a literal `sep.join([...])` of literal strings."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, (str, int, float, bool, type(None))) else _MISSING
    if isinstance(node, ast.Name):
        return env.get(node.id, _MISSING)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = lit(node.left, env), lit(node.right, env)
        if a is not _MISSING and b is not _MISSING and type(a) is type(b) and isinstance(a, (str, int, float)):
            return a + b
        return _MISSING
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        v = lit(node.operand, env)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return -v if isinstance(node.op, ast.USub) else v
        return _MISSING
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return _MISSING
                value = value.value
            v = lit(value, env)
            if not isinstance(v, str):
                return _MISSING
            parts.append(v)
        return "".join(parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
            and len(node.args) == 1 and isinstance(node.args[0], (ast.List, ast.Tuple)):
        sep = lit(node.func.value, env)
        values = [lit(e, env) for e in node.args[0].elts]
        if isinstance(sep, str) and all(isinstance(v, str) for v in values):
            return sep.join(values)
    return _MISSING


def sequence(node, env):
    """The literal values of a list or tuple literal, or None when any element is not one."""
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    values = [lit(e, env) for e in node.elts]
    return None if any(v is _MISSING for v in values) else values
