/**
 * tracekit/policy2/linear.py's Pattern: a linear-time search for the patterns tracekit/policy2/compile.py check_pattern
 * accepts, with RE2's semantics, for the verifier's label patterns (labels.ts): a bundle's own policy may hold any
 * pattern, and JavaScript's RegExp backtracks, so a hostile one would hang the verifier. A pattern outside the subset
 * (translate's lexical rules, sre's syntax, a repeat of a repeat, nested repeat counts past 1000) throws PolicyError;
 * every search spends a Budget the verification shares and throws Spent when it runs out. A port kept in step with the
 * reference by tests/test_run_conditions.py.
 */
export class PolicyError extends Error {}
export class Spent extends Error {}

const MAX_REPEAT = 1000, MAX_PROGRAM = 20000;
export const STEPS = 20_000_000;
const ESCAPES = new Set("dDwWsSbBAntrfv"), CLASS_ESCAPES = new Set("dDwWsntrfv");
const CONTROL: Record<string, string> = { n: "\n", t: "\t", r: "\r", f: "\f", v: "\v" };
const isWord = (c: string) => /^[0-9A-Za-z_]$/.test(c);
const SPACE = "\t\n\f\r ";
const CATS: Record<string, (c: string) => boolean> = {
  d: (c) => c >= "0" && c <= "9", D: (c) => !(c >= "0" && c <= "9"), w: isWord, W: (c) => !isWord(c),
  s: (c) => SPACE.includes(c), S: (c) => !SPACE.includes(c),
};
const FOLDS: Record<string, string[]> = { "ſ": ["s", "S"], "K": ["k", "K"] };

export class Budget {
  left: number;
  constructor(public steps = STEPS) { this.left = steps; }
  spend(n: number) {
    this.left -= n;
    if (this.left < 0) throw new Spent(`the label patterns took more than ${this.steps} steps to replay`);
  }
}

type Test = (c: string) => boolean;
// sre's parse, as compile.check_pattern reads a pattern: a class's items (a literal's code point, a range, a category
// escape), and the nodes; `kind` of a character: lit (LITERAL), notlit (NOT_LITERAL), in and notin (IN, NEGATE first
// in notin), any (ANY). Two nodes with the same key are equal in sre's parse, as its branch optimizations compare them.
type Item = ["L", number] | ["R", number, number] | ["C", string];
type Char = { op: "char"; kind: "lit" | "notlit" | "in" | "notin" | "any"; items: Item[] };
type Node = Char | { op: "at"; kind: string } | { op: "group"; body: Node[] }
  | { op: "branch"; alts: Node[][] } | { op: "repeat"; min: number; max: number; body: Node[] };

const uniq = (items: Item[]) => [...new Map(items.map((x) => [JSON.stringify(x), x])).values()];
const key = (n: Node) => n.op === "char" ? n.kind + JSON.stringify(n.items) : n.op === "at" ? "@" + n.kind : null;

function charTest(n: Char): Test {
  if (n.kind === "any") return (x) => x !== "\n";
  const tests: Test[] = n.items.map((it) => it[0] === "L" ? (x) => x.codePointAt(0) === it[1]
    : it[0] === "R" ? (x) => x.codePointAt(0)! >= it[1] && x.codePointAt(0)! <= it[2] : CATS[it[1]]);
  const negate = n.kind === "notlit" || n.kind === "notin";
  return (x) => tests.some((t) => t(x)) !== negate;
}

/** sre's parse of a pattern translate() lets through, as Nodes; PolicyError for what either refuses. */
class Parser {
  i = 0;
  names = new Set<string>();
  constructor(readonly s: string[]) {}

  fail(why: string): never { throw new PolicyError(why); }

  /** sre's _parse_sub: the alternatives, their common first nodes moved out, and alternatives of one literal or class
   * each as one class. */
  alternation(): Node[] {
    const alts = [this.sequence()];
    while (this.s[this.i] === "|") {
      this.i++;
      alts.push(this.sequence());
    }
    if (alts.length === 1) return alts[0];
    const out: Node[] = [];
    while (alts.every((a) => a.length) && key(alts[0][0]) !== null && alts.every((a) => key(a[0]) === key(alts[0][0]))) {
      out.push(alts[0][0]);
      for (const a of alts) a.shift();
    }
    if (alts.every((a) => a.length === 1 && a[0].op === "char" && (a[0].kind === "lit" || a[0].kind === "in")))
      return [...out, { op: "char", kind: "in", items: uniq(alts.flatMap((a) => (a[0] as Char).items)) }];
    return [...out, { op: "branch", alts }];
  }

  sequence(): Node[] {
    const out: Node[] = [];
    while (this.i < this.s.length && this.s[this.i] !== "|" && this.s[this.i] !== ")") {
      const c = this.s[this.i];
      if ("*+?{".includes(c)) {
        const [min, max] = this.repeat();
        if (this.s[this.i] === "?") this.i++;   // lazy: the same whether it matches
        if (this.i < this.s.length && "*+?{".includes(this.s[this.i])) this.fail("multiple repeat");
        const last = out.pop();
        if (!last || last.op === "at") this.fail("nothing to repeat");
        if (last.op === "repeat") this.fail("multiple repeat");
        out.push({ op: "repeat", min, max, body: last.op === "group" ? last.body : [last] });
        continue;
      }
      out.push(this.atom());
    }
    return out;
  }

  repeat(): [number, number] {
    const c = this.s[this.i++];
    if (c === "*") return [0, Infinity];
    if (c === "+") return [1, Infinity];
    if (c === "?") return [0, 1];
    const m = /^\{(\d+)(,(\d*))?\}/.exec(this.s.slice(this.i - 1, this.i + 40).join(""));
    if (!m) this.fail("a literal { must be escaped, and a repeat needs a lower bound");
    this.i += m[0].length - 1;
    const min = Number(m[1]), max = m[2] === undefined ? min : m[3] === "" ? Infinity : Number(m[3]);
    if (max < min) this.fail("min repeat greater than max repeat");
    return [min, max];
  }

  atom(): Node {
    const c = this.s[this.i++];
    if (c === "(") {
      if (this.s[this.i] === "?") {
        if (this.s[this.i + 1] === ":") this.i += 2;
        else if (this.s[this.i + 1] === "P" && this.s[this.i + 2] === "<") {
          const end = this.s.indexOf(">", this.i + 3);
          const name = end < 0 ? "" : this.s.slice(this.i + 3, end).join("");
          // (Python's str.isidentifier, near enough: a letter or _, then letters, digits, marks or _)
          if (!/^[\p{L}\p{Nl}_][\p{L}\p{Nl}\p{Mn}\p{Mc}\p{Nd}\p{Pc}]*$/u.test(name))
            this.fail(`bad character in group name ${name}`);
          if (this.names.has(name)) this.fail(`redefinition of group name ${name}`);
          this.names.add(name);
          this.i = end + 1;
        } else this.fail("only (?: and (?P< groups are allowed (no flags, lookaround or comments)");
      }
      const body = this.alternation();
      if (this.s[this.i++] !== ")") this.fail("missing ), unterminated subpattern");
      return { op: "group", body };
    }
    if (c === ")") this.fail("unbalanced parenthesis");
    if (c === "[") return this.set();
    if (c === ".") return { op: "char", kind: "any", items: [] };
    if (c === "^") return { op: "at", kind: "begin" };
    if (c === "$") return { op: "at", kind: "end" };
    if (c === "\\") {
      const e = this.escape(false);
      return typeof e === "string" ? { op: "at", kind: e } : e[0] === "C" ? { op: "char", kind: "in", items: [e] }
        : { op: "char", kind: "lit", items: [e] };
    }
    return { op: "char", kind: "lit", items: [["L", c.codePointAt(0)!]] };
  }

  /** The class item an escape names; outside a class \A \b \B are the assertions "beginstr", "boundary",
   * "nonboundary". */
  escape(inClass: boolean): Item | string {
    const e = this.s[this.i++];
    if (e === undefined) this.fail("bad escape (end of pattern)");
    if (e === "x") {
      const h = this.s.slice(this.i, this.i + 2).join("");
      if (!/^[0-9a-fA-F]{2}$/.test(h)) this.fail("escape \\x is outside the RE2 subset");
      this.i += 2;
      return ["L", parseInt(h, 16)];
    }
    if (/^[0-9A-Za-z]$/.test(e) && !(inClass ? CLASS_ESCAPES : ESCAPES).has(e) || e.codePointAt(0)! > 127)
      this.fail(`escape \\${e} is outside the RE2 subset`);
    if (CONTROL[e]) return ["L", CONTROL[e].codePointAt(0)!];
    if (CATS[e]) return ["C", e];
    if (e === "A") return "beginstr";
    if (e === "b") return "boundary";
    if (e === "B") return "nonboundary";
    return ["L", e.codePointAt(0)!];   // punctuation, as itself
  }

  /** sre's character set: its items, each once; one literal is a literal (negated: notlit). */
  set(): Char {
    const negate = this.s[this.i] === "^";
    if (negate) this.i++;
    const items: Item[] = [];
    const one = (c: string): Item => {
      if (c === "[") this.fail("nested sets and [: :] classes are outside the RE2 subset; escape a literal [");
      return c === "\\" ? this.escape(true) as Item : ["L", c.codePointAt(0)!];
    };
    for (;;) {
      const c = this.s[this.i++];
      if (c === undefined) this.fail("unterminated character set");
      if (c === "]" && items.length) break;
      const lo = one(c);
      if (this.s[this.i] === "-" && this.s[this.i + 1] !== "]" && this.s[this.i + 1] !== undefined) {
        this.i++;
        const hi = one(this.s[this.i++]);
        if (lo[0] !== "L" || hi[0] !== "L" || hi[1] < lo[1]) this.fail("bad character range");
        items.push(["R", lo[1], hi[1]]);
      } else items.push(lo);
    }
    const u = uniq(items);
    return u.length === 1 && u[0][0] === "L" ? { op: "char", kind: negate ? "notlit" : "lit", items: u }
      : { op: "char", kind: negate ? "notin" : "in", items: u };
  }
}

/** compile.py _risky: an unbounded repeat whose body itself begins with an unbounded repeat ((a+)+). */
function risky(items: Node[]): boolean {
  const unbounded = (n: Node) => n.op === "repeat" && n.max === Infinity;
  const starts = (seq: Node[]): boolean => seq.length > 0 && (unbounded(seq[0]) || seq[0].op === "group"
    && starts((seq[0] as { body: Node[] }).body) || seq[0].op === "branch" && (seq[0] as { alts: Node[][] }).alts.some(starts));
  return items.some((n) => n.op === "repeat" ? unbounded(n) && starts(n.body) || risky(n.body)
    : n.op === "group" ? risky(n.body) : n.op === "branch" && n.alts.some(risky));
}

/** compile.py _walk: nested repeat counts multiply to at most MAX_REPEAT. */
function walk(items: Node[], room = MAX_REPEAT) {
  for (const n of items) {
    if (n.op === "repeat") {
      const count = n.max === Infinity ? n.min : n.max;
      if (count > room) throw new PolicyError(`repeat counts above ${MAX_REPEAT}, nested ones multiplied, are outside the RE2 subset`);
      walk(n.body, Math.floor(room / Math.max(count, 1)));
    } else if (n.op === "group") walk(n.body, room);
    else if (n.op === "branch") for (const a of n.alts) walk(a, room);
  }
}

type Ins = ["char", Test] | ["split", number, number] | ["jmp", number] | ["at", string] | ["match"];

function emit(items: Node[], prog: (Ins | null)[]) {
  for (const n of items) {
    if (prog.length > MAX_PROGRAM) throw new PolicyError(`the pattern compiles to more than ${MAX_PROGRAM} instructions`);
    if (n.op === "char") prog.push(["char", charTest(n)]);
    else if (n.op === "at") prog.push(["at", n.kind]);
    else if (n.op === "group") emit(n.body, prog);
    else if (n.op === "branch") {
      const ends: number[] = [];
      for (const alt of n.alts.slice(0, -1)) {
        const at = prog.length;
        prog.push(null);
        emit(alt, prog);
        ends.push(prog.length);
        prog.push(null);
        prog[at] = ["split", at + 1, prog.length];
      }
      emit(n.alts[n.alts.length - 1], prog);
      for (const at of ends) prog[at] = ["jmp", prog.length];
    } else {
      for (let k = 0; k < n.min; k++) emit(n.body, prog);
      if (n.max === Infinity) {
        const at = prog.length;
        prog.push(null);
        emit(n.body, prog);
        prog.push(["jmp", at]);
        prog[at] = ["split", at + 1, prog.length];
      } else {
        const outs: number[] = [];
        for (let k = n.min; k < n.max; k++) {
          outs.push(prog.length);
          prog.push(null);
          emit(n.body, prog);
        }
        for (const at of outs) prog[at] = ["split", at + 1, prog.length];
      }
    }
  }
}

export class Pattern {
  prog: Ins[];
  found = new Map<string, boolean>();

  constructor(pattern: string, readonly anycase = false) {
    const p = new Parser([...pattern]);
    const items = p.alternation();
    if (p.i < p.s.length) p.fail("unbalanced parenthesis");
    if (risky(items)) throw new PolicyError("regex has a repeat of a repeat (e.g. '(a+)+'), which can hang matching");
    walk(items);
    const prog: (Ins | null)[] = [];
    emit(items, prog);
    prog.push(["match"]);
    if (prog.length > MAX_PROGRAM) throw new PolicyError(`the pattern compiles to more than ${MAX_PROGRAM} instructions`);
    this.prog = prog as Ins[];
  }

  private at(kind: string, t: string[], i: number): boolean {
    if (kind === "begin" || kind === "beginstr") return i === 0;
    if (kind === "end") return i === t.length;
    const b = (i > 0 && isWord(t[i - 1])) !== (i < t.length && isWord(t[i]));
    return kind === "boundary" ? b : !b;
  }

  private reads(test: Test, c: string): boolean {
    if (!this.anycase) return test(c);
    const forms = c.codePointAt(0)! < 128 ? [c.toLowerCase(), c.toUpperCase()] : [c, ...(FOLDS[c] ?? [])];
    return forms.some(test);
  }

  /** Whether the pattern matches somewhere in `text`, spending `budget`; a text searched before is answered again. */
  search(text: string, budget: Budget): boolean {
    if (!this.found.has(text)) this.found.set(text, this.run([...text], budget));
    return this.found.get(text)!;
  }

  private run(t: string[], budget: Budget): boolean {
    let threads: number[] = [];
    for (let i = 0; i <= t.length; i++) {
      const seen = new Set<number>(), ready: number[] = [];
      for (const start of [...threads, 0]) {
        const stack = [start];
        while (stack.length) {
          const pc = stack.pop()!;
          if (seen.has(pc)) continue;
          seen.add(pc);
          budget.spend(1);
          const ins = this.prog[pc];
          if (ins[0] === "match") return true;
          if (ins[0] === "jmp") stack.push(ins[1]);
          else if (ins[0] === "split") stack.push(ins[2], ins[1]);
          else if (ins[0] === "at") { if (this.at(ins[1], t, i)) stack.push(pc + 1); }
          else ready.push(pc);
        }
      }
      if (i === t.length) return false;
      budget.spend(ready.length);
      threads = ready.filter((pc) => this.reads((this.prog[pc] as ["char", Test])[1], t[i])).map((pc) => pc + 1);
    }
    return false;
  }
}
