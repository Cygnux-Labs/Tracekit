"""tracekit view's page (tracekit/ui/terminal.html): its themes, links, panels and views, run in Node where they are code.

    python3 -m pytest tests/test_view_ui.py -v
"""
import json
import os
import re
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tracekit import observe, view  # noqa: E402
from test_view import page_js, v2rec  # noqa: E402

PAGE = observe.read_text(observe.UI)
COLOUR = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\(")


def needs_node(test):
    if not shutil.which("node"):
        test.skipTest("needs node to run the page's code")


class Theme(unittest.TestCase):
    def test_every_colour_is_a_token_and_light_redefines_each_one(self):
        """A colour written outside the tokens stays dark in the light theme (the tape's row lines, the lanes)."""
        css = PAGE[PAGE.index("<style>"):PAGE.index("</style>")]
        blocks = re.findall(r"(:root[^{]*)\{([^}]*)\}", css)
        tokens = {sel.strip(): dict(re.findall(r"(--[\w-]+):\s*([^;]+);", body)) for sel, body in blocks}
        dark, auto, light = (tokens[k] for k in (":root", ':root:not([data-theme="dark"])', ':root[data-theme="light"]'))
        self.assertEqual(auto, light)
        self.assertEqual(set(light), set(dark) - {"--mono"})
        rest = re.sub(r":root[^{]*\{[^}]*\}", "", css)
        self.assertEqual(COLOUR.findall(rest), [])
        self.assertEqual(re.findall(r"""["'`]#[0-9a-fA-F]{3,8}\b""", PAGE[PAGE.index("<script"):]), [])
        self.assertIn("color:var(--ink)", PAGE)   # the help overlay's title, the one style attribute with a colour

    def test_a_picked_theme_is_kept_and_applies_where_storage_is_refused(self):
        needs_node(self)
        out = json.loads(page_js(["THEMES", "setTheme"], """
            const el = {}, $ = id => el[id] ??= {}, document = { documentElement: { dataset: {} } }, schedule = () => {};
            let kept = null; const localStorage = { setItem(k, v) { kept = [k, v]; } }, seen = [];
            const look = () => seen.push([document.documentElement.dataset.theme ?? null, el.theme.textContent, kept]);
            setTheme("light"); look();
            localStorage.setItem = () => { throw new Error("SecurityError"); };   // a private window
            setTheme("dark"); look();
            setTheme("<b>"); look();
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [["light", "THEME LIGHT", ["tracekit-theme", "light"]],
                               ["dark", "THEME DARK", ["tracekit-theme", "light"]],
                               [None, "THEME AUTO", ["tracekit-theme", "light"]]])


class DeepLinks(unittest.TestCase):
    def test_a_link_opens_its_run_view_and_record_and_back_steps_through_what_was_opened(self):
        """The URL said nothing of what was open: a run could be linked (#run=) but not its view or record, and Back
        left the page."""
        needs_node(self)
        out = json.loads(page_js(["VIEWS", "linkOf", "syncLink", "followLink"], """
            let scope = null, VIEW = "desk", selected = null, R = null, linked = false, following = false, wvKey = "x";
            const V2 = true, RUNS = new Map([["r 1&x", {}]]), lseq = r => r.tk_seq, schedule = () => {}, seen = [];
            const location = { hash: "#seq=7&view=graph&run=r+1%26x", pathname: "/" };
            const write = how => (_, __, h) => { seen.push([how, h]); location.hash = h.startsWith("#") ? h : ""; };
            const history = { pushState: write("push"), replaceState: write("replace") };
            const setScope = id => { scope = id; selected = null; };
            const openSeq = n => { selected = { tk_seq: n - 1 }; };   // record 7 has no row: the one before it opens
            syncLink();                                  // before the link is read the URL keeps it
            followLink(); syncLink();                    // followed: its record opened as the row before it
            seen.push([scope, VIEW]);
            selected = { pre: { tk_seq: 9 } }; syncLink();   // a click: a new entry, so Back returns to seq 6
            R = [{}]; selected = { tk_seq: 10 }; syncLink(); R = null;   // a replay step replaces it
            location.hash = "#run=nope&view=%3Cscript%3E"; followLink(); syncLink();   // an unknown run and view
            seen.push([scope, VIEW]);
            selected = null; scope = null; syncLink();
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [["replace", "#run=r+1%26x&view=graph&seq=6"], ["r 1&x", "graph"],
                               ["push", "#run=r+1%26x&view=graph&seq=9"], ["replace", "#run=r+1%26x&view=graph&seq=10"],
                               ["replace", "#run=r+1%26x"], ["r 1&x", "desk"], ["push", "/"]])

    def test_back_and_forward_follow_the_link_and_the_seq_command_shares_its_record_lookup(self):
        self.assertIn('window.addEventListener("popstate", () => linked && followLink());', PAGE)
        self.assertEqual(PAGE.count("S.recs.reduce((b, r) => lseq(r) != null && lseq(r) <= n"), 1)



class Panels(unittest.TestCase):
    def test_a_run_started_by_another_is_listed_under_it(self):
        recs = [v2rec(1, "run.registered", {"agent": {"name": "coder"}, "parent_run": "orch", "session": "orch"})]
        self.assertEqual(view.review(recs, mock.Mock(integrity="VERIFIED", assurance="dev"), "verified")["parent"], "orch")
        self.assertNotIn("parent", view.review(recs[:0], mock.Mock(integrity="VERIFIED", assurance="dev"), "verified"))

    def test_the_tree_puts_each_after_its_parent_and_keeps_orphans_and_loops(self):
        """Panel 1 listed runs by time and sub-agents one level under main: who started whom was not shown."""
        needs_node(self)
        out = page_js(["treeOrder"], """
            const items = [["a", null], ["c", "b"], ["b", "a"], ["d", "gone"], ["x", "y"], ["y", "x"], ["s", "s"]];
            process.stdout.write(treeOrder(items, i => i[0], i => i[1]).map(([i, d]) => i[0] + d).join(" "));""")
        self.assertEqual(out, "a0 b1 c2 d0 s0 x0 y1")

    def test_each_active_filter_is_a_chip_that_removes_it(self):
        needs_node(self)
        out = json.loads(page_js(["KINDS", "filterChips"], """
            const V2 = true, RUNS = new Map([["d91c70b32fa1", { agent: "coder" }]]);
            let scope = null, F = { agent: null, tool: null, file: null, flag: false, find: null, kind: null };
            const seen = [filterChips()];
            scope = "d91c70b32fa1"; seen.push(filterChips());
            F = { agent: "api", tool: "Bash", file: null, flag: true, find: "rm", kind: "apr" }; seen.push(filterChips());
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [[], [["run", "", "RUN coder·d91c70b3"]],
                               [["run", "", "RUN coder·d91c70b3"], ["clear", "agent", "AGT api"],
                                ["clear", "tool", "TOOL Bash"], ["clear", "flag", "FLAGGED"], ["clear", "find", "FIND rm"],
                                ["clear", "kind", "TAPE APPROVALS"], ["clear", "all", "CLEAR ALL"]]])
        self.assertIn('if (t.dataset.clear === "all") { runCommand("CLR"); return setScope(null); }', PAGE)


if __name__ == "__main__":
    unittest.main()
