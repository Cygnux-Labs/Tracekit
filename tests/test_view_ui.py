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



def text(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


class WhyThisDecision(unittest.TestCase):
    def detail(self, call):
        return json.loads(page_js(["esc", "short", "cp", "ANSWER", "lastAnswer", "ended", "callState", "whyDecision"], f"""
            const S = {{ sessions: new Map() }}, label = () => "coder·5e67", DESK = () => true;
            const a = {json.dumps(call)}; a.agent = {{ session: "r1" }}; a.approvals ??= []; a.flags ??= [];
            process.stdout.write(JSON.stringify(whyDecision(a)));"""))

    def test_a_held_call_shows_each_section_read_its_rule_and_the_commands_that_answer_it(self):
        """DETAIL listed a call's rules, not the walk that decided it: what was read, what matched, who may answer."""
        needs_node(self)
        html = self.detail({"tool": "send_email", "v2": {
            "decision": "ask", "cls": "email", "read": {"deny": 7, "ask": 6, "flag": 3}, "secs": {"TK-P001": "ask"},
            "rules": [{"id": "TK-P001", "reason": "email outside the company", "remedy": "Send it from a person."}]},
            "approvals": [{"v2": {"approval": "requested", "approval_id": "apr<1>",
                                  "agents": {"eligible": False, "reason": "the rule has no agent bounds"}}}]})
        self.assertEqual(text(html), (
            "WHY THIS DECISION 1 CALL send_email from coder·5e67 · class email (the policy's map of this tool) "
            "2 DENY RULES read 7 · none matched 3 ASK RULES read 6 · matched TK-P001 email outside the company what "
            "to do: Send it from a person. 4 FLAG RULES read 3 · none matched 5 DECISION ASK the first section with a "
            "match decides: deny, then ask, then flag; none, allow 6 OUTCOME WAITING 7 WHO ANSWERS a person the "
            "signer takes as an approver, on the approvals page , or in a terminal with the signer's approvals command no "
            "agent approver may answer it: the rule has no agent bounds tracekit approvals approve apr&lt;1&gt; COPY "
            "tracekit approvals reject apr&lt;1&gt; COPY"))
        self.assertIn('<b class="ask">3</b>', html)
        self.assertIn('<a href="/approvals">approvals page</a>', html)

    def test_a_call_of_a_policy_the_viewer_lacks_names_only_what_matched(self):
        needs_node(self)
        html = text(self.detail({"tool": "Bash", "pre": {}, "denied": True, "v2": {
            "decision": "deny", "policy_hash": "sha256:0123456789abcdef", "rules": [{"id": "TK-D003", "reason": ""}]}}))
        self.assertIn("2 POLICY sha256:0123456789ab…: not a policy this viewer has, so only the rules that matched are "
                      "known", html)
        self.assertIn("3 MATCHED TK-D003 (no reason in this policy) 4 DECISION DENY", html)
        self.assertIn("5 OUTCOME BLOCKED 6 WHO ANSWERS nobody: a denied call is never held", html)
        self.assertNotIn("tracekit approvals", html)
        html = text(self.detail({"tool": "Agent", "v2": {"decision": "ask", "rules": []}}))
        self.assertIn("nobody yet: the agent has not requested an approval for this call", html)



def hold(seq, call, run="r1", **v2):
    return {"event": "PreToolUse", "session_id": run, "tk_seq": seq, "tool_use_id": call, "tool_name": "send_email",
            "agent": "billing", "v2": {"decision": "ask", **v2}}


def answer(seq, call, how, run="r1", **v2):
    return {"event": "tk_alert", "session_id": run, "tk_seq": seq, "v2": {"tool_use_id": call, "approval": how, **v2}}


class WaitingForYou(unittest.TestCase):
    def test_every_runs_unanswered_holds_count_and_each_links_to_its_record(self):
        """The page showed a hold only inside its own run: nothing said a person was needed somewhere else."""
        needs_node(self)
        recs = [hold(1, "c1"), answer(2, "c1", "requested", approval_id="apr-1"), hold(3, "c2"),
                answer(4, "c2", "requested"), answer(5, "c2", "approve"), answer(6, "c2", "consumed"),
                hold(7, "c3", run="r2"), {"event": "SessionEnd", "session_id": "r2", "tk_seq": 8},
                hold(9, "c4"), answer(10, "c4", "escalated"), hold(11, "c5", run="r 3&x"),
                {**hold(12, "c6"), "v2": {"decision": "flag"}}, answer(13, "c7", "expired")]
        out = json.loads(page_js(["waiting", "renderWaiting"], f"""
            const ALL = {json.dumps(recs)}, el = {{}}, $ = id => el[id] ??= {{}};
            let desk = false, waitKey = [], waitList = []; const DESK = () => desk;
            const seen = [waiting().map(w => [w.rec.tool_use_id, w.req?.v2.approval_id ?? null, w.link])];
            renderWaiting(); seen.push([el.waiting.hidden, el.waiting.textContent, el.waiting.href]);
            desk = true; renderWaiting(); seen.push(el.waiting.href);
            ALL.push({json.dumps(answer(14, "c1", "reject"))}); seen.push(waiting().map(w => w.rec.tool_use_id));
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [[["c1", "apr-1", "#run=r1&seq=1"], ["c4", None, "#run=r1&seq=9"],
                                ["c5", None, "#run=r+3%26x&seq=11"]],
                               [False, "WAITING FOR YOU 3", "#run=r1&seq=1"], "/approvals", ["c4", "c5"]])

    def test_a_new_hold_or_high_alert_toasts_as_text_and_the_snapshot_does_not(self):
        needs_node(self)
        out = json.loads(page_js(["vis", "toastOf"], f"""
            const made = [], box = {{ children: [], prepend(t) {{ this.children.unshift(t); }} }};
            Object.defineProperty(box, "lastChild", {{ get() {{ return {{ remove: () => box.children.pop() }}; }} }});
            const document = {{ createElement: tag => {{ const e = {{ tag, kids: [], append(...k) {{ this.kids.push(...k); }},
                                                               remove() {{}} }}; made.push(e); return e; }} }};
            const $ = () => box, DESK = () => false, setTimeout = () => {{}};
            let toasting = false;
            toastOf({json.dumps(hold(1, "c1"))});   // the snapshot: no toast
            toasting = true;
            toastOf({json.dumps(hold(2, "c2"))});
            toastOf({{ event: "tk_alert", severity: "high", title: "rm\u202e<b>", text: "x", agent: "a", session_id: "r", tk_seq: 3 }});
            toastOf({{ event: "tk_alert", severity: "med", title: "quiet", session_id: "r", tk_seq: 4 }});
            for (let i = 0; i < 3; i++) toastOf({json.dumps(hold(5, "c5"))});
            process.stdout.write(JSON.stringify([box.children.length, made.filter(e => e.tag === "b").map(e => e.textContent),
                                                 made.filter(e => e.tag === "a").map(e => e.href)]));"""))
        self.assertEqual(out[0], 3)
        self.assertEqual(out[1][:2], ["HELD · send_email waits for a person", "HIGH · rm\\u202e<b>"])
        self.assertEqual(out[2][:2], ["#run=r1&seq=2", "#run=r&seq=3"])
        self.assertIn("toasting = false; snap.records.forEach(accept); toasting = true;", PAGE)


if __name__ == "__main__":
    unittest.main()
