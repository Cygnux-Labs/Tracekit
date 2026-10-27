"""tracekit view's page (tracekit/ui/terminal.html): its themes, links, panels and views, run in Node where they are code.

    python3 -m pytest tests/test_view_ui.py -v
"""
import html
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
        out = json.loads(page_js(["PAGES", "RVIEWS", "show", "linkOf", "syncLink", "followLink"], """
            let scope = null, PAGE = "desk", RV = "calls", CALLSLOG = false, selected = null, R = null, linked = false, following = false, wvKey = "x";
            const V2 = true, RUNS = new Map([["r 1&x", {}]]), lseq = r => r.tk_seq, schedule = () => {}, seen = [], goLive = () => {};
            const location = { hash: "#seq=7&view=graph&run=r+1%26x", pathname: "/" };
            const write = how => (_, __, h) => { seen.push([how, h]); location.hash = h.startsWith("#") ? h : ""; };
            const history = { pushState: write("push"), replaceState: write("replace") };
            const setScope = id => { scope = id; selected = null; };
            const openSeq = n => { selected = { tk_seq: n - 1 }; };   // record 7 has no row: the one before it opens
            syncLink();                                  // before the link is read the URL keeps it
            followLink(); syncLink();                    // followed: its record opened as the row before it
            seen.push([scope, PAGE, RV]);
            selected = { pre: { tk_seq: 9 } }; syncLink();   // a click: a new entry, so Back returns to seq 6
            R = [{}]; selected = { tk_seq: 10 }; syncLink(); R = null;   // a replay step replaces it
            location.hash = "#run=nope&view=%3Cscript%3E"; followLink(); syncLink();   // an unknown run and view
            seen.push([scope, PAGE, RV]);
            PAGE = "desk"; selected = null; syncLink();   // DESK with a run: its own page name
            scope = null; syncLink();
            // old links: the why log's TIMELINE is CALLS with its events, PERMISSIONS a page, a run alone its page
            for (const h of ["#view=timeline", "#view=permissions", "#run=r+1%26x", "#page=runs", "#view=waterfall&run=r+1%26x"]) {
              location.hash = h; followLink(); seen.push([h, PAGE, RV, CALLSLOG]); }
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [["replace", "#run=r+1%26x&view=graph&seq=6"], ["r 1&x", "run", "graph"],
                               ["push", "#run=r+1%26x&view=graph&seq=9"], ["replace", "#run=r+1%26x&view=graph&seq=10"],
                               ["replace", "#run=r+1%26x&view=calls"], ["r 1&x", "run", "calls"],
                               ["push", "#page=desk&run=r+1%26x"], ["push", "/"],
                               ["#view=timeline", "run", "calls", True], ["#view=permissions", "permissions", "calls", True],
                               ["#run=r+1%26x", "run", "calls", False], ["#page=runs", "runs", "calls", False],
                               ["#view=waterfall&run=r+1%26x", "run", "waterfall", False]])

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

    def test_a_rule_that_matched_under_another_class_is_said_not_counted(self):
        """The record names no class: a shell rule on an http tool matched under a class hint the signer also checked."""
        tr, h = view.Translator(view.policy_reasons()), None
        h = next(k for k, rules in tr.reasons.items() if "TK-D003" in rules and "TK-N001" in rules)
        own, other = (tr.feed(v2rec(1, "policy.decision", {"tool_use_id": "c1", "tool": "http_get", "decision": "deny",
                                                           "rule_ids": [i], "policy_hash": h}))[0]["v2"]
                      for i in ("TK-N001", "TK-D003"))
        self.assertEqual((own["cls"], own["secs"], "other" in own), ("http", {"TK-N001": "deny"}, False))
        self.assertEqual((other["secs"], other["other"]), ({"TK-D003": "deny"}, True))

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
    def test_every_runs_unanswered_holds_count_and_each_opens_its_record(self):
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
            const seen = [waiting().map(w => [w.rec.tool_use_id, w.req?.v2.approval_id ?? null, w.open])];
            renderWaiting(); seen.push([el.waiting.hidden, el.waiting.textContent, el.waiting.title]);
            desk = true; renderWaiting(); seen.push(el.waiting.title);
            ALL.push({json.dumps(answer(14, "c1", "reject"))}); seen.push(waiting().map(w => w.rec.tool_use_id));
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [[["c1", "apr-1", ["r1", 1]], ["c4", None, ["r1", 9]], ["c5", None, ["r 3&x", 11]]],
                               [False, "WAITING FOR YOU 3", "open the oldest: its detail has the command that answers it"],
                               "answer them on the approvals page", ["c4", "c5"]])
        # no link carries data: a hold opens through the page's state (checklist item 3)
        self.assertIn("if (DESK()) DESK().click(); else if (w) openRec(...w.open);", PAGE)

    def test_a_new_hold_or_high_alert_toasts_as_text_and_the_snapshot_does_not(self):
        needs_node(self)
        out = json.loads(page_js(["vis", "toastOf"], f"""
            const made = [], box = {{ children: [], prepend(t) {{ this.children.unshift(t); }} }};
            Object.defineProperty(box, "lastChild", {{ get() {{ return {{ remove: () => box.children.pop() }}; }} }});
            const document = {{ createElement: tag => {{ const e = {{ tag, kids: [], dataset: {{}}, append(...k) {{ this.kids.push(...k); }},
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
                                                 made.filter(e => e.dataset.orun).map(e => [e.dataset.orun, e.dataset.oseq])]));"""))
        self.assertEqual(out[0], 3)
        self.assertEqual(out[1][:2], ["HELD · send_email waits for a person", "HIGH · rm\\u202e<b>"])
        self.assertEqual(out[2][:2], [["r1", 2], ["r", 3]])
        self.assertIn("toasting = false; snap.records.forEach(accept); toasting = true;", PAGE)



class NeedsYou(unittest.TestCase):
    def needs(self, recs, runs, stopped=""):
        return json.loads(page_js(["j", "plural", "failLines", "waiting", "needsYou"], f"""
            const ALL = {json.dumps(recs)}, RUNS = new Map({json.dumps(runs)}.map(r => [r.id, r])), STOPPED = {json.dumps(stopped)};
            let waitKey = [], waitList = [];
            process.stdout.write(JSON.stringify(needsYou()));"""))

    def test_what_needs_a_person_comes_first_with_its_command_and_record(self):
        """A person asked "do I need to do anything?" and the answer was spread over runs, alerts and pages."""
        needs_node(self)
        held = {**hold(1, "c1"), "tool_input": {"to": "x@outside.example"},
                "v2": {"decision": "ask", "rules": [{"id": "TK-P001", "reason": "an email outside the company"}]}}
        out = self.needs([held, answer(2, "c1", "requested", approval_id="apr-1"), hold(3, "c2")], [
            {"id": "r1", "agent": "billing", "verdict": "verified", "state": "open", "incidents": [
                {"incident_id": "inc-1", "trigger": "rule", "rule_ids": ["TK-D002"], "state": "held"},
                {"incident_id": "inc-0", "trigger": "rule", "rule_ids": [], "state": "resumed"}]},
            {"id": "r2xxxxxxxx", "agent": "coder", "verdict": "failed", "state": "final",
             "report": "[PASS] chain\n[FAIL] signatures\n  seq 4: bad signature"}], stopped="verification stopped")
        self.assertEqual([(n["kind"], n["open"]) for n in out], [
            ("HOLD", ["r1", 1]), ("HOLD", ["r1", 3]), ("CONTAINED", ["r1", ""]), ("FAILED", ["r2xxxxxxxx", ""]),
            ("STOPPED", None)])
        self.assertEqual(out[0]["what"], "send_email · billing waits for a person: TK-P001 an email outside the company")
        self.assertEqual(out[0]["detail"], 'binds { "to": "x@outside.example" }')
        self.assertEqual(out[0]["cmds"], ["tracekit approvals approve apr-1", "tracekit approvals reject apr-1"])
        self.assertEqual((out[1]["detail"], out[1]["cmds"]),
                         ("arguments kept as a commitment only · no approval requested yet", []))
        self.assertEqual(out[2]["what"], "billing · run held by incident inc-1")
        self.assertEqual(out[3]["detail"], "[FAIL] signatures")

    def test_nothing_needed_reads_all_clear_with_the_agents_working(self):
        needs_node(self)
        self.assertEqual(self.needs([], [{"id": "r1", "verdict": "verified", "state": "open"}]), [])
        self.assertIn('`ALL CLEAR · ${esc(plural(working, "agent"))} working · nothing needs you`', PAGE)



class AlertGroups(unittest.TestCase):
    def test_repeats_of_one_kind_are_one_ranked_group_and_every_alert_stays_in_it(self):
        """13,040 alert rows, mostly one capture-gap alert whose text differed each time: ALERTS read as a flood."""
        needs_node(self)
        out = json.loads(page_js(["srcOf", "SEV_RANK", "alertGroups"], """
            const rec = (run, seq) => ({ rec: { session_id: run, tk_seq: seq } });
            const alerts = [];
            const add = (sev, key, run, text) => alerts.push({ sev, key, text, ref: rec(run, alerts.length), i: alerts.length });
            for (let i = 0; i < 5; i++) add("med", "GAP · signer_unavailable", i < 3 ? "r1" : "r2", `missed ${i}`);
            add("high", "BLOCKED · TK-D003", "r1", "BLOCKED Bash: git push --force");
            add("info", "SIGNER EPOCH", "r3", "1 key");
            add("med", "FLAGGED · TK-F001", "r1", "FLAGGED · Bash");
            process.stdout.write(JSON.stringify(alertGroups(alerts).map(g => [g.key, g.all.length, g.runs, g.al.text])));"""))
        self.assertEqual(out, [["BLOCKED · TK-D003", 1, 1, "BLOCKED Bash: git push --force"],
                               ["FLAGGED · TK-F001", 1, 1, "FLAGGED · Bash"],
                               ["GAP · signer_unavailable", 5, 2, "missed 4"], ["SIGNER EPOCH", 1, 1, "1 key"]])
        self.assertIn("g.all.slice(-GRP_PAGE * (OPENGRP.get(g.key)))", PAGE)   # an open group lists its alerts, paged

    def test_each_alert_is_keyed_by_its_rule_or_kind_not_its_changing_text(self):
        for key in ('"BLOCKED · " + (act.reasons.join(" ") || act.tool)', '"GAP · " + v.kind',
                    '"FINDING " + v.finding.rule', 'String(r.title || "ALERT").replace(/\\b\\d+\\b/g, "n")'):
            self.assertIn(key, PAGE)



class Permissions(unittest.TestCase):
    def test_every_decision_but_a_plain_allow_with_its_outcome_and_who_answered(self):
        """The dev viewer has no approvals page and run reviews listed approvals for 17 of 250 runs with holds."""
        needs_node(self)
        recs = [{**hold(1, "c1"), "v2": {"decision": "deny"}}, {**hold(2, "c2"), "v2": {"decision": "flag"}},
                {"event": "PostToolUse", "session_id": "r1", "tool_use_id": "c2", "tk_seq": 3},
                hold(4, "c3"), answer(5, "c3", "requested", approval_id="apr-3"),
                answer(6, "c3", "approve", approver="oidc:alice"), answer(7, "c3", "consumed"),
                {"event": "PostToolUse", "session_id": "r1", "tool_use_id": "c3", "tk_seq": 8},
                hold(9, "c4"), answer(10, "c4", "reject", approver="uid:501"), hold(11, "c5"), answer(12, "c5", "expired"),
                hold(13, "c6"), answer(14, "c6", "requested", approval_id="apr-6"),
                {**hold(15, "c7"), "v2": {"decision": "allow"}}, {**hold(16, "c8"), "analysis": True},
                hold(17, "c9", run="r2"), {"event": "SessionEnd", "session_id": "r2", "tk_seq": 18}]
        out = json.loads(page_js(["ANSWER", "permRows"], f"""
            const ALL = {json.dumps(recs)}; let scope = null, permKey = [], permList = [];
            const rows = r => r.map(x => [x.rec.tool_use_id, x.tabs.filter(Boolean).join(" "), x.out[1], x.ans?.v2.approver ?? null,
                                          x.req?.v2.approval_id ?? null]);
            const seen = [rows(permRows())];
            scope = "r2"; seen.push(rows(permRows()));
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out[0], [["c9", "all ask expired", "NOT ANSWERED", None, None],
                                  ["c6", "all ask waiting", "WAITING", None, "apr-6"],
                                  ["c5", "all ask expired", "EXPIRED", None, None],
                                  ["c4", "all ask rejected", "REJECTED", "uid:501", None],
                                  ["c3", "all ask approved", "APPROVED · RAN", "oidc:alice", "apr-3"],
                                  ["c2", "all flag", "RAN · FLAGGED", None, None], ["c1", "all deny", "BLOCKED", None, None]])
        self.assertEqual(out[1], [["c9", "all ask expired", "NOT ANSWERED", None, None]])

    def test_a_run_review_keeps_every_permission_with_its_outcome_after_the_records_leave(self):
        """Run reviews listed only approve and reject answers: a hold that expired, was abandoned or got no answer was in
        none, and a review is what the page keeps of a run whose records left the live view."""
        alice = {"scheme": "oidc", "subject": "alice", "attested": True}
        req = lambda seq, aid, call: v2rec(seq, "approval.request", {"approval_id": aid, "binding": {"tool_call_id": call}})  # noqa: E731
        prov = [{"field": "to", "kind": "email", "source": {"run_seq": 1, "tool": "fetch_page"}}]
        recs = [v2rec(1, "policy.decision", {"tool_use_id": "c1", "tool": "rm", "decision": "deny", "rule_ids": ["T-DENY"]}),
                v2rec(2, "policy.decision", {"tool_use_id": "c2", "tool": "ls", "decision": "allow", "rule_ids": []}),
                v2rec(3, "policy.decision", {"tool_use_id": "c3", "tool": "pay", "decision": "ask", "rule_ids": ["T-PAY"],
                                             "provenance": prov}),
                req(4, "apr-3", "c3"),
                v2rec(5, "approval", {"tool_use_id": "c3", "approval_id": "apr-3", "decision": "approve",
                                      "approver_identity": alice}),
                v2rec(6, "approval.consumed", {"approval_id": "apr-3"}, tool_call_id="c3"),
                v2rec(7, "policy.decision", {"tool_use_id": "c4", "tool": "pay", "decision": "ask", "rule_ids": ["T-PAY"]}),
                req(8, "apr-4", "c4"), v2rec(9, "approval.expired", {"approval_id": "apr-4"}),
                v2rec(10, "policy.decision", {"tool_use_id": "c5", "tool": "curl", "decision": "flag", "rule_ids": ["T-F"]}),
                v2rec(11, "policy.decision", {"tool_use_id": "c6", "tool": "pay", "decision": "ask", "rule_ids": ["T-PAY"]})]
        rep = mock.Mock(integrity="VERIFIED", assurance="dev")
        got = view.review(recs, rep, "verified")
        self.assertEqual([(p["tool_use_id"], p["decision"], p["outcome"], p.get("approval_id"), p.get("by"),
                           p.get("answer_seq")) for p in got["permissions"]],
                         [("c1", "deny", "blocked", None, None, None),
                          ("c3", "ask", "approved · ran", "apr-3", "oidc:alice (attested)", 5),
                          ("c4", "ask", "expired", "apr-4", None, 9), ("c5", "flag", "flagged", None, None, None),
                          ("c6", "ask", "waiting", None, None, None)])
        self.assertEqual(got["permissions"][1]["provenance"], prov)
        self.assertEqual(len(got["approvals"]), 1)   # the approvals list is as it was
        final = view.review(recs + [v2rec(12, "run.final", {})], rep, "verified")
        self.assertEqual(final["permissions"][-1]["outcome"], "not answered")
        with mock.patch.object(view, "PERMISSIONS_KEPT", 2):
            kept = view.review(recs, rep, "verified")
        self.assertEqual(([p["tool_use_id"] for p in kept["permissions"]], kept["permissions_left_out"]),
                         (["c5", "c6"], 3))

    def test_the_view_is_reachable_without_why_logs_and_from_a_link(self):
        needs_node(self)
        self.assertNotIn('"permissions"', re.search(r"const NEEDWHY = new Set\(\[[^\]]*\]\)", PAGE).group(0))
        self.assertEqual(page_js(["PAGES", "centre"], """
            let PAGE = "permissions", RV = "calls", CALLSLOG = false;
            process.stdout.write(PAGES.includes("permissions") + " " + centre());"""), "true permissions")


def page_rec(seq, event, typ, **kw):
    return {"event": event, "session_id": "r1", "tk_seq": seq, "hash": f"sha256:{seq:064x}", "v2": {"type": typ}, **kw}


VERIFIED_REPORT = """tenant default · agent a · final
operator-side view — re-verify with the signed release for evidence

[PASS] keys — 1 record key(s) from 1 key record(s)
[WARN] witness quorum — 0 pinned cosignature(s), 0 required
[PASS] run chain — contiguous from run_seq 0

Integrity: VERIFIED.
"""
FAILED_REPORT = """operator-side view — re-verify with the signed release for evidence

[PASS] manifest — every file is listed with its SHA-256
[FAIL] signatures — 1 record(s) whose signature does not verify
        record 4: bad signature
[FAIL] run chain — broken at run_seq 4

Integrity: FAILED.
"""


class Evidence(unittest.TestCase):
    """EVIDENCE was the run review with the report as one block of text: no record-by-record walk, no stamp."""

    def test_the_walk_checks_and_stamp_are_the_servers_result(self):
        needs_node(self)
        recs = [page_rec(5, "SessionStart", "run.registered"),
                page_rec(6, "PreToolUse", "policy.decision", tool_use_id="c1"),
                page_rec(7, "tk_alert", "approval", title="APPROVED · send_email"),
                page_rec(8, "PostToolUse", "tool.result", tool_use_id="c1"),
                {"event": "tk_alert", "session_id": "r1", "tk_seq": None, "analysis": True, "title": "RUN r1"},
                page_rec(9, "tk_model", "model.exchange")]
        out = json.loads(page_js(["tuid", "WALK_MAX", "evidenceOf"], f"""
            const recs = {json.dumps(recs)}, S = {{ actions: new Map([["r1|c1", {{ tool: "send_email", target: "to a@b", pre: recs[1] }}]]) }};
            const of = r => {{ const e = evidenceOf(r, recs); return [e.ok, e.stamp, e.total, e.rows.map(x => [x.seq, x.what, x.type, x.hash.slice(-2)]),
                                                                   e.checks.map(c => [c.status, c.check, c.detail, c.problems])]; }};
            const many = Array.from({{ length: 2005 }}, (_, i) => ({{ tk_seq: i, event: "tk_note", title: "n" }}));
            const capped = evidenceOf({{ verdict: "verified", records: 2010 }}, many);
            process.stdout.write(JSON.stringify([of({{ verdict: "verified", records: 6, report: {json.dumps(VERIFIED_REPORT)} }}),
                of({{ verdict: "failed", report: {json.dumps(FAILED_REPORT)} }}), of({{ verdict: "pending", report: "No checkpoint covers the run's last record yet." }}),
                of({{ verdict: "error" }}), [capped.rows.length, capped.rows[0].seq, capped.total]]));"""))
        verified, failed, pending, error, capped = out
        self.assertEqual(verified[:3], [True, ["ok", "VERIFIED"], 6])
        self.assertEqual(verified[3], [[5, "run.registered", "run.registered", "05"],
                                       [6, "send_email · to a@b", "policy.decision", "06"],
                                       [7, "APPROVED · send_email", "approval", "07"],
                                       [8, "send_email · result", "tool.result", "08"],
                                       [9, "model.exchange", "model.exchange", "09"]])
        self.assertEqual(verified[4], [["pass", "keys", "1 record key(s) from 1 key record(s)", []],
                                       ["warn", "witness quorum", "0 pinned cosignature(s), 0 required", []],
                                       ["pass", "run chain", "contiguous from run_seq 0", []]])
        self.assertEqual(failed[:2], [False, ["bad", "FAILED · SIGNATURES"]])   # its first FAIL line
        self.assertEqual(failed[4], [["pass", "manifest", "every file is listed with its SHA-256", []],
                                     ["fail", "signatures", "1 record(s) whose signature does not verify",
                                      ["record 4: bad signature"]],
                                     ["fail", "run chain", "broken at run_seq 4", []]])
        self.assertEqual((pending[:2], pending[4]), ([False, ["wait", "PENDING"]], []))
        self.assertEqual(error[:2], [False, ["bad", "NOT CHECKED"]])
        self.assertEqual(capped, [2000, 5, 2010])   # the newest 2,000; the run's count says how many are left out

    def test_the_view_draws_the_walk_stamp_commands_tip_and_review(self):
        needs_node(self)
        recs = [page_rec(5, "SessionStart", "run.registered"), page_rec(6, "tk_note", "input.observed", title="INPUT · task")]
        out = json.loads(page_js(["esc", "cp", "tuid", "WALK_MAX", "evidenceOf", "evidenceView"], f"""
            const S = {{ recs: {json.dumps(recs)}, actions: new Map() }}, RUNS = new Map(), el = {{}}, html = {{}};
            const $ = id => el[id] ??= {{}}, put = (id, h) => {{ html[id] = h; }};
            const runCmds = r => ["tracekit export --v2 --run " + r.id, "tracekit verify " + r.id + ".tkb"], reviewHtml = (r, cmds) => `<REVIEW cmds=${{cmds}}>`;
            let scope = "r1"; const seen = [];
            for (const verdict of ["verified", "failed"]) {{
              RUNS.set("r1", {{ id: "r1", verdict, records: 2, decisions: {{}}, report: {json.dumps(VERIFIED_REPORT)} }});
              evidenceView(); seen.push(html.whyv);
            }}
            scope = null; evidenceView(); seen.push(html.whyv);
            process.stdout.write(JSON.stringify(seen));"""))
        ok, bad, none = out
        self.assertEqual(re.findall(r'<div class="rec( ok)?" data-tkseq="(\d+)"', ok), [(" ok", "5"), (" ok", "6")])
        self.assertIn('<div class="stamp ok">VERIFIED</div>', ok)
        self.assertIn("THE VIEWER'S CHECK, OPERATOR-SIDE: tracekit view exported this run's bundle", ok)
        for text in ("tracekit export --v2 --run r1", "tracekit verify r1.tkb", "<REVIEW cmds=false>",
                     "Download the bundle and check it with tracekit verify from the signed release: that, not this "
                     "page, is the evidence.", "VERIFIER REPORT · AS THE VIEWER PRINTED IT"):
            self.assertIn(text, ok)
        self.assertNotIn("sha256:", re.sub(r'title="[^"]*"', "", ok))   # a short hash, the whole one on hover
        self.assertEqual(re.findall(r'<div class="rec( ok)?"', bad), ["", ""])   # a failed run's walk covers nothing
        self.assertIn('<div class="stamp bad">FAILED</div>', bad)
        self.assertIn("Select a run", none)

    def test_a_runs_later_review_keeps_the_report_it_came_without(self):
        """A growing run's next checkpoint and its findings send the review alone: the report went, and with it the
        EVIDENCE checks."""
        needs_node(self)
        out = page_js(["accept"], """
            let V2 = true, R = null, scope = null, DROPPED = 0, MAXREC = 50000;
            const ALL = [], RUNS = new Map(), document = { body: { classList: { add() {} } } };
            const inScope = () => true, ingest = () => {}, rebuild = () => {}, stopRun = () => {}, toastOf = () => {};
            accept({ session_id: "r1", tenant: "default", analysis: true, review: { verdict: "verified", records: 3 }, text: "[PASS] keys" });
            accept({ session_id: "r1", tenant: "default", analysis: true, event: "tk_run", review: { verdict: "verified", records: 5 } });
            process.stdout.write(RUNS.get("r1").records + " " + RUNS.get("r1").report);""")
        self.assertEqual(out, "5 [PASS] keys")


# a run's calls in each state the TIMELINE draws; `ended` reads the run's session
CALLS_JS = """
    const S = { sessions: new Map([["open", { end: null }], ["done", { end: 9 }]]), actList: [] };
    const ag = { session: "done", name: "coder" }, live = { session: "open", name: "orch" }, ask = { decision: "ask" };
    const call = (tool, o) => ({ tool, target: "", agent: ag, end: null, flags: [], approvals: [], ...o });
    const C = {
      ok: call("Read", { start: 1, end: 2, post: {} }),
      failed: call("Bash", { start: 2, end: 2.5, post: {}, error: true, flags: ["error"] }),
      blocked: call("Bash", { start: 3, denied: true, flags: ["denied"] }),
      flagged: call("WebFetch", { start: 4, end: 5, post: {}, flags: ["flagged"] }),
      approved: call("send_email", { start: 5, end: 7, post: {}, flags: ["held_for_approval"], v2: ask, approvals: [
        { ts: 5.5, v2: { approval: "requested" } }, { ts: 6, v2: { approval: "approve" } }, { ts: 6.9, v2: { approval: "consumed" } }] }),
      rejected: call("send_email", { start: 7, flags: ["held_for_approval"], v2: ask, approvals: [{ ts: 8, v2: { approval: "reject" } }] }),
      waiting: call("Agent", { agent: live, start: 8, flags: ["held_for_approval"], v2: ask, approvals: [{ ts: 8.2, v2: { approval: "requested" } }] }),
      running: call("Read", { agent: live, start: 8.5 }),
      noresult: call("Read", { start: 8.6 }),
    };"""


class Waterfall(unittest.TestCase):
    """TIMELINE showed only one lane per agent: which call waited for a person, and how long, was not drawn."""

    def test_each_call_is_bars_by_its_outcome_and_a_hold_waits_until_its_answer(self):
        needs_node(self)
        out = json.loads(page_js(["ANSWER", "ended", "wfBars"], CALLS_JS + """
            process.stdout.write(JSON.stringify(Object.fromEntries(Object.entries(C).map(([k, a]) => [k, wfBars(a)]))));"""))
        self.assertEqual(out, {
            "ok": [["ok", 1, 2]], "failed": [["deny", 2, 2.5]], "blocked": [["deny", 3, 3]], "flagged": [["flag", 4, 5]],
            "approved": [["wait", 5, 6], ["ok", 6, 7]],          # waited from the decision to the answer, then ran
            "rejected": [["wait", 7, 8], ["deny", 8, 8]],        # refused: never ran
            "waiting": [["wait", 8, None]],                      # still waiting: to the right edge
            "running": [["ok", 8.5, None]], "noresult": [["ok", 8.6, 8.6]]})

    def test_by_call_draws_a_row_per_call_and_by_agent_the_lanes(self):
        needs_node(self)
        out = json.loads(page_js(["esc", "fmtDur", "tickStep", "tickText", "ANSWER", "lastAnswer", "ended", "callState",
                                  "WFMAX", "wfBars", "renderWaterfall"], CALLS_JS + """
            const V2 = true, R = null, fmtT = ts => "t" + ts, label = a => a.name, actMatch = a => !a.hide;
            const el = {}, $ = id => el[id] ??= { style: { setProperty() {} }, clientWidth: 900 }, put = (id, h) => { $(id).html = h; };
            const btn = by => ({ dataset: { wfby: by }, classList: { toggle(c, on) { this.on = on; } } }), btns = [btn("call"), btn("agent")];
            const document = { querySelectorAll: () => btns };
            let PAGE = "run", RV = "waterfall", WFBY = "call", selected = C.flagged, seen = [];
            S.actList = [{ ...C.ok, hide: true }, ...Object.values(C)];
            const look = () => seen.push([el.lanetitle.textContent, el.wfby.hidden, el.lanes.hidden, el.wf.hidden,
              el.lanelegend.hidden, el.wflegend.hidden, btns.map(b => b.classList.on)]);
            renderWaterfall(); look(); seen.push(el.wf.html, el.wflegend.html);
            WFBY = "agent"; renderWaterfall(); look();
            PAGE = "desk"; renderWaterfall(); look();
            PAGE = "run"; WFBY = "call"; S.actList = Array.from({ length: 605 }, (_, i) => ({ ...C.ok, start: i, end: i + 1 }));
            renderWaterfall(); seen.push(el.wf.html, el.wflegend.html);
            S.actList = [{ ...C.ok, hide: true }]; renderWaterfall(); seen.push(el.wf.html);
            process.stdout.write(JSON.stringify(seen));"""))
        by_call, html, legend, by_agent, desk, capped, capped_legend, none = out
        self.assertEqual(by_call, ["TIMELINE · ONE ROW PER CALL", False, True, False, True, False, [True, False]])
        self.assertEqual(by_agent, ["TIMELINE · ONE LANE PER AGENT", False, False, True, False, True, [False, True]])
        self.assertEqual(desk[:6], ["TIMELINE · ONE LANE PER AGENT", True, False, True, False, True])
        # one row per call the filters keep, each opening its call; the selected one marked
        self.assertEqual(re.findall(r'data-wf="(\d+)"', html), [str(i) for i in range(1, 10)])
        self.assertEqual(re.findall(r'class="wfr( on)?" data-wf="(\d+)"', html)[3], (" on", "4"))
        bars = re.findall(r'<rect class="wk-(\w+)" x="([\d.]+)" y="4" width="([\d.]+)"', html)
        self.assertEqual([b[0] for b in bars], ["ok", "deny", "deny", "flag", "wait", "ok", "wait", "deny", "wait", "ok", "ok"])
        self.assertIn('<pattern id="wfhatch"', html)
        _, x, w = bars[8]                                          # the hold still waiting runs to the right edge
        self.assertAlmostEqual(float(x) + float(w), 900 - 340, places=0)
        self.assertIn('title="coder · send_email · REJECTED"', html)
        self.assertIn("<title>waiting for a person · 1s</title><", html)
        self.assertIn("<title>failed · 500 ms</title>", html)
        self.assertIn("<title>rejected</title>", html)
        # the legend names only what the run shows
        self.assertEqual(re.findall(r'class="wk-(\w+)">([^<]+)<', legend),
                         [("ok", "allowed"), ("flag", "flagged"), ("deny", "blocked, refused or failed"),
                          ("wait", "waiting for a person")])
        self.assertEqual(re.findall(r'class="wk-(\w+)">([^<]+)<', capped_legend), [("ok", "allowed")])
        # the newest 600 are drawn, and it says how many are not
        self.assertEqual(len(re.findall(r'data-wf="', capped)), 600)
        self.assertIn('data-wf="5"', capped)
        self.assertNotIn('data-wf="4"', capped)
        self.assertIn("5 earlier calls are not drawn: the newest 600 are.", capped)
        self.assertIn("No call matches the filters.", none)

    def test_a_row_and_the_toggle_are_opened_by_the_pages_click_handlers(self):
        self.assertIn("if (t.dataset.wf) return select(S.actList[+t.dataset.wf]);", PAGE)
        self.assertIn("if (t.dataset.wfby) { WFBY = t.dataset.wfby; return schedule(); }", PAGE)
        self.assertIn("[data-wf][tabindex]", PAGE)   # Enter opens a row reached with Tab


SIGNED ={"evidence": [{"seq": 4, "hash": "sha256:4", "type": "tool.result"}]}


def call(policy, **more):
    return {"type": "action", "agent": "executor", "policy": policy, **SIGNED, **more}


class GraphGrades(unittest.TestCase):
    """GRAPH drew every flow alike: a link between two signed records looked like one an unsigned why log claims, an
    arrow into a call the signer stopped like one into a call that ran, and what a sensor saw leave was not drawn."""

    def test_each_edge_is_graded_by_its_proof(self):
        needs_node(self)
        by = {"in": SIGNED, "cited": {"tracekit": {"run_seq": 2}}, "log": {}, "ran": call({"decision": "allow"}),
              "denied": call({"decision": "deny"}), "rejected": call({"decision": "ask", "approval": {"decision": "reject"}}),
              "expired": call({"decision": "ask", "approval": {"decision": "expired"}}),
              "approved": call({"decision": "ask", "approval": {"decision": "approve"}}), "held": call({"decision": "ask"})}
        edges = [("in", "cited", "observed"), ("in", "log", "observed"), ("log", "ran", "observed"),
                 ("in", "ran", "observed"), ("in", "denied", "observed"), ("log", "rejected", "observed"),
                 ("in", "expired", "observed"), ("in", "approved", "observed"), ("in", "held", "observed"),
                 ("in", "denied", "inferred"), ("in", "ran", "tested"), ("ran", "fx:r1|9", "sensor")]
        out = json.loads(page_js(["ANSWER", "DECIDED", "decided", "signedNode", "edgeGrade"], f"""
            const by = {json.dumps(by)};
            process.stdout.write(JSON.stringify({json.dumps(edges)}.map(([src, dst, evidence]) => edgeGrade({{ src, dst, evidence }}, by))));"""))
        self.assertEqual(out, ["signed", "recorded", "recorded", "signed", "blocked", "blocked", "blocked", "signed",
                               "signed", "inferred", "tested", "observed"])

    def test_a_network_effect_joined_to_a_call_of_this_run_is_a_node_after_it(self):
        needs_node(self)
        out = json.loads(page_js(["whyRef", "netEffects"], """
            const WHY = { calls: { "r1|4": ["w1", "ev:call"], "r2|9": ["w2", "ev:other"] } };
            const S = { effects: new Map(), actions: new Map([["r1|c1", { pre: { session_id: "r1", v2: { run_seq: 4 } } }],
                                                              ["r2|c9", { pre: { session_id: "r2", v2: { run_seq: 9 } } }]]) };
            const fx = (seq, kind, call) => S.effects.set("r1|" + seq, { rec: { tk_seq: seq, v2: { effect: { kind, target: "api.example:443" } } }, call });
            fx(7, "connect", "r1|c1"); fx(8, "net", "r1|c1");                    // a kernel sensor's connect, the egress observer's
            fx(9, "exec", "r1|c1"); fx(10, "connect", null);                     // not a connection; joined to no call
            fx(11, "connect", "r2|c9"); fx(12, "connect", "r1|gone");            // a call of another why run; a call not here
            const by = { "ev:call": { agent: "executor", seq: 5 } };
            process.stdout.write(JSON.stringify(netEffects({ run_id: "w1" }, by).map(n => [n.id, n.type, n.call, n.agent, n.seq, n.label])));"""))
        self.assertEqual(out, [["fx:r1|7", "effect", "ev:call", "executor", 5, "api.example:443"],
                               ["fx:r1|8", "effect", "ev:call", "executor", 5, "api.example:443"]])

    def test_each_edge_title_says_its_grade_and_the_legend_names_only_those_drawn(self):
        needs_node(self)
        d = {"run_id": "w1", "agents": [{"name": "executor"}], "nodes": [
            {"id": "in", "type": "input", "agent": "executor", "seq": 1, "label": "msg", "trust": "untrusted", **SIGNED},
            {"id": "un", "type": "input", "agent": "executor", "seq": 2, "label": "note"},
            {"id": "dec", "type": "decision", "agent": "executor", "seq": 3, "label": "mock", **SIGNED},
            {**call({"decision": "allow"}), "id": "ok", "seq": 4, "label": "fetch"},
            {**call({"decision": "ask", "approval": {"decision": "reject"}}), "id": "no", "seq": 5, "label": "send_email"}],
            "edges": [{"src": "in", "dst": "dec", "kind": "context", "evidence": "observed"},
                      {"src": "un", "dst": "dec", "kind": "context", "evidence": "observed"},
                      {"src": "dec", "dst": "ok", "kind": "invoked", "evidence": "observed"},
                      {"src": "dec", "dst": "no", "kind": "invoked", "evidence": "observed"},
                      {"src": "in", "dst": "no", "kind": "argument", "evidence": "inferred"}]}
        out = json.loads(page_js(["esc", "plural", "ANSWER", "DECIDED", "decided", "signedNode", "edgeGrade", "GRADE",
                                  "whyRef", "netEffects", "effectHow", "reach", "GTYPE", "GRAPH_MAX", "pct", "graphView"], f"""
            const GV = {{ inferred: false, ruled: false, focus: null, fit: true }}, CSS = {{ escape: s => s }}, got = {{}};
            const el = {{ clientWidth: 900, clientHeight: 600, querySelector: () => null }}, $ = id => id === "gsvg" ? null : (got[id] ??= {{}});
            const WHY = {{ calls: {{ "r1|4": ["w1", "ok"] }} }};
            const S = {{ actions: new Map([["r1|c1", {{ pre: {{ session_id: "r1", v2: {{ run_seq: 4 }} }} }}]]), effects: new Map([["r1|9",
                {{ rec: {{ tk_seq: 31, v2: {{ effect: {{ kind: "connect", target: "api.example:443" }} }} }}, call: "r1|c1", how: "window", status: "explained" }}]]) }};
            graphView(el, {json.dumps(d)});
            process.stdout.write(JSON.stringify([el.innerHTML, got.wvsum.textContent]));"""))
        svg, summary = out
        self.assertEqual([html.unescape(t) for t in re.findall(r"<path [^>]*><title>([^<]*)</title>", svg)], [
            "context · signed: both ends are signed records", "context · recorded flow",
            "invoked · signed: both ends are signed records", "invoked · blocked: its signed decision stopped the call",
            "connect api.example:443 · started while this call ran · observed: a sensor saw it"])
        self.assertEqual(re.findall(r"</svg> ([^<]*)</span>", svg), [
            "signed: both ends are signed records", "recorded flow", "observed: a sensor saw it",
            "blocked: its signed decision stopped the call"])   # no inferred link is drawn, so none is named
        self.assertIn("stroke:var(--cyan)", svg)
        self.assertRegex(svg, r'<g data-tkseq="31"[^>]*>.*>api.example:443</text>')   # the effect opens its record
        self.assertEqual(summary, "5 nodes · 4 of 5 edges (recorded, tested) · 1 network effect a sensor saw")


WHY_RUN = {"run_id": "w1", "path": "/runs/w 1", "replay": {"program": "app:System", "allowed": False}, "nodes": [
    {"id": "ev:task", "type": "input", "agent": "executor", "seq": 1, "label": "task", "evidence": [{"seq": 6}]},
    {"id": "ev:msg", "type": "input", "agent": "executor", "seq": 2, "label": "msg:planner->executor", "trust": "untrusted",
     "evidence": [{"seq": 16}]},
    {"id": "ev:dec", "type": "decision", "agent": "executor", "seq": 3, "label": "mock", "evidence": [{"seq": "3 of run r1"}]},
    {"id": "ev:call", "type": "action", "agent": "executor", "seq": 4, "label": "send_email", "evidence": [{"seq": 27}]}]}
WHY_CALL = {"provenance": [], "target": "tool=send_email", "lineage": [["ev:msg", "ev:dec", "ev:call"],
                                                                      ["ev:task", "ev:dec", "ev:call"]], "candidates": [
    {"node": "ev:msg", "label": "msg:planner->executor", "kind": "input", "trust": "untrusted", "status": "untested",
     "intervention": "input:msg:planner->executor", "test": None, "reuse": 0.3},
    {"node": None, "label": "planner->executor", "kind": "message", "status": "untested",
     "intervention": "channel:planner->executor", "test": None}]}
WHY_TEXT = """Why did executor run send_email?
Not tested yet. 2 inputs and channels reached this action. Start with the untrusted ones.
How it got here:
1. input · executor · task (record 6)
2. input · executor · msg:planner->executor (untrusted) (record 16)
3. model call · executor · mock
4. tool call · executor · send_email (record 27)
run w1"""


class WhyCauses(unittest.TestCase):
    """WHY's verdict and chain could only be read on the page, a candidate cause linked to nothing, and its test's
    command was a template with SPEC to fill in (Causeway U25: a ready command per cause)."""

    def body(self, run):
        return json.loads(page_js(["esc", "shq", "cp", "WSTATUS", "CHAIN", "pct", "effectBar", "verdict", "lineageHtml",
                                   "WTYPE", "PROV", "recSeq", "whyText", "whyBody"], f"""
            const WTARGET = {{}}, WJOINT = new Set(), WBUSY = null, WMSG = "", d = {json.dumps(run)}, A = {json.dumps(WHY_CALL)};
            process.stdout.write(JSON.stringify([whyText({{ run: "w1", node: "ev:call" }}, d, A), whyBody({{ run: "w1", node: "ev:call" }}, d, A).join("")]));"""))

    def test_the_explanation_is_the_verdict_the_chain_with_its_records_and_the_run(self):
        needs_node(self)
        self.assertEqual(self.body(WHY_RUN)[0], WHY_TEXT)

    def test_each_cause_links_its_node_and_record_and_has_its_ready_command(self):
        needs_node(self)
        page = self.body(WHY_RUN)[1]
        copies = [html.unescape(v) for v in re.findall(r'data-copy="([^"]*)"', page)]
        self.assertEqual(copies, [WHY_TEXT,
                                  "tracekit why test '/runs/w 1' --system 'app:System' --remove "
                                  "'input:msg:planner->executor' --target 'tool=send_email'",
                                  "tracekit why test '/runs/w 1' --system 'app:System' --remove "
                                  "'channel:planner->executor' --target 'tool=send_email'"])
        self.assertIn('title="copy">COPY THIS EXPLANATION</button>', page)
        self.assertIn('<a href="#" data-wopen="ev:msg" data-wr="w1">planner-&gt;executor</a> '
                      '<a href="#" data-tkseq="16">record&nbsp;16</a>', page)
        self.assertEqual(page.count("data-wopen="), 2)   # the call's DETAILS and the input; the channel has no node
        # a run that names no program has no ready command: only the explanation is copied
        nothing = self.body({**WHY_RUN, "replay": {"program": "", "allowed": False}})[1]
        self.assertEqual(len(re.findall(r"data-copy=", nothing)), 1)

    def test_a_copy_button_returns_to_its_own_label(self):
        self.assertIn("const label = b.dataset.label ??= b.textContent;", PAGE)
        self.assertIn('setTimeout(() => { b.textContent = label; }, 1200)', PAGE)


PAGE_TEXT = " ".join(PAGE.split())
APPROVALS_PAGE = observe.read_text(os.path.join(os.path.dirname(observe.UI), "approvals.html"))
RUNS_PAGE = observe.read_text(os.path.join(os.path.dirname(observe.UI), "runs.html"))


class NothingLost(unittest.TestCase):
    """v7 moved today's viewer into pages and a run's views (the decision of 27 Oct 17:55 in #439): one check per row of
    its table and per item of the Keep list, so a later change that drops a feature fails here."""

    def test_every_global_page_and_run_view_is_reachable(self):
        needs_node(self)
        out = json.loads(page_js(["PAGES", "RVIEWS", "show", "centre"], """
            let PAGE = "desk", RV = "calls", CALLSLOG = false; const goLive = () => { PAGE = "run"; }, seen = {};
            for (const v of [...PAGES, ...RVIEWS, "timeline"]) { show(v); seen[v] = [PAGE, RV, centre()]; }
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, {
            "desk": ["desk", "calls", "desk"], "runs": ["runs", "calls", "desk"], "live": ["run", "calls", "desk"],
            "approvals": ["approvals", "calls", "desk"], "permissions": ["permissions", "calls", "permissions"],
            "influence": ["influence", "calls", "influence"], "overview": ["run", "overview", "overview"],
            "calls": ["run", "calls", "desk"], "waterfall": ["run", "waterfall", "desk"], "graph": ["run", "graph", "graph"],
            "why": ["run", "why", "why"], "agents": ["run", "agents", "agents"], "evidence": ["run", "evidence", "evidence"],
            "timeline": ["run", "calls", "timeline"]})   # the why log's TIMELINE: CALLS with its events

    def test_each_page_places_the_panels_it_had(self):
        css = PAGE[PAGE.index("<style>"):PAGE.index("</style>")]
        for rule in ("body.pg-run main>.p.agents", "body.pg-run main>.p.mix", "body.pg-run main>.p.detail",
                     "body.pg-run.rv-calls:not(.callslog) main>.p.tape", "body.pg-run.rv-waterfall main>.p.lanes",
                     "body.pg-run.wv main>.p.whyv", "body.pg-runs main>.p.runsp", "body.pg-approvals main>.p.apprp",
                     "body.pg-permissions main>.p.whyv", "body.pg-influence main>.p.whyv"):
            self.assertIn(rule, css)
        # DESK is today's grid: every panel, the stats strip and NEEDS YOU
        self.assertIn("body:not(.pg-desk) main>.p", css)
        for panel in ("agents", "tape", "alerts", "mix", "lanes", "reason", "files", "detail"):
            self.assertIn(f'<section class="p {panel}">', PAGE)

    def test_todays_features_are_each_still_there(self):
        rows = {
            "stats strip": ['["RUNS", scope ? 1', '"HIGH ALERTS"', '"RECORDS", signed'],
            "chain badge": ["CHAIN ✓ ${chainState.n} SIGNED RECORDS"],
            "clock and zone": ['$("clock").textContent'],
            "tape columns": ["TIME", "AGENT", "EVT", "TOOL", "TARGET / TEXT", "STATUS", "MS"],
            "alerts with why": ['<span class="src">WHY</span>'],
            "tool mix": ["function renderMix()"], "lanes": ["TIMELINE · ONE LANE PER AGENT"],
            "timeline by call and by agent": ["function renderWaterfall()", "TIMELINE · ONE ROW PER CALL",
                                              'data-wfby="call"', 'data-wfby="agent"', '<pattern id="wfhatch"',
                                              '"waiting for a person"'],
            "reasoning": ["REASONING<small>self-reported, not proof</small>"],
            "files": ["<th>PATH</th>", "LAST AGENT"],
            "detail, why, node": ['data-wtab="detail"', 'data-wtab="why"', 'data-wtab="node"', "LEDGER EVIDENCE · SEQ"],
            "modes": ['"STATIC"', '"BUNDLE"', '"STOPPED"', '"DISCONNECTED"', '"REPLAY"', 'id="lost"'],
            "replay": ['id="play"', 'id="speed"', 'id="scrub"', 'id="rback"', 'id="rfwd"', 'data-jump="deny"',
                       'data-jump="hold"', 'data-jump="gap"', 'id="rlive"'],
            "why views": ["function overviewView(", "function timelineView(", "function whyView(", "function graphView(",
                          "function agentsView(", "function influenceView(", "function runsView(", "function renderNode(",
                          "FIND THE CAUSE", "RUN TEST", "inferred links", "ruled-out tests", "ACTUAL SIZE",
                          "CLEAR HIGHLIGHT", "SHOW WHAT IT REACHED", "INFLUENCE MATRIX", "CRITICAL PATH",
                          "HOW TO READ THE EVIDENCE"],
            "new v7 pieces": ["function renderRunHead()", "function renderRunsPage()", "function renderApprovalsPage()",
                              "function evidenceView(", "NEEDS YOU", "WHY THIS DECISION", "WAITING FOR YOU"],
            "evidence": ["function evidenceOf(", "CHAIN · EACH SIGNED RECORD IN ORDER",
                         "CHECKS · THE VIEWER'S VERIFIER REPORT", '<div class="stamp ${esc(e.stamp[0])}">',
                         "reviewHtml(r, false)", "VERIFIER REPORT · AS THE VIEWER PRINTED IT"],
            "graph graded by proof": ["function edgeGrade(", "function netEffects(", "signed: both ends are signed records",
                                      "recorded flow", "observed: a sensor saw it",
                                      "blocked: its signed decision stopped the call", "network effect\")} a sensor saw"],
            "why cause chains": ["function whyText(", '"COPY THIS EXPLANATION"', 'data-wopen="${esc(c.node)}"',
                                 'data-tkseq="${esc(seq)}">record&nbsp;${esc(seq)}',
                                 "tracekit why test ${path} --system ${prog} --remove ${shq(c.intervention)} --target ${tq}"],
            "honesty tips": ["A row is a signed record of the hash-chained ledger unless it says ANALYSIS",
                             "Times are this browser's local time",
                             "Reasoning is what the model reported about itself; actions are what it did",
                             "trust.json pins the signer's log key; that check, not this page, is the evidence",
                             "Download the bundle and check it with tracekit verify from the signed release: that, "
                             "not this page, is the evidence", "THE VIEWER'S CHECK, OPERATOR-SIDE", "operator-side"],
            "security": ["const esc = s =>", "const vis = s =>", "\\\\u\" + c.charCodeAt(0)"],
        }
        for feature, marks in rows.items():
            for mark in marks:
                with self.subTest(feature=feature, mark=mark):
                    self.assertIn(mark, PAGE_TEXT)

    def test_every_command_and_key_is_still_parsed(self):
        for cmd in ("AGT", "TOOL", "FILE", "FIND", "FLAG", "CLR", "SEQ", "HELP", "PAUSE", "PLAY", "SPEED"):
            with self.subTest(cmd=cmd):
                self.assertIn(f'case "{cmd}":', PAGE)
        for key in ('e.key === "/"', 'e.key === "Escape"', 'e.key === "f"', 'e.key === "?"', 'e.key === "t"',
                    '" ": togglePlay', "ArrowLeft:", "ArrowRight:", 'd: () => jump("deny")', 'h: () => jump("hold")',
                    'g: () => jump("gap")', "l: () => R && stopRun()", "/^[1-7]$/.test(e.key)"):
            with self.subTest(key=key):
                self.assertIn(key, PAGE)

    def test_the_run_and_approval_pages_keep_their_controls(self):
        for mark in ('id="run"', 'id="agent"', 'id="tenant"', 'id="since"', 'id="until"', 'id="verdict"', 'id="gaps"',
                     'id="denies"', 'id="approvals"', ">Log<", ">Tenant<", ">Ended<", "More runs", "More records",
                     'id="download"'):
            with self.subTest(page="runs.html", mark=mark):
                self.assertIn(mark, RUNS_PAGE)
        for mark in ('id="register"', 'id="filter"', "Expires", "Answered by", 'id="args"', 'id="reason"',
                     "Revoke the agent's approval", "5000"):
            with self.subTest(page="approvals.html", mark=mark):
                self.assertIn(mark, APPROVALS_PAGE)


if __name__ == "__main__":
    unittest.main()
