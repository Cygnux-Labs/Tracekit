"""The actions of a tool executor (tracekit/executor.py) as framework tools. The agent holds only its run: the executor
holds the actions' credentials and decides, runs and records each call in the signer (tier T2). docs/executor.md.

    from tracekit.integrations import executor_tools as ex
    run = signer.register_run({"request_id": "r1", "agent": {"name": "payer"}})
    actions = ex.actions("https://executor.internal:8090", run, headers={"authorization": "Bearer ..."})
    tools = [ex.openai_agents(a) for a in actions]               # agents.FunctionTool
    tools = [ex.langchain(a) for a in actions]                   # langchain_core StructuredTool
    server = ex.claude_agent_sdk(actions)                        # ClaudeAgentOptions(mcp_servers={"executor": server})

`headers` authenticate the agent to the executor (its `http.authenticators`: a bearer token, a service-account
token); `context` is an ssl.SSLContext for its CA and a client certificate. The Tracekit adapters leave these tools to
the executor, which decides and records them: each is marked (EXECUTOR), and the Claude Agent SDK hooks skip the tools
of the MCP server named SERVER. A refusal (deny, an approval not given, the signer unreachable) raises
ExecutorRefused with the executor's message, which each framework hands the model as the tool's error.
"""
import asyncio
import json
import urllib.error
import urllib.request

from tracekit.client import no_redirect_opener, remote_url_error

EXECUTOR = "tracekit_executor"   # set on the tools built here (a LangChain tool's metadata key): adapters don't gate them
SERVER = "tracekit-executor"     # claude_agent_sdk's server: tools mcp__tracekit-executor__<action>


class ExecutorRefused(Exception):
    pass


class Action:
    def __init__(self, url, run, spec, headers, context):
        self.name, self.description, self.args = spec["name"], spec["description"], spec["args"]
        self._url, self._context = f"{url.rstrip('/')}/v1/actions/{self.name}", context
        self._headers = {**headers, "content-type": "application/json",
                         "x-tracekit-run": f"{run['run_id']}.{run['run_token']}"}

    def __call__(self, args, tool_call_id=None):
        """{"status": the upstream's HTTP status, "result": its JSON or text}; ExecutorRefused when it did not run."""
        body = json.dumps({"args": args, **({"tool_call_id": tool_call_id} if tool_call_id else {})}).encode()
        try:
            return _get(urllib.request.Request(self._url, body, self._headers, method="POST"), self._context)
        except urllib.error.HTTPError as e:
            try:
                why = json.loads(e.read())["error"]["message"]
            except (ValueError, KeyError, TypeError):
                why = f"tracekit executor: HTTP {e.code}"
            raise ExecutorRefused(why) from None


def _get(req, context):
    # the agent's credential for the executor never follows a redirect
    with no_redirect_opener(context).open(req, timeout=600) as r:   # an action held for an approval answers once a person decides
        return json.loads(r.read())


def actions(url, run, headers=None, context=None):
    """The executor's actions, each callable for `run` (a register_run response: run_id, run_token)."""
    if remote_url_error(url):   # the run token and the agent's credential for the executor never go in clear
        raise ValueError(f"{url[:256]}: {remote_url_error(url)}")
    listed = _get(urllib.request.Request(f"{url.rstrip('/')}/v1/actions", headers=headers or {}), context)
    return [Action(url, run, a, headers or {}, context) for a in listed["actions"]]


def openai_agents(action):
    from agents import FunctionTool

    async def invoke(ctx, raw):
        return json.dumps(await asyncio.to_thread(action, json.loads(raw or "{}"), ctx.tool_call_id))
    t = FunctionTool(name=action.name, description=action.description, params_json_schema=action.args,
                     on_invoke_tool=invoke, strict_json_schema=False)
    setattr(t, EXECUTOR, True)
    return t


def langchain(action):
    from langchain_core.tools import StructuredTool, ToolException

    def run(**args):
        try:
            return json.dumps(action(args))
        except ExecutorRefused as e:
            raise ToolException(str(e)) from None
    return StructuredTool.from_function(run, name=action.name, description=action.description,
                                        args_schema=action.args, handle_tool_error=True, metadata={EXECUTOR: True})


def claude_agent_sdk(actions, name=SERVER):
    from claude_agent_sdk import create_sdk_mcp_server, tool

    def one(action):
        async def handler(args):
            try:
                out = await asyncio.to_thread(action, args)
            except ExecutorRefused as e:
                return {"content": [{"type": "text", "text": str(e)}], "is_error": True}
            return {"content": [{"type": "text", "text": json.dumps(out)}]}
        return tool(action.name, action.description, action.args)(handler)
    return create_sdk_mcp_server(name, tools=[one(a) for a in actions])
