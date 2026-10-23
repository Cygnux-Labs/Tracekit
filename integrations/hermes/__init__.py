"""Tracekit for Hermes Agent: the Tracekit signer decides every tool call before it runs and records its outcome.
The hooks are tracekit.integrations.hermes, from the tracekit-ai package:
https://github.com/Cygnux-Labs/Tracekit/wiki/Integrations-Hermes
"""


def register(ctx):
    try:
        from agent.secret_scope import get_secret
        from hermes_cli.config import load_config_readonly
        from tracekit.integrations.hermes import hook_timeout_s, hooks
    except Exception as e:   # Hermes would run every call ungated without the hooks: they block instead
        why = (f"Tool call blocked: the Tracekit plugin can't load ({type(e).__name__}: {e}). Install tracekit-ai in "
               "Hermes's environment, or disable the plugin (hermes plugins disable tracekit)")

        def pre_tool_call(**_):
            return {"action": "block", "message": why}

        def post_tool_call(**_):
            return None
    else:
        pre_tool_call, post_tool_call = hooks(lambda: get_secret("TRACEKIT_SIGNER_TOKEN"),
                                              lambda: hook_timeout_s(load_config_readonly()))
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)
