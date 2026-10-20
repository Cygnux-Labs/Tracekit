# tracekit-stagehand

> **Experimental (v1):** this package builds on the v1 laptop signer and isn't part of the stable core
> ([what's stable](../../docs/support.md)).

Stagehand `act` / `extract` / `observe` / `goto` calls as policy-checked, signed `browser:<method>` steps
(`pip install ./contrib/stagehand`). A denied call raises `PermissionError`.

```python
from tracekit_stagehand import instrument_stagehand
page = instrument_stagehand(stagehand.page, tracer)
```

`browser_agent.py` runs offline against a Stagehand-shaped stand-in (plus Browser Use when installed). Browser Use itself
stays in core: `tracekit.adapters.browser`.
