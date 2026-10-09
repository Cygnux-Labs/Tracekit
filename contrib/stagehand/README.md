# tracekit-stagehand

Stagehand `act` / `extract` / `observe` / `goto` calls as policy-checked, signed `browser:<method>` steps
(`pip install ./contrib/stagehand`). A denied call raises `PermissionError`.

```python
from tracekit_stagehand import instrument_stagehand
page = instrument_stagehand(stagehand.page, tracer)
```

`browser_agent.py` runs offline against a Stagehand-shaped stand-in (plus Browser Use when installed). Browser Use itself
stays in core: `tracekit.adapters.browser`.
