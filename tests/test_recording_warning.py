import warnings

from tracekit.integrations.recording_warning import warn_unrecorded


class _DummySignerError(Exception):
    def __init__(self, msg: str, recorded):
        super().__init__(msg)
        self.recorded = recorded


def test_warn_unrecorded_when_recorded_is_none():
    err = _DummySignerError("reply lost", recorded=None)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warn_unrecorded("MCP input_required", err)
    assert len(caught) == 1
    assert str(caught[0].message) == "tracekit: MCP input_required may not have been recorded: reply lost"


def test_warn_unrecorded_when_recorded_is_false_or_plain_exception():
    for err in (_DummySignerError("down", recorded=False), RuntimeError("boom")):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            warn_unrecorded("MCP input_required", err)
        assert len(caught) == 1
        assert str(caught[0].message).startswith("tracekit: MCP input_required not recorded: ")


def test_warn_unrecorded_silent_when_recorded_is_true():
    err = _DummySignerError("already recorded", recorded=True)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warn_unrecorded("MCP input_required", err)
    assert caught == []
