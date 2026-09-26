import api


def test_slow_upstream_succeeds():
    # The upstream SLA is 5 seconds, so a 4-second call must succeed.
    assert api.fetch(4)["ok"]


def test_fast_upstream_succeeds():
    assert api.fetch(0.1)["ok"]
