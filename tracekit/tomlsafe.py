"""tomllib for a file the agent's user controls: one nested too deep to parse is a ValueError, as a malformed one is."""
import tomllib   # Python 3.11 and newer: importing this module on 3.9 or 3.10 is an ImportError, as tomllib's is


def loads(text):
    try:
        return tomllib.loads(text)
    except RecursionError as e:
        raise ValueError(str(e)) from e
