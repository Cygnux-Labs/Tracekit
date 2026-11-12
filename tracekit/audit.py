"""tracekit audit: replay local coding-agent transcripts through the policy engine.

Read-only. Never starts a signer, never writes, never follows a symlink. A replay against today's policy, not a signed
record.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .agent_hooks import AGENT_NAMES, _blocked, tool as hook_tool
from .core import scrub
from .graph import _open_regular
from .hook import transcript_entries
from .report import DECISIONS, _counts, _days, _wait, call_text, share_rules, when
from .signer.service import DEFAULT_POLICY, _dotenv, _escaped, _shown, evaluate, load_policy
from .view import ENGINE_RULES
