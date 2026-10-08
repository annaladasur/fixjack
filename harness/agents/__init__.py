"""Agent adapters. Each wraps one open-source coding agent behind the same
interface so the harness can drive them identically and log the model id.

The invocation for each agent is the operator's to confirm against the
agent's current CLI; the adapters document the shape and fail loudly until
`command` is filled in.
"""
from .base import Adapter, RunResult, get_adapter, register

__all__ = ["Adapter", "RunResult", "get_adapter", "register"]

from . import cline, codex_cli, gemini_cli, openhands  # noqa: E402,F401  (registers adapters)
