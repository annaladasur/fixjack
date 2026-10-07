from .base import Adapter, register


@register
class GeminiCLI(Adapter):
    """Google Gemini CLI (github.com/google-gemini/gemini-cli)."""

    name = "gemini_cli"
    model_env = "GEMINI_MODEL"
    # Operator fills in the non-interactive invocation for the pinned version
    # (prompt from the task file, workspace as cwd). Confirm against `gemini --help`.
    command = None
