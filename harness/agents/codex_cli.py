from .base import Adapter, register


@register
class CodexCLI(Adapter):
    """OpenAI Codex CLI (github.com/openai/codex). Not the Codex Security CLI."""

    name = "codex_cli"
    model_env = "CODEX_MODEL"
    # Operator fills in the non-interactive invocation for the installed
    # version, e.g. the CLI's exec/quiet mode reading the task file as the
    # prompt and running with the workspace as cwd. Confirm flags against
    # `codex --help` for the pinned version and record the version in the run log.
    command = None
