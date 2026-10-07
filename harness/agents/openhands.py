from .base import Adapter, register


@register
class OpenHands(Adapter):
    """OpenHands (github.com/OpenHands/OpenHands-CLI; runtime in software-agent-sdk)."""

    name = "openhands"
    model_env = "OPENHANDS_MODEL"
    # Operator fills in the headless invocation for the pinned CLI version
    # (task from the task file, workspace as cwd). Confirm against the CLI's help.
    command = None
