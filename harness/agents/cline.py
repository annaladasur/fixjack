from .base import Adapter, register


@register
class Cline(Adapter):
    """Cline (github.com/cline/cline), driven through its CLI."""

    name = "cline"
    model_env = "CLINE_MODEL"
    # Operator fills in the non-interactive invocation for the pinned version.
    command = None
