"""Represents a request for an action menu."""

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.models.base import SchemaMeta

from ..message_types import MENU_REQUEST, PROTOCOL_PACKAGE

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.menu_request_handler.MenuRequestHandler"


class MenuRequest(AgentMessage):
    """Class representing a request for an action menu."""

    class Meta:
        """Metadata for action menu request."""

        handler_class = HANDLER_CLASS
        message_type = MENU_REQUEST
        schema_class = "MenuRequestSchema"

    def __init__(self, **kwargs):
        """Initialize a menu request object."""
        super().__init__(**kwargs)


@SchemaMeta()
class MenuRequestSchema(AgentMessageSchema):
    """MenuRequest schema class."""
