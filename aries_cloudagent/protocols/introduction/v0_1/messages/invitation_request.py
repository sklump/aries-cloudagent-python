"""Represents an request for an invitation from the introduction service."""

from marshmallow import fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.models.base import SchemaMeta

from ..message_types import INVITATION_REQUEST, PROTOCOL_PACKAGE

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.invitation_request_handler.InvitationRequestHandler"
)


class InvitationRequest(AgentMessage):
    """Class representing an invitation request."""

    class Meta:
        """Metadata for an invitation request."""

        handler_class = HANDLER_CLASS
        message_type = INVITATION_REQUEST
        schema_class = "InvitationRequestSchema"

    def __init__(self, *, responder: str = None, message: str = None, **kwargs):
        """
        Initialize invitation request object.

        Args:
            responder: The name of the agent initiating the introduction
            message: Comments on the introduction
        """
        super().__init__(**kwargs)
        self.responder = responder
        self.message = message


@SchemaMeta()
class InvitationRequestSchema(AgentMessageSchema):
    """Invitation request schema class."""

    responder = fields.Str(
        required=True,
        description="Agent name initiating the introduction",
        example="Alice's agent",
    )
    message = fields.Str(
        required=False,
        allow_none=True,
        description="Comments on the introduction",
        example="Hello Bob, it's Alice",
    )
