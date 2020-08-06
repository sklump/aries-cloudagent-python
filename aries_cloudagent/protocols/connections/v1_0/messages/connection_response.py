"""Represents a connection response message."""

from marshmallow import fields

from .....messaging.agent_message import AgentMessage, AgentMessageSchema
from .....messaging.models.base import SchemaMeta

from ..message_types import CONNECTION_RESPONSE, PROTOCOL_PACKAGE
from ..models.connection_detail import ConnectionDetail, ConnectionDetailSchema

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers."
    "connection_response_handler.ConnectionResponseHandler"
)


class ConnectionResponse(AgentMessage):
    """Class representing a connection response."""

    class Meta:
        """Metadata for a connection response."""

        handler_class = HANDLER_CLASS
        schema_class = "ConnectionResponseSchema"
        message_type = CONNECTION_RESPONSE

    def __init__(self, *, connection: ConnectionDetail = None, **kwargs):
        """
        Initialize connection response object.

        Args:
            connection: Connection details object

        """
        super().__init__(**kwargs)
        self.connection = connection


@SchemaMeta(signed_fields=("connection",))
class ConnectionResponseSchema(AgentMessageSchema):
    """Connection response schema class."""

    connection = fields.Nested(ConnectionDetailSchema, required=True)
