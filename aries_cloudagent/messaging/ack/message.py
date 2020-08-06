"""Represents an explicit ack message as per Aries RFC 15."""

from marshmallow import fields

from ..agent_message import AgentMessage, AgentMessageSchema
from ..models.base import SchemaMeta


class Ack(AgentMessage):
    """
    Base class representing an explicit ack message.

    Subclass to adopt, specify Meta message type and handler class.
    """

    class Meta:
        """Ack metadata."""

        schema_class = "AckSchema"

    def __init__(self, status: str = None, **kwargs):
        """
        Initialize an explicit ack message instance.

        Args:
            status: Status (default OK)

        """
        super().__init__(**kwargs)
        self.status = status or "OK"


@SchemaMeta()
class AckSchema(AgentMessageSchema):
    """Schema for Ack base class."""

    status = fields.Constant(
        constant="OK",
        required=True,
        description="Status: specify OK",
        default="OK",
        example="OK",
    )
