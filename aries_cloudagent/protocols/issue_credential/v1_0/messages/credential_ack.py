"""A credential ack message."""

from .....messaging.ack.message import Ack, AckSchema
from .....messaging.models.base import SchemaMeta

from ..message_types import CREDENTIAL_ACK, PROTOCOL_PACKAGE

HANDLER_CLASS = (
    f"{PROTOCOL_PACKAGE}.handlers.credential_ack_handler.CredentialAckHandler"
)


class CredentialAck(Ack):
    """Class representing a credential ack message."""

    class Meta:
        """Credential metadata."""

        handler_class = HANDLER_CLASS
        schema_class = "CredentialAckSchema"
        message_type = CREDENTIAL_ACK

    def __init__(self, **kwargs):
        """Initialize credential object."""
        super().__init__(**kwargs)


@SchemaMeta()
class CredentialAckSchema(AckSchema):
    """Credential ack schema."""
