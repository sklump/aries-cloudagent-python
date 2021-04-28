"""Record for out of band invitations."""

from typing import Any, Mapping, Union

from marshmallow import fields

from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import UUIDFour

from ..messages.invitation import InvitationMessage, InvitationMessageSchema


class InvitationRecord(BaseExchangeRecord):
    """Represents an out of band invitation record."""

    class Meta:
        """InvitationRecord metadata."""

        schema_class = "InvitationRecordSchema"

    RECORD_TYPE = "oob_invitation"
    RECORD_ID_NAME = "invitation_id"
    RECORD_TOPIC = "oob_invitation"
    TAG_NAMES = {"invi_msg_id"}

    STATE_INITIAL = "initial"
    STATE_AWAIT_RESPONSE = "await_response"
    STATE_DONE = "done"

    def __init__(
        self,
        *,
        invitation_id: str = None,
        state: str = None,
        invi_msg_id: str = None,
        invitation: Union[InvitationMessage, Mapping] = None,  # invitation message
        invitation_url: str = None,
        trace: bool = False,
        public_did: str = None,  # For backward compatibility, BaseRecord.from_storage()
        **kwargs,
    ):
        """Initialize a new InvitationRecord."""
        super().__init__(invitation_id, state, trace=trace, **kwargs)
        self._id = invitation_id
        self.state = state
        self.invi_msg_id = invi_msg_id
        # self.invitation = InvitationMessage.deserialize(invitation)
        self.invitation = (
            invitation.serialize()
            if isinstance(invitation, InvitationMessage)
            else invitation
        )
        self.invitation_url = invitation_url
        self.trace = trace

    @property
    def invitation_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for the JSON record value generated for this invitation."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "invitation",
                "invitation_url",
                "state",
                "trace",
            )
        }

    def serialize(self, as_string=False) -> dict:
        """
        Create a JSON-compatible dict representation of the model instance.

        Args:
            as_string: Return a string of JSON instead of a dict

        Returns:
            A dict representation of this model, or a JSON string if as_string is True

        """
        copy = InvitationRecord(
            invitation_id=self.invitation_id,
            state=self.state,
            invi_msg_id=self.invi_msg_id,
            invitation=None,
            invitation_url=self.invitation_url,
            public_did=None,
            trace=self.trace,
        )
        copy.invitation = InvitationMessage.deserialize(self.invitation)
        return super(self.__class__, copy).serialize(as_string)

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class InvitationRecordSchema(BaseExchangeSchema):
    """Schema to allow serialization/deserialization of invitation records."""

    class Meta:
        """InvitationRecordSchema metadata."""

        model_class = InvitationRecord

    invitation_id = fields.Str(
        required=False,
        description="Invitation record identifier",
        example=UUIDFour.EXAMPLE,
    )
    state = fields.Str(
        required=False,
        description="Out of band message exchange state",
        example=InvitationRecord.STATE_AWAIT_RESPONSE,
    )
    invi_msg_id = fields.Str(
        required=False,
        description="Invitation message identifier",
        example=UUIDFour.EXAMPLE,
    )
    invitation = fields.Nested(
        InvitationMessageSchema(),
        required=False,
        description="Out of band invitation message",
    )
    invitation_url = fields.Str(
        required=False,
        description="Invitation message URL",
        example=(
            "https://example.com/endpoint?"
            "c_i=eyJAdHlwZSI6ICIuLi4iLCAiLi4uIjogIi4uLiJ9XX0="
        ),
    )
