"""Aries#0037 v1.0 presentation exchange information with non-secrets storage."""

from typing import Any, Mapping, Union

from marshmallow import fields, validate

from .....indy.sdk.artifacts import UNENCRYPTED_TAGS
from .....indy.sdk.artifacts.proof import IndyProof, IndyProofSchema
from .....indy.sdk.artifacts.proof_request import (
    IndyProofRequest,
    IndyProofRequestSchema,
)
from .....messaging.models import serial
from .....messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from .....messaging.valid import UUIDFour

from ..messages.presentation_proposal import (
    PresentationProposal,
    PresentationProposalSchema,
)
from ..messages.presentation_request import (
    PresentationRequest,
    PresentationRequestSchema,
)


class V10PresentationExchange(BaseExchangeRecord):
    """Represents an Aries#0037 v1.0 presentation exchange."""

    class Meta:
        """V10PresentationExchange metadata."""

        schema_class = "V10PresentationExchangeSchema"

    RECORD_TYPE = "presentation_exchange_v10"
    RECORD_ID_NAME = "presentation_exchange_id"
    RECORD_TOPIC = "present_proof"
    TAG_NAMES = {"~thread_id"} if UNENCRYPTED_TAGS else {"thread_id"}

    INITIATOR_SELF = "self"
    INITIATOR_EXTERNAL = "external"

    ROLE_PROVER = "prover"
    ROLE_VERIFIER = "verifier"

    STATE_PROPOSAL_SENT = "proposal_sent"
    STATE_PROPOSAL_RECEIVED = "proposal_received"
    STATE_REQUEST_SENT = "request_sent"
    STATE_REQUEST_RECEIVED = "request_received"
    STATE_PRESENTATION_SENT = "presentation_sent"
    STATE_PRESENTATION_RECEIVED = "presentation_received"
    STATE_VERIFIED = "verified"
    STATE_PRESENTATION_ACKED = "presentation_acked"

    def __init__(
        self,
        *,
        presentation_exchange_id: str = None,
        connection_id: str = None,
        thread_id: str = None,
        initiator: str = None,
        role: str = None,
        state: str = None,
        # presentation proposal message (_dict for backward compatibility)
        presentation_proposal_dict: Union[PresentationProposal, Mapping] = None,  # msg
        presentation_request: Union[IndyProofRequest, Mapping] = None,  # indy proof req
        presentation_request_dict: Union[PresentationRequest, Mapping] = None,  # msg
        presentation: Union[IndyProof, Mapping] = None,  # indy proof
        verified: str = None,
        auto_present: bool = False,
        error_msg: str = None,
        trace: bool = False,
        **kwargs
    ):
        """Initialize a new PresentationExchange."""
        super().__init__(presentation_exchange_id, state, trace=trace, **kwargs)
        self.connection_id = connection_id
        self.thread_id = thread_id
        self.initiator = initiator
        self.role = role
        self.state = state
        self.presentation_proposal_dict = serial(presentation_proposal_dict)
        self.presentation_request = serial(presentation_request)
        self.presentation_request_dict = serial(presentation_request_dict)
        self.presentation = serial(presentation)
        self.verified = verified
        self.auto_present = auto_present
        self.error_msg = error_msg
        self.trace = trace

    @property
    def presentation_exchange_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this presentation exchange."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "connection_id",
                "initiator",
                "presentation_proposal_dict",
                "presentation_request",
                "presentation_request_dict",
                "presentation",
                "role",
                "state",
                "auto_present",
                "error_msg",
                "verified",
                "trace",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class V10PresentationExchangeSchema(BaseExchangeSchema):
    """Schema for de/serialization of v1.0 presentation exchange records."""

    class Meta:
        """V10PresentationExchangeSchema metadata."""

        model_class = V10PresentationExchange

    presentation_exchange_id = fields.Str(
        required=False,
        description="Presentation exchange identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    connection_id = fields.Str(
        required=False,
        description="Connection identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    thread_id = fields.Str(
        required=False,
        description="Thread identifier",
        example=UUIDFour.EXAMPLE,  # typically a UUID4 but not necessarily
    )
    initiator = fields.Str(
        required=False,
        description="Present-proof exchange initiator: self or external",
        example=V10PresentationExchange.INITIATOR_SELF,
        validate=validate.OneOf(["self", "external"]),
    )
    role = fields.Str(
        required=False,
        description="Present-proof exchange role: prover or verifier",
        example=V10PresentationExchange.ROLE_PROVER,
        validate=validate.OneOf(["prover", "verifier"]),
    )
    state = fields.Str(
        required=False,
        description="Present-proof exchange state",
        example=V10PresentationExchange.STATE_VERIFIED,
    )
    presentation_proposal_dict = fields.Nested(
        PresentationProposalSchema(),
        required=False,
        description="Presentation proposal message",
    )
    presentation_request = fields.Nested(
        IndyProofRequestSchema(),
        required=False,
        description="(Indy) presentation request (also known as proof request)",
    )
    presentation_request_dict = fields.Nested(
        PresentationRequestSchema(),
        required=False,
        description="Presentation request message",
    )
    presentation = fields.Nested(
        IndyProofSchema(),
        required=False,
        description="(Indy) presentation (also known as proof)",
    )
    verified = fields.Str(  # tag: must be a string
        required=False,
        description="Whether presentation is verified: true or false",
        example="true",
        validate=validate.OneOf(["true", "false"]),
    )
    auto_present = fields.Bool(
        required=False,
        description="Prover choice to auto-present proof as verifier requests",
        example=False,
    )
    error_msg = fields.Str(
        required=False, description="Error message", example="Invalid structure"
    )
