"""Issuer credential revocation information."""

from typing import Any, Sequence

from marshmallow import fields

from ...config.injection_context import InjectionContext
from ...messaging.models.base_record import BaseRecord, BaseRecordSchema
from ...messaging.valid import INDY_DID, INDY_RAW_PUBLIC_KEY, UUIDFour


class DidVerkeyRecord(BaseRecord):
    """Represents credential revocation information to retain post-issue."""

    class Meta:
        """DidVerkeyRecord metadata."""

        schema_class = "DidVerkeyRecordSchema"

    RECORD_TYPE = "did_verkey"
    RECORD_ID_NAME = "record_id"
    TAG_NAMES = {"did", "verkey"}

    def __init__(
        self,
        *,
        record_id: str = None,
        did: str = None,
        verkey: str = None,
        **kwargs,
    ):
        """Initialize a new DidVerkeyRecord."""
        super().__init__(record_id, **kwargs)
        self.did = did
        self.verkey = verkey

    @property
    def record_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id

    @classmethod
    async def retrieve_by_did_verkey(
        cls,
        context: InjectionContext,
        *,
        did: str = None,
        verkey: str = None,
    ) -> "DidVerkeyRecord":
        """Retrieve a record by DID or verkey."""
        return await cls.retrieve_by_tag_filter(
            context,
            {
                **{"did": did for _ in [""] if did},
                **{"verkey": verkey for _ in [""] if verkey}
            }
        )

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class DidVerkeyRecordSchema(BaseRecordSchema):
    """Schema to allow de/serialization of records."""

    class Meta:
        """DidVerkeyRecordSchema metadata."""

        model_class = DidVerkeyRecord

    record_id = fields.Str(
        required=False,
        description="Issuer credential revocation record identifier",
        example=UUIDFour.EXAMPLE,
    )
    did = fields.Str(
        required=False,
        description="DID",
        **INDY_DID,
    )
    verkey = fields.Str(
        required=False,
        description="Verification key",
        **INDY_RAW_PUBLIC_KEY,
    )
