"""Issuer storage handling for credential revocation data."""

import logging

from typing import Any, Sequence

from marshmallow import fields

from ...config.injection_context import InjectionContext
from ...messaging.models.base_record import BaseRecord, BaseRecordSchema
from ...messaging.valid import (
    INDY_CRED_DEF_ID,
    INDY_CRED_REV_ID,
    INDY_REV_REG_ID,
    UUIDFour,
)

LOGGER = logging.getLogger(__name__)


class IssuerCredentialRecord(BaseRecord):
    """Class for issuer to retain tracking credential revocation data."""

    class Meta:
        """IssuerCredentialRecord metadata."""

        schema_class = "IssuerCredentialRecordSchema"

    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "issuer_cred"
    LOG_STATE_FLAG = "debug.revocation"
    CACHE_ENABLED = False
    TAG_NAMES = {
        "cred_def_id",
        "rev_reg_id",
        "cred_rev_id",
        "state",
    }

    ISSUANCE_BY_DEFAULT = "ISSUANCE_BY_DEFAULT"
    ISSUANCE_ON_DEMAND = "ISSUANCE_ON_DEMAND"

    STATE_ISSUED = "issued"
    STATE_REVOKED = "revoked"

    def __init__(
        self,
        *,
        record_id: str = None,
        state: str = None,
        cred_def_id: str = None,
        rev_reg_id: str = None,
        cred_rev_id: str = None,
        cred_values: dict = None,
        **kwargs,
    ):
        """Initialize the issuer credential record."""
        super().__init__(
            record_id, state=state or IssuerCredentialRecord.STATE_ISSUED, **kwargs
        )

        self.cred_def_id = cred_def_id
        self.rev_reg_id = rev_reg_id
        self.cred_rev_id = cred_rev_id
        self.cred_values = {
            attr: str(value) for (attr, value) in cred_values.items()
        } if cred_values else None

    @property
    def record_id(self) -> str:
        """Accessor for the record ID."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON value properties of this issuer credential record."""
        return {
            prop: getattr(self, prop) for prop in ("cred_values",)
        }

    @classmethod
    async def query_revocable(
        cls,
        context: InjectionContext,
        cred_def_id: str,
        cred_values: dict,
        *,
        state: str = None
    ) -> Sequence["IssuerCredentialRecord"]:
        """Retrieve issuer credential records by cred def id and credential values.

        Args:
            context: The injection context to use
            cred_def_id: cred def id to match
            cred_values: Mapping of attribute names to values to match
            state: A state value by which to filter (default STATE_ISSUED)

        """
        tag_filter = {
            "cred_def_id": cred_def_id,
            "state": state or IssuerCredentialRecord.STATE_ISSUED
        }

        cred_values_raw = {
            attr: str(value) for (attr, value) in cred_values.items()
        }
        records = await cls.query(context, tag_filter)
        result = [
            r for r in records if cred_values_raw.items() <= r.value[
                "cred_values"
            ].items()
        ]
        return result

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class IssuerCredentialRecordSchema(BaseRecordSchema):
    """Schema to allow serialization/deserialization of revocation registry records."""

    class Meta:
        """IssuerCredentialRecordSchema metadata."""

        model_class = IssuerCredentialRecord

    record_id = fields.Str(
        required=False,
        description="Issuer credential record identifier",
        example=UUIDFour.EXAMPLE,
    )
    state = fields.Str(
        required=False,
        description="Issue credential record state",
        example=IssuerCredentialRecord.STATE_ISSUED,
    )
    cred_def_id = fields.Str(
        required=False,
        description="Credential definition identifier",
        **INDY_CRED_DEF_ID
    )
    rev_reg_id = fields.Str(
        required=False,
        description="Revocation registry identifier",
        **INDY_REV_REG_ID
    )
    cred_rev_id = fields.Str(
        required=False,
        description="Credential revocation identifier",
        **INDY_CRED_REV_ID
    )
    cred_values = fields.Dict(
        required=False,
        description="Mapping of attribute names to their respective values",
        keys=fields.Str(
            description="attribute name",  # marshmallow 3.0 ignores
            example="favouriteDrink"
        ),
        values=fields.Str(
            description="attribute value",  # marshmallow 3.0 ignores
            example="martini"
        )
    )
