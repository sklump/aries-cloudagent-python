"""Issuer storage handling for credential revocation data."""

import logging
import re

from typing import Any, Sequence

from marshmallow import fields

from ...config.injection_context import InjectionContext
from ...messaging.models.base_record import BaseRecord, BaseRecordSchema
from ...messaging.valid import (  # TODO update
    INDY_CRED_REV_ID,
    INDY_SCHEMA_ID,
    UUIDFour,
)

LOGGER = logging.getLogger(__name__)


class IssuerCredentialRecord(BaseRecord):
    """Class for issuer to retain tracking credential revocation data."""

    class Meta:
        """IssuerCredentialRecord metadata."""

        schema_class = "IssuerCredentialRecordSchema"

    RECORD_ID_NAME = "record_id"
    RECORD_TYPE = "issuer_rev_reg"
    LOG_STATE_FLAG = "debug.revocation"
    CACHE_ENABLED = False
    TAG_NAMES = {
        "schema_id",
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
        schema_id: str = None,
        rev_reg_id: str = None,
        cred_rev_id: str = None,
        cred_values: dict = None,
        **kwargs,
    ):
        """Initialize the issuer credential record."""
        super().__init__(
            record_id, state=state or IssuerCredentialRecord.STATE_ISSUED, **kwargs
        )

        self.rev_reg_id = rev_reg_id
        if rev_reg_id:
            cd_id_match = re.match(r"^.*?:4:(.*:3:CL:[^:]+:[^:]+):.*", rev_reg_id)
            self.cred_def_id = cd_id_match.group(1) if cd_id_match else None
        self.schema_id = schema_id
        self.cred_rev_id = cred_rev_id
        self.cred_values = cred_values

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
    async def query_by_values(
        cls,
        context: InjectionContext,
        cred_values: dict,
        *,
        ident: str = None,
        state: str = None
    ) -> Sequence["IssuerCredentialRecord"]:
        """Retrieve issuer credential records by credential values.

        Args:
            context: The injection context to use
            cred_values: The credential values to match
            ident: schema id or cred def id to match
            state: A state value to filter by
        """
        tag_filter = {
            "cred_def_id" if ":3:" in ident else "schema_id": ident,
            **{"state": state for _ in [""] if state}
        }
        records = await cls.query(context, tag_filter)
        result = [
            r for r in records if cred_values.items() <= r.value["cred_values"].items()
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
    schema_id = fields.Str(
        required=False,
        description="Schema identifier",
        **INDY_SCHEMA_ID,
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
