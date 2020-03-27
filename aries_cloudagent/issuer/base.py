"""Ledger issuer class."""

from abc import ABC, ABCMeta, abstractmethod
from typing import Sequence, Tuple

from ..core.error import BaseError


DEFAULT_CRED_DEF_TAG = "default"
DEFAULT_ISSUANCE_TYPE = "ISSUANCE_BY_DEFAULT"
DEFAULT_SIGNATURE_TYPE = "CL"


class IssuerError(BaseError):
    """Generic issuer error."""


class IssuerRevocationRegistryFullError(IssuerError):
    """Revocation registry is full when issuing a new credential."""


class BaseIssuer(ABC, metaclass=ABCMeta):
    """Base class for issuer."""

    def __repr__(self) -> str:
        """
        Return a human readable representation of this class.

        Returns:
            A human readable string for this class

        """
        return "<{}>".format(self.__class__.__name__)

    @abstractmethod
    def make_schema_id(
        self, origin_did: str, schema_name: str, schema_version: str
    ) -> str:
        """Derive the ID for a schema."""

    @abstractmethod
    async def create_schema(
        self,
        origin_did: str,
        schema_name: str,
        schema_version: str,
        attribute_names: Sequence[str],
    ) -> Tuple[str, str]:
        """
        Create a new credential schema.

        Args:
            origin_did: the DID issuing the credential definition
            schema_name: the schema name
            schema_version: the schema version
            attribute_names: a sequence of schema attribute names

        Returns:
            A tuple of the schema ID and JSON

        """

    @abstractmethod
    def make_credential_definition_id(
        self, origin_did: str, schema: dict, signature_type: str = None, tag: str = None
    ) -> str:
        """Derive the ID for a credential definition."""

    @abstractmethod
    async def credential_definition_in_wallet(
        self, credential_definition_id: str
    ) -> bool:
        """
        Check whether a given credential definition ID is present in the wallet.

        Args:
            credential_definition_id: The credential definition ID to check
        """

    @abstractmethod
    async def create_and_store_credential_definition(
        self,
        origin_did: str,
        schema: dict,
        signature_type: str = None,
        tag: str = None,
        support_revocation: bool = False,
    ) -> Tuple[str, str]:
        """
        Create a new credential definition and store it in the wallet.

        Args:
            origin_did: the DID issuing the credential definition
            schema_json: the schema used as a basis
            signature_type: the credential definition signature type (default 'CL')
            tag: the credential definition tag
            support_revocation: whether to enable revocation for this credential def

        Returns:
            A tuple of the credential definition ID and JSON

        """

    @abstractmethod
    def create_credential_offer(self, credential_definition_id) -> str:
        """
        Create a credential offer for the given credential definition id.

        Args:
            credential_definition_id: The credential definition to create an offer for

        Returns:
            The created credential offer

        """

    @abstractmethod
    async def create_credential(
        self,
        schema: dict,
        credential_offer: dict,
        credential_request: dict,
        credential_values: dict,
        revoc_reg_id: str = None,
        tails_reader_handle: int = None,
    ) -> Tuple[str, str]:
        """
        Create a credential.

        Args
            schema: Schema to create credential for
            credential_offer: Credential Offer to create credential for
            credential_request: Credential request to create credential for
            credential_values: Values to go in credential
            revoc_reg_id: ID of the revocation registry
            tails_reader_handle: Handle for the tails file blob reader

        Returns:
            A tuple of created credential and revocation id

        """

    @abstractmethod
    def revoke_credential(
        self, revoc_reg_id: str, tails_file_path: str, cred_revoc_id: str
    ) -> str:
        """
        Revoke a credential.

        Args:
            revoc_reg_id: ID of the revocation registry
            tails_file_path: path to the local tails file
            cred_revoc_id: index of the credential in the revocation registry

        Returns:
            the revocation delta

        """

    @abstractmethod
    async def create_and_store_revocation_registry(
        self,
        origin_did: str,
        cred_def_id: str,
        revoc_def_type: str,
        tag: str,
        max_cred_num: int,
        tails_base_path: str,
        issuance_type: str = None,
    ) -> Tuple[str, str, str]:
        """
        Create a new revocation registry and store it in the wallet.

        Args:
            origin_did: the DID issuing the revocation registry
            cred_def_id: the identifier of the related credential definition
            revoc_def_type: the revocation registry type (default CL_ACCUM)
            tag: the unique revocation registry tag
            max_cred_num: the number of credentials supported in the registry
            tails_base_path: where to store the tails file
            issuance_type: optionally override the issuance type

        Returns:
            A tuple of the revocation registry ID, JSON, and entry JSON

        """
