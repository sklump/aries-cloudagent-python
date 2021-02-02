"""Classes to manage connections."""

import logging
import asyncio
import json

from typing import Mapping, Sequence, Optional

from ....connections.models.conn_record import ConnRecord
from ....core.error import BaseError
from ....core.profile import ProfileSession
from ....multitenant.manager import MultitenantManager
from ....storage.error import StorageNotFoundError
from ....wallet.base import BaseWallet
from ....wallet.util import naked_to_did_key, b64_to_bytes, did_key_to_naked

from ...didexchange.v1_0.message_types import ARIES_PROTOCOL as DIDX_PROTO
from ...connections.v1_0.message_types import ARIES_PROTOCOL as CONN_PROTO
from ...didexchange.v1_0.manager import DIDXManager
from ...didcomm_prefix import DIDCommPrefix
from ...issue_credential.v1_0.models.credential_exchange import V10CredentialExchange
from ...issue_credential.v2_0.models.cred_ex_record import V20CredExRecord
from ...issue_credential.v2_0.messages.cred_offer import V20CredOffer
from ...present_proof.v1_0.message_types import PRESENTATION_REQUEST
from ...present_proof.v1_0.models.presentation_exchange import V10PresentationExchange

from .messages.invitation import InvitationMessage
from .messages.reuse import HandshakeReuse
from .messages.reuse_accept import HandshakeReuseAccept
from .messages.problem_report import ProblemReportReason, ProblemReport
from ....connections.base_manager import BaseConnectionManager
from ....transport.inbound.receipt import MessageReceipt

from .messages.service import Service as ServiceMessage
from .models.invitation import InvitationRecord

from ...connections.v1_0.manager import ConnectionManager
from ...present_proof.v1_0.manager import PresentationManager

from ...connections.v1_0.messages.connection_invitation import ConnectionInvitation
from ....ledger.base import BaseLedger
from ....messaging.responder import BaseResponder
from ...present_proof.v1_0.messages.presentation_proposal import PresentationProposal
from ...present_proof.v1_0.util.indy import indy_proof_req_preview2indy_requested_creds
from ....indy.holder import IndyHolder
from ....messaging.decorators.attach_decorator import AttachDecorator


class OutOfBandManagerError(BaseError):
    """Out of band error."""


class OutOfBandManagerNotImplementedError(BaseError):
    """Out of band error for unimplemented functionality."""


class OutOfBandManager(BaseConnectionManager):
    """Class for managing out of band messages."""

    def __init__(self, session: ProfileSession):
        """
        Initialize a OutOfBandManager.

        Args:
            session: The profile session for this out of band manager
        """
        self._session = session
        self._logger = logging.getLogger(__name__)
        super().__init__(self._session)

    @property
    def session(self) -> ProfileSession:
        """
        Accessor for the current profile session.

        Returns:
            The profile session for this connection manager

        """
        return self._session

    async def create_invitation(
        self,
        my_label: str = None,
        my_endpoint: str = None,
        auto_accept: bool = None,
        public: bool = False,
        include_handshake: bool = False,
        use_connections: bool = False,
        multi_use: bool = False,
        alias: str = None,
        attachments: Sequence[Mapping] = None,
        metadata: dict = None,
    ) -> InvitationRecord:
        """
        Generate new connection invitation.

        This interaction represents an out-of-band communication channel. In the future
        and in practice, these sort of invitations will be received over any number of
        channels such as SMS, Email, QR Code, NFC, etc.

        Args:
            my_label: label for this connection
            my_endpoint: endpoint where other party can reach me
            auto_accept: auto-accept a corresponding connection request
                (None to use config)
            public: set to create an invitation from the public DID
            use_connections: use (old) RFC 160 connections protocol, not RFC 23
            multi_use: set to True to create an invitation for multiple-use connection
            alias: optional alias to apply to connection for later use
            include_handshake: whether to include handshake protocols
            attachments: list of dicts in form of {"id": ..., "type": ...}

        Returns:
            Invitation record

        """
        if not (include_handshake or attachments):
            raise OutOfBandManagerError(
                "Invitation must include handshake protocols, "
                "request attachments, or both"
            )

        wallet = self._session.inject(BaseWallet)

        # Multitenancy setup
        multitenant_mgr = self._session.inject(MultitenantManager, required=False)
        wallet_id = self._session.settings.get("wallet.id")
        public_did = None

        accept = bool(
            auto_accept
            or (
                auto_accept is None
                and self._session.settings.get(
                    "debug.auto_accept_requests_public"
                    if public
                    else "debug.auto_accept_requests_peer"
                )
            )
        )
        if public and multi_use:
            raise OutOfBandManagerError(
                "Cannot create public invitation with multi_use"
            )
        if public and accept != self._session.settings.get(
            "debug.auto_accept_requests_public",
            False,
        ):
            raise OutOfBandManagerError(
                "Cannot override auto-acceptance configuration for "
                "requests to invitations on public DIDs"
            )

        message_attachments = []
        for atch in attachments or []:
            a_type = atch.get("type")
            a_id = atch.get("id")

            if a_type == "credential-offer":
                try:
                    cred_ex_rec = await V10CredentialExchange.retrieve_by_id(
                        self._session,
                        a_id,
                    )
                    message_attachments.append(
                        InvitationMessage.wrap_message(
                            cred_ex_rec.credential_offer_dict
                        )
                    )
                except StorageNotFoundError:
                    cred_ex_rec = await V20CredExRecord.retrieve_by_id(
                        self._session,
                        a_id,
                    )
                    message_attachments.append(
                        InvitationMessage.wrap_message(
                            V20CredOffer.deserialize(
                                cred_ex_rec.cred_offer
                            ).offer()  # default to indy format: will change for DIF
                        )
                    )
            elif a_type == "present-proof":
                pres_ex_rec = await V10PresentationExchange.retrieve_by_id(
                    self._session,
                    a_id,
                )
                message_attachments.append(
                    InvitationMessage.wrap_message(
                        pres_ex_rec.presentation_request_dict
                    )
                )
            else:
                raise OutOfBandManagerError(f"Unknown attachment type: {a_type}")
        if include_handshake and not use_connections:
            handshake_protocol = [DIDCommPrefix.qualify_current(DIDX_PROTO)]
        elif include_handshake and use_connections:
            handshake_protocol = [DIDCommPrefix.qualify_current(CONN_PROTO)]
        else:
            handshake_protocol = None
        if public:
            if not self._session.settings.get("public_invites"):
                raise OutOfBandManagerError("Public invitations are not enabled")

            public_did = await wallet.get_public_did()
            if not public_did:
                raise OutOfBandManagerError(
                    "Cannot create public invitation with no public DID"
                )

            if metadata:
                raise OutOfBandManagerError(
                    "Cannot store metadata on public invitations"
                )
            invi_msg = InvitationMessage(
                label=my_label or self._session.settings.get("default_label"),
                handshake_protocols=handshake_protocol,
                request_attach=message_attachments,
                service=[f"did:sov:{public_did.did}"],
            )
            # Add mapping for multitenant relay.
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(
                    wallet_id, public_did.verkey, skip_if_exists=True
                )

        else:
            invitation_mode = (
                ConnRecord.INVITATION_MODE_MULTI
                if multi_use
                else ConnRecord.INVITATION_MODE_ONCE
            )

            if not my_endpoint:
                my_endpoint = self._session.settings.get("default_endpoint")

            # Create and store new invitation key
            connection_key = await wallet.create_signing_key()

            # Add mapping for multitenant relay
            if multitenant_mgr and wallet_id:
                await multitenant_mgr.add_key(wallet_id, connection_key.verkey)

            # Create connection invitation message
            # Note: Need to split this into two stages to support inbound routing
            # of invitations
            # Would want to reuse create_did_document and convert the result
            invi_msg = InvitationMessage(
                label=my_label or self._session.settings.get("default_label"),
                handshake_protocols=handshake_protocol,
                request_attach=message_attachments,
                service=[
                    ServiceMessage(
                        _id="#inline",
                        _type="did-communication",
                        recipient_keys=[naked_to_did_key(connection_key.verkey)],
                        service_endpoint=my_endpoint,
                    )
                ],
            )

            # Create connection record
            conn_rec = ConnRecord(
                invitation_key=connection_key.verkey,
                invitation_msg_id=invi_msg._id,
                their_role=ConnRecord.Role.REQUESTER.rfc23,
                state=ConnRecord.State.INVITATION.rfc23,
                accept=ConnRecord.ACCEPT_AUTO if accept else ConnRecord.ACCEPT_MANUAL,
                invitation_mode=invitation_mode,
                alias=alias,
            )

            await conn_rec.save(self._session, reason="Created new invitation")
            await conn_rec.attach_invitation(self._session, invi_msg)

            if metadata:
                for key, value in metadata.items():
                    await conn_rec.metadata_set(self._session, key, value)

        # Create invitation record
        invi_rec = InvitationRecord(
            state=InvitationRecord.STATE_INITIAL,
            invi_msg_id=invi_msg._id,
            invitation=invi_msg.serialize(),
        )
        return invi_rec

    async def receive_invitation(
        self,
        invi_msg: InvitationMessage,
        use_existing_connection: bool = True,
        auto_accept: bool = None,
        alias: str = None,
    ) -> dict:
        """Receive an out of band invitation message."""

        print(f'>> >> OOBManager receive-invitation {auto_accept}')
        ledger: BaseLedger = self._session.inject(BaseLedger)

        # There must be exactly 1 service entry
        if len(invi_msg.service_blocks) + len(invi_msg.service_dids) != 1:
            raise OutOfBandManagerError("service array must have exactly one element")

        if len(invi_msg.request_attach) < 1 and len(invi_msg.handshake_protocols) < 1:
            raise OutOfBandManagerError(
                "Invitation must specify handshake_protocols, request_attach, or both"
            )
        # Get the single service item
        if len(invi_msg.service_blocks) >= 1:
            service = invi_msg.service_blocks[0]
            public_did = None
        else:
            # If it's in the did format, we need to convert to a full service block
            # An existing connection can only be reused based on a public DID
            # in an out-of-band message.
            # https://github.com/hyperledger/aries-rfcs/tree/master/features/0434-outofband
            service_did = invi_msg.service_dids[0]
            async with ledger:
                verkey = await ledger.get_key_for_did(service_did)
                did_key = naked_to_did_key(verkey)
                endpoint = await ledger.get_endpoint_for_did(service_did)
            public_did = service_did.split(":")[-1]
            service = ServiceMessage.deserialize(
                {
                    "id": "#inline",
                    "type": "did-communication",
                    "recipientKeys": [did_key],
                    "routingKeys": [],
                    "serviceEndpoint": endpoint,
                }
            )

        unq_handshake_protos = list(
            dict.fromkeys(
                [
                    DIDCommPrefix.unqualify(proto)
                    for proto in invi_msg.handshake_protocols
                ]
            )
        )
        # Reuse Connection
        # Only if started by an invitee with Public DID
        conn_rec = None
        if public_did is not None:
            # Inviter has a public DID
            # Looking for an existing connection
            tag_filter = {}
            post_filter = {}
            # post_filter["state"] = ConnRecord.State.COMPLETED.rfc160
            post_filter["their_public_did"] = public_did
            conn_rec = await self.find_existing_connection(
                tag_filter=tag_filter, post_filter=post_filter
            )
        if conn_rec is not None:
            num_included_protocols = len(unq_handshake_protos)
            num_included_req_attachments = len(invi_msg.request_attach)
            # Handshake_Protocol included Request_Attachment
            # not included Use_Existing_Connection Yes
            if (
                num_included_protocols >= 1
                and num_included_req_attachments == 0
                and use_existing_connection
            ):
                await self.create_handshake_reuse_message(
                    invi_msg=invi_msg,
                    conn_record=conn_rec,
                )
                try:
                    await asyncio.wait_for(
                        self.check_reuse_msg_state(
                            conn_rec=conn_rec,
                        ),
                        15,
                    )
                    await conn_rec.metadata_delete(
                        session=self._session, key="reuse_msg_id"
                    )
                    if (
                        await conn_rec.metadata_get(self._session, "reuse_msg_state")
                        == "not_accepted"
                    ):
                        conn_rec = None
                    else:
                        await conn_rec.metadata_delete(
                            session=self._session, key="reuse_msg_state"
                        )
                except asyncio.TimeoutError:
                    # If no reuse_accepted or problem_report message was recieved within
                    # the 15s timeout then a new connection to be created
                    await conn_rec.metadata_delete(
                        session=self._session, key="reuse_msg_id"
                    )
                    await conn_rec.metadata_delete(
                        session=self._session, key="reuse_msg_state"
                    )
                    conn_rec.state = ConnRecord.State.ABANDONED.rfc160
                    await conn_rec.save(self._session, reason="Sent connection request")
                    conn_rec = None
            # Inverse of the following cases
            # Handshake_Protocol not included
            # Request_Attachment included
            # Use_Existing_Connection Yes
            # Handshake_Protocol included
            # Request_Attachment included
            # Use_Existing_Connection Yes
            elif not (
                (
                    num_included_protocols == 0
                    and num_included_req_attachments >= 1
                    and use_existing_connection
                )
                or (
                    num_included_protocols >= 1
                    and num_included_req_attachments >= 1
                    and use_existing_connection
                )
            ):
                conn_rec = None
        if conn_rec is None:
            if len(unq_handshake_protos) == 0:
                raise OutOfBandManagerError(
                    "No existing connection exists and \
                        handshake_protocol is missing"
                )
            # Create a new connection
            for proto in unq_handshake_protos:
                if proto == DIDX_PROTO:
                    didx_mgr = DIDXManager(self._session)
                    print(f'  .. OOB calling DIDXManager recv-invi(auto={auto_accept})')
                    conn_rec = await didx_mgr.receive_invitation(
                        invitation=invi_msg,
                        their_public_did=public_did,
                        auto_accept=auto_accept,
                    )
                elif proto == CONN_PROTO:
                    service.recipient_keys = [
                        did_key_to_naked(key) for key in service.recipient_keys or []
                    ]
                    service.routing_keys = [
                        did_key_to_naked(key) for key in service.routing_keys
                    ] or []
                    connection_invitation = ConnectionInvitation.deserialize(
                        {
                            "@id": invi_msg._id,
                            "@type": DIDCommPrefix.qualify_current(CONN_PROTO),
                            "label": invi_msg.label,
                            "recipientKeys": service.recipient_keys,
                            "serviceEndpoint": service.service_endpoint,
                            "routingKeys": service.routing_keys,
                        }
                    )
                    conn_mgr = ConnectionManager(self._session)
                    print(f'  .. OOB calling ConnManager recv-invi(auto={auto_accept})')
                    conn_rec = await conn_mgr.receive_invitation(
                        invitation=connection_invitation,
                        their_public_did=public_did,
                        auto_accept=auto_accept,
                    )
                if conn_rec is not None:
                    break

        # Request Attach
        if len(invi_msg.request_attach) >= 1 and conn_rec is not None:
            req_attach = invi_msg.request_attach[0]
            if isinstance(req_attach, AttachDecorator):
                if req_attach.data is not None:
                    req_attach_type = req_attach.data.json["@type"]
                    if DIDCommPrefix.unqualify(req_attach_type) == PRESENTATION_REQUEST:
                        proof_present_mgr = PresentationManager(self._session)
                        indy_proof_request = json.loads(
                            b64_to_bytes(
                                req_attach.data.json["request_presentations~attach"][0][
                                    "data"
                                ]["base64"]
                            )
                        )
                        present_request_msg = req_attach.data.json
                        service_deco = {}
                        oob_invi_service = service.serialize()
                        service_deco["recipientKeys"] = oob_invi_service.get(
                            "recipientKeys"
                        )
                        service_deco["routingKeys"] = oob_invi_service.get(
                            "routingKeys"
                        )
                        service_deco["serviceEndpoint"] = oob_invi_service.get(
                            "serviceEndpoint"
                        )
                        present_request_msg["~service"] = service_deco
                        presentation_ex_record = V10PresentationExchange(
                            connection_id=conn_rec.connection_id,
                            thread_id=present_request_msg["@id"],
                            initiator=V10PresentationExchange.INITIATOR_EXTERNAL,
                            role=V10PresentationExchange.ROLE_PROVER,
                            presentation_request=indy_proof_request,
                            presentation_request_dict=present_request_msg,
                            auto_present=self._session.context.settings.get(
                                "debug.auto_respond_presentation_request"
                            ),
                            trace=(invi_msg._trace is not None),
                        )

                        presentation_ex_record.presentation_request = indy_proof_request
                        presentation_ex_record = (
                            await proof_present_mgr.receive_request(
                                presentation_ex_record
                            )
                        )

                        if presentation_ex_record.auto_present:
                            presentation_preview = None
                            if presentation_ex_record.presentation_proposal_dict:
                                exchange_pres_proposal = PresentationProposal.deserialize(
                                    presentation_ex_record.presentation_proposal_dict
                                )
                                presentation_preview = (
                                    exchange_pres_proposal.presentation_proposal
                                )

                            try:
                                req_creds = (
                                    await indy_proof_req_preview2indy_requested_creds(
                                        indy_proof_request,
                                        presentation_preview,
                                        holder=self._session.inject(IndyHolder),
                                    )
                                )
                            except ValueError as err:
                                self._logger.warning(f"{err}")
                                return

                            (
                                presentation_ex_record,
                                presentation_message,
                            ) = await proof_present_mgr.create_presentation(
                                presentation_exchange_record=presentation_ex_record,
                                requested_credentials=req_creds,
                                comment=(
                                    "auto-presented for proof request nonce={}".format(
                                        indy_proof_request["nonce"]
                                    )
                                ),
                            )
                        responder = self._session.inject(BaseResponder, required=False)
                        connection_targets = await self.fetch_connection_targets(
                            connection=conn_rec
                        )
                        if responder:
                            await responder.send(
                                message=presentation_message,
                                target_list=connection_targets,
                            )
                        if presentation_message is None:
                            raise OutOfBandManagerError(
                                "No presentation for proof request nonce={}".format(
                                    indy_proof_request["nonce"]
                                )
                            )
                        else:
                            return presentation_message.serialize()
                    else:
                        raise OutOfBandManagerError(
                            "Unsupported request~attach type, \
                                only request-presentation is supported"
                        )
            else:
                raise OutOfBandManagerError("request~attach is not properly formatted")
        else:
            return conn_rec.serialize()

    async def find_existing_connection(
        self,
        tag_filter: dict,
        post_filter: dict,
    ) -> Optional[ConnRecord]:
        """
        Find existing ConnRecord.

        Args:
            tag_filter: The filter dictionary to apply
            post_filter: Additional value filters to apply matching positively,
                with sequence values specifying alternatives to match (hit any)

        Returns:
            ConnRecord or None

        """
        conn_records = await ConnRecord.query(
            self._session,
            tag_filter=tag_filter,
            post_filter_positive=post_filter,
            alt=True,
        )
        if not conn_records:
            return None
        else:
            for conn_rec in conn_records:
                if conn_rec.state == "active":
                    return conn_rec
            return None

    async def check_reuse_msg_state(
        self,
        conn_rec: ConnRecord,
    ):
        """
        Check reuse message state from the ConnRecord Metadata.

        Args:
            conn_rec: The required ConnRecord with updated metadata

        Returns:

        """
        recieved = False
        while not recieved:
            if (
                not await conn_rec.metadata_get(self._session, "reuse_msg_state")
                == "initial"
            ):
                recieved = True
        return

    async def create_handshake_reuse_message(
        self,
        invi_msg: InvitationMessage,
        conn_record: ConnRecord,
    ) -> None:
        """
        Create and Send a Handshake Reuse message under RFC 0434.

        Args:
            invi_msg: OOB Invitation Message
            service: Service block extracted from the OOB invitation

        Returns:

        Raises:
            OutOfBandManagerError: If there is an issue creating or
            sending the OOB invitation

        """
        try:
            # ID of Out-of-Band invitation to use as a pthid
            pthid = invi_msg._id
            reuse_msg = HandshakeReuse()
            thid = reuse_msg._id
            reuse_msg.assign_thread_id(thid=thid, pthid=pthid)
            connection_targets = await self.fetch_connection_targets(
                connection=conn_record
            )
            responder = self._session.inject(BaseResponder, required=False)
            if responder:
                await responder.send(
                    message=reuse_msg,
                    target_list=connection_targets,
                )
                await conn_record.metadata_set(
                    session=self._session, key="reuse_msg_id", value=reuse_msg._id
                )
                await conn_record.metadata_set(
                    session=self._session, key="reuse_msg_state", value="initial"
                )
        except Exception as err:
            raise OutOfBandManagerError(
                f"Error on creating and sending a handshake reuse message: {err}"
            )

    async def receive_reuse_message(
        self,
        reuse_msg: HandshakeReuse,
        receipt: MessageReceipt,
    ):
        """
        Recieve and process a HandshakeReuse message under RFC 0434.

        Process a `HandshakeReuse` message by looking up
        the connection records using the MessageReceipt sender DID.

        Args:
            reuse_msg: The `HandshakeReuse` to process
            receipt: The message receipt

        Returns:

        Raises:
            OutOfBandManagerError: If the existing connection is not active
            or the connection does not exists

        """
        try:
            invi_msg_id = reuse_msg._thread.pthid
            reuse_msg_id = reuse_msg._thread.thid
            tag_filter = {}
            post_filter = {}
            # post_filter["state"] = "active"
            tag_filter["their_did"] = receipt.sender_did
            conn_record = await self.find_existing_connection(
                tag_filter=tag_filter, post_filter=post_filter
            )
            responder = self._session.inject(BaseResponder, required=False)
            if conn_record is not None:
                reuse_accept_msg = HandshakeReuseAccept()
                reuse_accept_msg.assign_thread_id(thid=reuse_msg_id, pthid=invi_msg_id)
                connection_targets = await self.fetch_connection_targets(
                    connection=conn_record
                )
                if responder:
                    await responder.send(
                        message=reuse_accept_msg,
                        target_list=connection_targets,
                    )
                # Delete the ConnRecord created; re-use existing connection
                invi_id_post_filter = {}
                invi_id_post_filter["invitation_msg_id"] = invi_msg_id
                conn_rec_to_delete = await self.find_existing_connection(
                    tag_filter={},
                    post_filter=invi_id_post_filter,
                )
                if conn_rec_to_delete is not None:
                    if conn_record.connection_id != conn_rec_to_delete.connection_id:
                        await conn_rec_to_delete.delete_record(session=self._session)
            else:
                try:
                    conn_records = await ConnRecord.query(
                        self._session,
                        tag_filter={"their_did": receipt.sender_did},
                        post_filter_positive={},
                    )
                    if len(conn_records) >= 1:
                        all_conn_rec_by_sender = conn_records[0]
                    else:
                        all_conn_rec_by_sender = None
                except StorageNotFoundError:
                    all_conn_rec_by_sender = None
                targets = None
                if all_conn_rec_by_sender is not None:
                    targets = await self.fetch_connection_targets(
                        connection=conn_record
                    )
                    problem_report = ProblemReport(
                        problem_code=(
                            ProblemReportReason.EXISTING_CONNECTION_NOT_ACTIVE.value
                        ),
                        explain=(
                            "No active connection found "
                            f"for invitee {receipt.sender_did}"
                        ),
                    )
                    problem_report.assign_thread_id(
                        thid=reuse_msg_id, pthid=invi_msg_id
                    )
                    await responder.send_reply(
                        problem_report,
                        target_list=targets,
                    )
                else:
                    raise OutOfBandManagerError(
                        (f"No existing ConnRecord found, {receipt.sender_did}"),
                    )
        except StorageNotFoundError:
            raise OutOfBandManagerError(
                (f"No existing ConnRecord found for OOB Invitee, {receipt.sender_did}"),
            )

    async def receive_reuse_accepted_message(
        self,
        reuse_accepted_msg: HandshakeReuseAccept,
        receipt: MessageReceipt,
        conn_record: ConnRecord,
    ):
        """
        Recieve and process a HandshakeReuseAccept message under RFC 0434.

        Process a `HandshakeReuseAccept` message by updating the ConnRecord metadata
        state to `accepted`.

        Args:
            reuse_accepted_msg: The `HandshakeReuseAccept` to process
            receipt: The message receipt

        Returns:

        Raises:
            OutOfBandManagerError: if there is an error in processing the
            HandshakeReuseAccept message

        """
        try:
            invi_msg_id = reuse_accepted_msg._thread.pthid
            thread_reuse_msg_id = reuse_accepted_msg._thread.thid
            conn_reuse_msg_id = await conn_record.metadata_get(
                session=self._session, key="reuse_msg_id"
            )
            assert thread_reuse_msg_id == conn_reuse_msg_id
            await conn_record.metadata_set(
                session=self._session, key="reuse_msg_state", value="accepted"
            )
        except StorageNotFoundError as e:
            raise OutOfBandManagerError(
                (
                    f"Error processing reuse accepted message \
                        for OOB invitation {invi_msg_id}, {e}"
                )
            )

    async def receive_problem_report(
        self,
        problem_report: ProblemReport,
        receipt: MessageReceipt,
        conn_record: ConnRecord,
    ):
        """
        Recieve and process a ProblemReport message from the inviter to invitee.

        Process a `ProblemReport` message by updating  the ConnRecord metadata
        state to `not_accepted`.

        Args:
            problem_report: The `ProblemReport` to process
            receipt: The message receipt

        Returns:

        Raises:
            OutOfBandManagerError: if there is an error in processing the
            HandshakeReuseAccept message

        """
        try:
            invi_msg_id = problem_report._thread.pthid
            thread_reuse_msg_id = problem_report._thread.thid
            conn_reuse_msg_id = await conn_record.metadata_get(
                session=self._session, key="reuse_msg_id"
            )
            assert thread_reuse_msg_id == conn_reuse_msg_id
            await conn_record.metadata_set(
                session=self._session, key="reuse_msg_state", value="not_accepted"
            )
        except StorageNotFoundError:
            raise OutOfBandManagerError(
                (
                    f"Error processing problem report message \
                        for OOB invitation {invi_msg_id}"
                )
            )
