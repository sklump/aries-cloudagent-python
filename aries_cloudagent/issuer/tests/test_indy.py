import json

import pytest

from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from indy.error import (
    AnoncredsRevocationRegistryFullError,
    ErrorCode,
    IndyError,
    WalletItemNotFound
)

from ...revocation.models.issuer_cred_record import IssuerCredentialRecord
from ...wallet.indy import IndyWallet

from ..base import IssuerRevocationRegistryFullError
from ..indy import IndyIssuer, IssuerError


TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"
SCHEMA_NAME = "resident"
SCHEMA_VERSION = "1.0"
SCHEMA_TXN=1234
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:{SCHEMA_VERSION}"
CRED_DEF_ID = f"{TEST_DID}:3:CL:{SCHEMA_TXN}:default"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:CL_ACCUM:0"
TEST_RR_DELTA = {
    "ver": "1.0",
    "value": {
        "prevAccum": "1 ...",
        "accum": "21 ...",
        "issued": [1, 2, 12, 42]
    }
}


@pytest.mark.indy
class TestIndyIssuer(AsyncTestCase):
    async def setUp(self):
        self.wallet = IndyWallet(
            {
                "auto_create": True,
                "auto_remove": True,
                "key": await IndyWallet.generate_wallet_key(),
                "key_derivation_method": "RAW",
                "name": "test",
            }
        )
        self.issuer = IndyIssuer(self.wallet)
        assert self.issuer.wallet is self.wallet
        await self.wallet.open()

    async def tearDown(self):
        await self.wallet.close()

    async def test_repf(self):
        assert "IndyIssuer" in str(self.issuer)  # cover __repr__

    @async_mock.patch("indy.anoncreds.issuer_create_and_store_credential_def")
    async def test_schema_cred_def(self, mock_indy_cred_def):
        assert self.issuer.make_schema_id(
            TEST_DID,
            SCHEMA_NAME,
            SCHEMA_VERSION
        ) == SCHEMA_ID

        (s_id, schema_json) = await self.issuer.create_schema(
            TEST_DID,
            SCHEMA_NAME,
            SCHEMA_VERSION,
            ["name", "moniker", "genre", "effective"]
        )
        assert s_id == SCHEMA_ID
        schema = json.loads(schema_json)
        schema['seqNo'] = SCHEMA_TXN

        assert self.issuer.make_credential_definition_id(
            TEST_DID,
            schema,
            tag='default'
        ) == CRED_DEF_ID

        (s_id, _) = await self.issuer.create_schema(
            TEST_DID,
            SCHEMA_NAME,
            SCHEMA_VERSION,
            ["name", "moniker", "genre", "effective"]
        )
        assert s_id == SCHEMA_ID

        mock_indy_cred_def.return_value = (
            CRED_DEF_ID,
            json.dumps({"dummy": "cred-def"})
        )
        assert (CRED_DEF_ID, json.dumps({"dummy": "cred-def"})) == (
            await self.issuer.create_and_store_credential_definition(
                TEST_DID,
                schema,
                support_revocation=True
            )
        )
        
    @async_mock.patch("indy.anoncreds.issuer_create_credential_offer")
    async def test_credential_definition_in_wallet(self, mock_indy_create_offer):
        mock_indy_create_offer.return_value = {
            "sample": "offer"
        }
        assert await self.issuer.credential_definition_in_wallet(CRED_DEF_ID)

    @async_mock.patch("indy.anoncreds.issuer_create_credential_offer")
    async def test_credential_definition_in_wallet_no(self, mock_indy_create_offer):
        mock_indy_create_offer.side_effect = WalletItemNotFound(
            error_code=ErrorCode.WalletItemNotFound
        )
        assert not await self.issuer.credential_definition_in_wallet(CRED_DEF_ID)

    @async_mock.patch("indy.anoncreds.issuer_create_credential_offer")
    async def test_credential_definition_in_wallet_x(self, mock_indy_create_offer):
        mock_indy_create_offer.side_effect = IndyError(
            error_code=ErrorCode.WalletInvalidHandle
        )
        with self.assertRaises(IssuerError):
            await self.issuer.credential_definition_in_wallet(CRED_DEF_ID)

    @async_mock.patch("indy.anoncreds.issuer_create_credential_offer")
    async def test_create_credential_offer(self, mock_indy_create_offer):
        test_offer = {"test": "offer"}
        test_cred_def_id = "test-cred-def-id"
        mock_indy_create_offer.return_value = json.dumps(test_offer)
        offer_json = await self.issuer.create_credential_offer(test_cred_def_id)
        assert json.loads(offer_json) == test_offer
        mock_indy_create_offer.assert_awaited_once_with(
            self.wallet.handle,
            test_cred_def_id
        )

    @async_mock.patch("indy.anoncreds.issuer_create_credential")
    @async_mock.patch("aries_cloudagent.issuer.indy.create_tails_reader")
    @async_mock.patch("indy.anoncreds.issuer_revoke_credential")
    async def test_create_revoke_credential(
        self,
        mock_indy_revoke_credential,
        mock_tails_reader,
        mock_indy_create_credential
    ):
        test_schema = {"attrNames": ["attr1"]}
        test_offer = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "key_correctness_proof": {
                "c": "...",
                "xz_cap": "...",
                "xr_cap": ["..."],
            },
            "nonce": "..."
        }
        test_request = {"test": "request"}
        test_values = {"attr1": "value1"}
        test_cred = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "rev_reg_id": REV_REG_ID,
            "values": {
                "attr1": {
                    "raw": "value1",
                    "encoded": "123456123899216581404"
                }
            },
            "signature": {
                "...": "..."
            },
            "signature_correctness_proof": {
                "...": "..."
            },
            "rev_reg": {
                "accum": "21 12E8..."
            },
            "witness": {
                "omega": "21 1369..."
            }
        }
        test_cred_rev_id = "42"
        test_rr_delta = TEST_RR_DELTA
        mock_indy_create_credential.return_value = (
            json.dumps(test_cred),
            test_cred_rev_id,
            test_rr_delta,
        )

        with self.assertRaises(IssuerError):  # missing attribute
            cred_json, revoc_id = await self.issuer.create_credential(
                test_schema, test_offer, test_request, {}
            )

        cred_json, cred_rev_id = await self.issuer.create_credential(  # main line
            test_schema,
            test_offer,
            test_request,
            test_values,
            REV_REG_ID,
            "/tmp/tails/path/dummy"
        )
        mock_indy_create_credential.assert_awaited_once()
        (
            call_wallet,
            call_offer,
            call_request,
            call_values,
            call_etc1,
            call_etc2,
        ) = mock_indy_create_credential.call_args[0]
        assert call_wallet is self.wallet.handle
        assert json.loads(call_offer) == test_offer
        assert json.loads(call_request) == test_request
        values = json.loads(call_values)
        assert "attr1" in values

        revocable = await self.issuer.query_revocable(
            cred_def_id=CRED_DEF_ID,
            cred_values={"attr1": "value1"},
        )
        assert len(revocable) == 1

        revo = revocable[0]
        mock_indy_revoke_credential.return_value = json.dumps(TEST_RR_DELTA)
        result = await self.issuer.revoke_credential(
            revo.rev_reg_id,
            tails_file_path="dummy",
            cred_revoc_id=revo.cred_rev_id
        )
        assert json.loads(result) == TEST_RR_DELTA

        revocable = await self.issuer.query_revocable(
            cred_def_id=CRED_DEF_ID,
            cred_values={"attr1": "value1"},
        )
        assert not revocable

    @async_mock.patch("indy.anoncreds.issuer_create_credential")
    @async_mock.patch("aries_cloudagent.issuer.indy.create_tails_reader")
    async def test_create_credential_rr_full(
        self,
        mock_tails_reader,
        mock_indy_create_credential
    ):
        test_schema = {"attrNames": ["attr1"]}
        test_offer = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "key_correctness_proof": {
                "c": "...",
                "xz_cap": "...",
                "xr_cap": ["..."],
            },
            "nonce": "..."
        }
        test_request = {"test": "request"}
        test_values = {"attr1": "value1"}
        test_credential = {"test": "credential"}
        test_cred_rev_id = "42"
        test_rr_delta = TEST_RR_DELTA
        mock_indy_create_credential.side_effect = AnoncredsRevocationRegistryFullError(
            error_code=ErrorCode.AnoncredsRevocationRegistryFullError
        )
        with self.assertRaises(IssuerRevocationRegistryFullError):
            await self.issuer.create_credential(
                test_schema,
                test_offer,
                test_request,
                test_values
            )

    @async_mock.patch("indy.anoncreds.issuer_create_credential")
    @async_mock.patch("aries_cloudagent.issuer.indy.create_tails_reader")
    async def test_create_credential_x_indy(
        self,
        mock_tails_reader,
        mock_indy_create_credential
    ):
        test_schema = {"attrNames": ["attr1"]}
        test_offer = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "key_correctness_proof": {
                "c": "...",
                "xz_cap": "...",
                "xr_cap": ["..."],
            },
            "nonce": "..."
        }
        test_request = {"test": "request"}
        test_values = {"attr1": "value1"}
        test_credential = {"test": "credential"}
        test_cred_rev_id = "42"
        test_rr_delta = TEST_RR_DELTA

        mock_indy_create_credential.side_effect = IndyError(
            error_code=ErrorCode.WalletInvalidHandle
        )
        with self.assertRaises(IssuerError):
            await self.issuer.create_credential(
                test_schema,
                test_offer,
                test_request,
                test_values
            )

    @async_mock.patch("indy.anoncreds.issuer_create_and_store_revoc_reg")
    @async_mock.patch("aries_cloudagent.issuer.indy.create_tails_writer")
    async def test_create_and_store_revocation_registry(
        self,
        mock_indy_tails_writer,
        mock_indy_rr
    ):
        mock_indy_rr.return_value = ("a", "b", "c")
        (rr_id, rrdef_json, rre_json) = (
            await self.issuer.create_and_store_revocation_registry(
                TEST_DID,
                CRED_DEF_ID,
                "CL_ACCUM",
                "rr-tag",
                100,
                "/tmp/tails/path",
            )   
        )
        assert (rr_id, rrdef_json, rre_json) == ("a", "b", "c")

    @async_mock.patch("indy.anoncreds.issuer_merge_revocation_registry_deltas")
    async def test_merge_revocation_registry_deltas(self, mock_indy_merge):
        mock_indy_merge.return_value = json.dumps({"net": "delta"})
        assert {"net": "delta"} == await self.issuer.merge_revocation_registry_deltas(
            {"fro": "delta"},
            {"to": "delta"}
        )
