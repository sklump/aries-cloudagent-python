import json

from asynctest import TestCase as AsyncTestCase, mock as async_mock

from ....config.injection_context import InjectionContext
from ....storage.base import BaseStorage, StorageNotFoundError
from ....storage.basic import BasicStorage
from ....wallet.base import BaseWallet, DIDInfo

from .. import did_verkey_record as test_module
from ..did_verkey_record import DidVerkeyRecord

TEST_DID = [
    "55GkHamhTU1ZbTbV2ab9DE",
    "FFFFFFFFFFFFFFFFFFFFFF",
]
TEST_VERKEY = [
    "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx",
    "00000000000000000000000000000000000000000000",
]


class TestRecord(AsyncTestCase):
    def setUp(self):
        self.context = InjectionContext(enforce_typing=False)

        self.wallet = async_mock.MagicMock()
        self.wallet.type = "indy"
        self.context.injector.bind_instance(BaseWallet, self.wallet)

        self.storage = BasicStorage()
        self.context.injector.bind_instance(BaseStorage, self.storage)

    async def test_serde(self):
        rec = DidVerkeyRecord(
            record_id=test_module.UUIDFour.EXAMPLE,
            did=TEST_DID[0],
            verkey=TEST_VERKEY[0],
        )
        ser = rec.serialize()
        assert ser["record_id"] == rec.record_id
        assert ser["did"] == TEST_DID[0]
        assert ser["verkey"] == TEST_VERKEY[0]
        assert rec.did == TEST_DID[0]
        assert rec.verkey == TEST_VERKEY[0]

        assert rec == DidVerkeyRecord.deserialize(ser)

    async def test_rec_ops(self):
        recs = [
            DidVerkeyRecord(
                did=TEST_DID[i],
                verkey=TEST_VERKEY[i],
            )
            for i in range(len(TEST_DID))
        ]
        assert recs[0] != recs[1]

        for rec in recs:
            await rec.save(self.context)

        assert (
            await DidVerkeyRecord.retrieve_by_did_verkey(
                self.context,
                did=TEST_DID[0],
            )
        ) == recs[0]
        assert (
            await DidVerkeyRecord.retrieve_by_did_verkey(
                self.context,
                verkey=TEST_VERKEY[0],
            )
        ) == recs[0]
        with self.assertRaises(StorageNotFoundError):
            await DidVerkeyRecord.retrieve_by_did_verkey(
                self.context,
                did="no-such-did"
            )
        assert len(await DidVerkeyRecord.query(self.context)) == len(TEST_DID)
