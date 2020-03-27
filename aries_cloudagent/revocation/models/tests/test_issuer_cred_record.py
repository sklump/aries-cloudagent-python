import json

import pytest

from asynctest import TestCase as AsyncTestCase, mock as async_mock
from asyncio import sleep

from ....config.injection_context import InjectionContext
from ....issuer.base import BaseIssuer, IssuerError
from ....issuer.indy import IndyIssuer
from ....ledger.base import BaseLedger
from ....storage.base import BaseStorage
from ....storage.basic import BasicStorage
from ....wallet.base import BaseWallet, DIDInfo

from ...error import RevocationError

from ..issuer_cred_record import IssuerCredentialRecord


class TestRecord(AsyncTestCase):
    test_did = "55GkHamhTU1ZbTbV2ab9DE"

    def setUp(self):
        self.context = InjectionContext(enforce_typing=False)

        self.wallet = async_mock.MagicMock()
        self.wallet.WALLET_TYPE = "indy"
        self.context.injector.bind_instance(BaseWallet, self.wallet)

        self.storage = BasicStorage()
        self.context.injector.bind_instance(BaseStorage, self.storage)

    async def test_init(self):
        CRED_DEF_ID = f"{TestRecord.test_did}:3:CL:1234:default"
        REV_REG_ID = f"{TestRecord.test_did}:4:{CRED_DEF_ID}:CL_ACCUM:0"
        CRED_VALUES = {
            "name": "Hubert Kowalczyk",
            "moniker": "DRAM",
            "genre": "techno",
            "since": "1994"
        }

        rec = IssuerCredentialRecord(
            cred_def_id=CRED_DEF_ID,
            rev_reg_id=REV_REG_ID,
            cred_values=CRED_VALUES
        )
        assert rec.cred_def_id == CRED_DEF_ID
        assert rec.record_id == rec._id
        assert {"cred_values": CRED_VALUES}.items() <= rec.value.items()

        rec = IssuerCredentialRecord()
        assert rec.cred_def_id is None
        assert {"cred_values": None}.items() <= rec.value.items()

        old_rec = IssuerCredentialRecord(
            cred_def_id=CRED_DEF_ID,
            rev_reg_id=REV_REG_ID,
            cred_values=CRED_VALUES,
            created_at="1234567890"
        )
        assert rec != old_rec

    async def test_query_revocable(self):
        CRED_DEF_ID = f"{TestRecord.test_did}:3:CL:1234:default"
        REV_REG_ID = f"{TestRecord.test_did}:4:{CRED_DEF_ID}:CL_ACCUM:0"
        CRED_VALUES = [
            {
                "name": "Hubert Kowalczyk",
                "moniker": "DRAM",
                "genre": "techno",
                "since": "1994"
            },
            {
                "name": "Stephen Klump",
                "moniker": "Supersonic",
                "genre": "electro",
                "since": "1999"
            },
            {
                "name": "Peter Stromer",
                "moniker": "Spaceship Manager",
                "genre": "psy-trance",
                "since": "1997"
            },
            {
                "name": "Luke Ballon",
                "moniker": "Ted Dancin'",
                "genre": "house",
                "since": "1994"
            }
        ]

        recs = [
            IssuerCredentialRecord(
                cred_def_id=CRED_DEF_ID,
                rev_reg_id=REV_REG_ID,
                cred_values=cv,
                cred_rev_id=str(CRED_VALUES.index(cv) + 1)
            ) for cv in CRED_VALUES
        ]
        recs.append(
            IssuerCredentialRecord(
                state=IssuerCredentialRecord.STATE_REVOKED,
                cred_def_id=CRED_DEF_ID,
                rev_reg_id=REV_REG_ID,
                cred_values={
                    "name": "Mike Fowldes",
                    "moniker": "Mr. Gone",
                    "genre": "tech-house",
                    "since": "1994"
                },
                cred_rev_id=str(23),
            )
        )
        for rec in recs:
            await rec.save(self.context)

        hits = await IssuerCredentialRecord.query_revocable(  # covers de/serialize
            self.context,
            cred_def_id=CRED_DEF_ID,
            cred_values={"moniker": "No such DJ"},
        )
        assert not hits

        hits = await IssuerCredentialRecord.query_revocable(
            self.context,
            cred_def_id=CRED_DEF_ID,
            cred_values={"moniker": "DRAM"},
        )
        assert len(hits) == 1 and hits[0].value["cred_rev_id"] == "1"

        hits = await IssuerCredentialRecord.query_revocable(
            self.context,
            cred_def_id=CRED_DEF_ID,
            cred_values={"since": 1994},  # cover stringification to raw value
        )
        assert len(hits) == 2 and {"1", "4"} == {h.value["cred_rev_id"] for h in hits}

        hits = await IssuerCredentialRecord.query_revocable(
            self.context,
            cred_def_id=CRED_DEF_ID,
            cred_values={"genre": "tech-house"},
            state=IssuerCredentialRecord.STATE_REVOKED
        )
        assert len(hits) == 1 and hits[0].value["cred_rev_id"] == "23"
