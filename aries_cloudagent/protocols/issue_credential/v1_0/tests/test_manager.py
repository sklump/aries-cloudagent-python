import asyncio
import json

from asynctest import mock as async_mock, TestCase as AsyncTestCase
from copy import deepcopy
from time import time

from .....core.in_memory import InMemoryProfile
from .....cache.base import BaseCache
from .....cache.in_memory import InMemoryCache
from .....indy.holder import IndyHolder
from .....indy.issuer import IndyIssuer
from .....indy.sdk.artifacts.cred import IndyCredential
from .....messaging.credential_definitions.util import CRED_DEF_SENT_RECORD_TYPE
from .....ledger.base import BaseLedger
from .....storage.base import StorageRecord
from .....storage.error import StorageNotFoundError

from ..manager import CredentialManager, CredentialManagerError
from ..messages.credential_ack import CredentialAck
from ..messages.credential_issue import CredentialIssue
from ..messages.credential_offer import CredentialOffer
from ..messages.credential_proposal import CredentialProposal
from ..messages.credential_request import CredentialRequest
from ..messages.inner.credential_preview import CredentialPreview, CredAttrSpec
from ..models.credential_exchange import V10CredentialExchange

from .. import manager as test_module


TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
SCHEMA_NAME = "bc-reg"
SCHEMA_TXN = 12
SCHEMA_ID = f"{TEST_DID}:2:{SCHEMA_NAME}:1.0"
SCHEMA = {
    "ver": "1.0",
    "id": SCHEMA_ID,
    "name": SCHEMA_NAME,
    "version": "1.0",
    "attrNames": ["legalName", "jurisdictionId", "incorporationDate"],
    "seqNo": SCHEMA_TXN,
}
CRED_DEF_ID = f"{TEST_DID}:3:CL:12:tag1"
CRED_DEF = {
    "ver": "1.0",
    "id": CRED_DEF_ID,
    "schemaId": SCHEMA_TXN,
    "type": "CL",
    "tag": "tag1",
    "value": {
        "primary": {
            "n": "...",
            "s": "...",
            "r": {
                "master_secret": "...",
                "legalName": "...",
                "jurisdictionId": "...",
                "incorporationDate": "...",
            },
            "rctxt": "...",
            "z": "...",
        },
        "revocation": {
            "g": "1 ...",
            "g_dash": "1 ...",
            "h": "1 ...",
            "h0": "1 ...",
            "h1": "1 ...",
            "h2": "1 ...",
            "htilde": "1 ...",
            "h_cap": "1 ...",
            "u": "1 ...",
            "pk": "1 ...",
            "y": "1 ...",
        },
    },
}
REV_REG_DEF_TYPE = "CL_ACCUM"
REV_REG_ID = f"{TEST_DID}:4:{CRED_DEF_ID}:{REV_REG_DEF_TYPE}:tag1"
TAILS_DIR = "/tmp/indy/revocation/tails_files"
TAILS_HASH = "8UW1Sz5cqoUnK9hqQk7nvtKK65t7Chu3ui866J23sFyJ"
TAILS_LOCAL = f"{TAILS_DIR}/{TAILS_HASH}"
REV_REG_DEF = {
    "ver": "1.0",
    "id": REV_REG_ID,
    "revocDefType": "CL_ACCUM",
    "tag": "tag1",
    "credDefId": CRED_DEF_ID,
    "value": {
        "issuanceType": "ISSUANCE_ON_DEMAND",
        "maxCredNum": 5,
        "publicKeys": {"accumKey": {"z": "1 ..."}},
        "tailsHash": TAILS_HASH,
        "tailsLocation": TAILS_LOCAL,
    },
}
INDY_OFFER = {
    "nonce": "614100168443907415054289",
    "schema_id": SCHEMA_ID,
    "cred_def_id": CRED_DEF_ID,
    "key_correctness_proof": {
        "c": "56585275561905717161839952743647026395542989876162452893531670700564212393854",
        "xz_cap": "287165348340975789727971384349378142287959058342225940074538845935436773874329328991029519089234724427434486533815831859470220965864684738156552672305499237703498538513271159520247291220966466227432832227063850459130839372368207180055849729905609985998538537568736869293407524473496064816314603497171002962615258076622463931743189286900496109205216280607630768503576692684508445827948798897460776289403908388023698817549732288585499518794247355928287227786391839285875542402023633857234040392852972008208415080178060364227401609053629562410235736217349229809414782038441992275607388974250885028366550369268002576993725278650846144639865881671599246472739142902676861561148712912969364530598265",
        "xr_cap": [
            [
                "member",
                "247173988424242283128308731284354519593625104582055668969315003963838548670841899501658349312938942946846730152870858369236571789232183841781453957957720697180067746500659257059976519795874971348181945469064991738990738845965440847535223580150468375375443512237424530837415294161162638683584221123453778375487245671372772618360172541002473454666729113558205280977594339672398197686260680189972481473789054636358472310216645491588945137379027958712059669609528877404178425925715596671339305959202588832885973524555444251963470084399490131160758976923444260763440975941005911948597957705824445435191054260665559130246488082450660079956928491647323363710347167509227696874201965902602039122291827",
            ],
            [
                "favourite",
                "1335045667644070498565118732156146549025899560440568943935771536511299164006020730238478605099548137764051990321413418863325926730012675851687537953795507658228985382833693223549386078823801188511091609027561372137859781602606173745112393410558404328055415428275164533367998547196095783458226529569321865083846885509205360165413682408429660871664533434140200342530874654054024409641491095797032894595844264175356021739370667850887453108137634226023771337973520900908849320630756049969052968900455735023806005098461831167599998292029791540116613937132049776519811961709679592741659868352478832873910002910063294074562896887581629929595271513565238416621119418443383796085468376565042025935483490",
            ],
            [
                "master_secret",
                "1033992860010367458372180504097559955661066772142722707045156268794833109485917658718054000138242001598760494274716663669095123169580783916372365989852993328621834238281615788751278692675115165487417933883883618299385468584923910731758768022514670608541825229491053331942365151645754250522222493603795702384546708563091580112967031435038732735155283423684631622768416201085577137158105343396606143962017453945220908112975903537378485103755718950361047334234687103399968712220979025991673471498636490232494897885460464490635716242509247751966176791851396526210422140145723375747195416033531994076204650208879292521201294795264925045126704368284107432921974127792914580116411247536542717749670349",
            ],
        ],
    },
}
INDY_CRED_REQ = {
    "nonce": "1017762706737386703693758",
    "prover_did": TEST_DID,
    "cred_def_id":  CRED_DEF_ID,
    "blinded_ms": {
        "u": "83907504917598709544715660183444547664806528194879236493704185267249518487609477830252206438464922282419526404954032744426656836343614241707982523911337758117991524606767981934822739259321023980818911648706424625657217291525111737996606024710795596961607334766957629765398381678917329471919374676824400143394472619220909211861028497009707890651887260349590274729523062264675018736459760546731362496666872299645586181905130659944070279943157241097916683504866583173110187429797028853314290183583689656212022982000994142291014801654456172923356395840313420880588404326139944888917762604275764474396403919497783080752861",
        "ur": "1 2422A7A25A9AB730F3399C77C28E1F6E02BB94A2C07D245B28DC4EE33E33DE49 1 1EF3FBD36FBA7510BDA79386508C0A84A33DF4171107C22895ACAE4FA4499F02 2 095E45DDF417D05FB10933FFC63D474548B7FFFF7888802F07FFFFFF7D07A8A8",
        "hidden_attributes": ["master_secret"],
        "committed_attributes": {},
    },
    "blinded_ms_correctness_proof": {
        "c": "77782990462020711078900471139684606615516190979556618670020830699801678914552",
        "v_dash_cap": "1966215015532422356590954855080129096516569112935438312989092847889400013191094311374123910677667707922694722167856889267996544544770134106600289624974901761453909338477897555013062690166110508298265469948048257876547569520215226798025984795668101468265482570744011744194025718081101032551943108999422057478928838218205736972438022128376728526831967897105301274481454020377656694232901381674223529320224276009919370080174601226836784570762698964476355045131401700464714725647784278935633253472872446202741297992383148244277451017022036452203286302631768247417186601621329239603862883753434562838622266122331169627284313213964584034951472090601638790603966977114416216909593408778336960753110805965734708636782885161632",
        "m_caps": {
            "master_secret": "1932933391026030434402535597188163725022560167138754201841873794167337347489231254032687761158191503499965986291267527620598858412377279828812688105949083285487853357240244045442"
        },
        "r_caps": {},
    },
}


class TestCredentialManager(AsyncTestCase):
    async def setUp(self):
        self.session = InMemoryProfile.test_session()
        self.profile = self.session.profile
        self.context = self.profile.context
        setattr(
            self.profile, "session", async_mock.MagicMock(return_value=self.session)
        )

        Ledger = async_mock.MagicMock()
        self.ledger = Ledger()
        self.ledger.get_schema = async_mock.CoroutineMock(return_value=SCHEMA)
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value=CRED_DEF
        )
        self.ledger.get_revoc_reg_def = async_mock.CoroutineMock(
            return_value=REV_REG_DEF
        )
        self.ledger.__aenter__ = async_mock.CoroutineMock(return_value=self.ledger)
        self.ledger.credential_definition_id2schema_id = async_mock.CoroutineMock(
            return_value=SCHEMA_ID
        )
        self.context.injector.bind_instance(BaseLedger, self.ledger)

        self.manager = CredentialManager(self.profile)
        assert self.manager.profile

    async def test_record_eq(self):
        same = [
            V10CredentialExchange(
                credential_exchange_id="dummy-0",
                thread_id="thread-0",
                credential_definition_id=CRED_DEF_ID,
                role=V10CredentialExchange.ROLE_ISSUER,
            )
        ] * 2
        diff = [
            V10CredentialExchange(
                credential_exchange_id="dummy-1",
                credential_definition_id=CRED_DEF_ID,
                role=V10CredentialExchange.ROLE_ISSUER,
            ),
            V10CredentialExchange(
                credential_exchange_id="dummy-0",
                thread_id="thread-1",
                credential_definition_id=CRED_DEF_ID,
                role=V10CredentialExchange.ROLE_ISSUER,
            ),
            V10CredentialExchange(
                credential_exchange_id="dummy-1",
                thread_id="thread-0",
                credential_definition_id=f"{CRED_DEF_ID}_distinct_tag",
                role=V10CredentialExchange.ROLE_ISSUER,
            ),
        ]

        for i in range(len(same) - 1):
            for j in range(i, len(same)):
                assert same[i] == same[j]

        for i in range(len(diff) - 1):
            for j in range(i, len(diff)):
                assert diff[i] == diff[j] if i == j else diff[i] != diff[j]

    async def test_prepare_send(self):
        connection_id = "test_conn_id"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=SCHEMA_ID
        )
        with async_mock.patch.object(
            self.manager, "create_offer", autospec=True
        ) as create_offer:
            create_offer.return_value = (async_mock.MagicMock(), async_mock.MagicMock())
            ret_exchange, ret_cred_offer = await self.manager.prepare_send(
                connection_id, proposal
            )
            create_offer.assert_called_once()
            assert ret_exchange is create_offer.return_value[0]
            arg_exchange = create_offer.call_args[1]["cred_ex_record"]
            assert arg_exchange.auto_issue
            assert arg_exchange.connection_id == connection_id
            assert arg_exchange.schema_id is None
            assert arg_exchange.credential_definition_id is None
            assert arg_exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert arg_exchange.credential_proposal_dict == proposal

    async def test_create_proposal(self):
        connection_id = "test_conn_id"
        comment = "comment"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )

        self.ledger.credential_definition_id2schema_id = async_mock.CoroutineMock(
            return_value=SCHEMA_ID
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            exchange: V10CredentialExchange = await self.manager.create_proposal(
                connection_id,
                auto_offer=True,
                comment=comment,
                credential_preview=preview,
                cred_def_id=CRED_DEF_ID,
            )
            save_ex.assert_called_once()

            await self.manager.create_proposal(
                connection_id,
                auto_offer=True,
                comment=comment,
                credential_preview=preview,
                cred_def_id=None,
            )  # OK to leave underspecified until offer

        proposal = CredentialProposal.deserialize(exchange.credential_proposal_dict)

        assert exchange.auto_offer
        assert exchange.connection_id == connection_id
        assert not exchange.credential_definition_id  # leave underspecified until offer
        assert not exchange.schema_id  # leave underspecified until offer
        assert exchange.thread_id == proposal._thread_id
        assert exchange.role == exchange.ROLE_HOLDER
        assert exchange.state == V10CredentialExchange.STATE_PROPOSAL_SENT

    async def test_create_proposal_no_preview(self):
        connection_id = "test_conn_id"
        comment = "comment"

        self.ledger.credential_definition_id2schema_id = async_mock.CoroutineMock(
            return_value=SCHEMA_ID
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            exchange: V10CredentialExchange = await self.manager.create_proposal(
                connection_id,
                auto_offer=True,
                comment=comment,
                credential_preview=None,
                cred_def_id=CRED_DEF_ID,
            )
            save_ex.assert_called_once()

        proposal = CredentialProposal.deserialize(exchange.credential_proposal_dict)

        assert exchange.auto_offer
        assert exchange.connection_id == connection_id
        assert not exchange.credential_definition_id  # leave underspecified until offer
        assert not exchange.schema_id  # leave underspecified until offer
        assert exchange.thread_id == proposal._thread_id
        assert exchange.role == exchange.ROLE_HOLDER
        assert exchange.state == V10CredentialExchange.STATE_PROPOSAL_SENT

    async def test_receive_proposal(self):
        connection_id = "test_conn_id"
        comment = "comment"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            proposal = CredentialProposal(
                credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=None
            )

            exchange = await self.manager.receive_proposal(proposal, connection_id)
            save_ex.assert_called_once()

            assert exchange.connection_id == connection_id
            assert exchange.credential_definition_id is None
            assert exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert exchange.state == V10CredentialExchange.STATE_PROPOSAL_RECEIVED
            assert exchange.schema_id is None
            assert exchange.thread_id == proposal._thread_id

            ret_proposal: CredentialProposal = CredentialProposal.deserialize(
                exchange.credential_proposal_dict
            )
            attrs = ret_proposal.credential_proposal.attributes
            assert attrs == preview.attributes

            self.context.message = CredentialProposal(
                credential_proposal=preview, cred_def_id=None, schema_id=None
            )
            await self.manager.receive_proposal(
                proposal, connection_id
            )  # OK to leave open until offer

    async def test_create_free_offer(self):
        connection_id = "test_conn_id"
        comment = "comment"
        schema_id_parts = SCHEMA_ID.split(":")

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=None
        )

        exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_definition_id=CRED_DEF_ID,
            role=V10CredentialExchange.ROLE_ISSUER,
            credential_proposal_dict=proposal.serialize(),
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            self.cache = InMemoryCache()
            self.context.injector.bind_instance(BaseCache, self.cache)

            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.create_credential_offer = async_mock.CoroutineMock(
                return_value=json.dumps(INDY_OFFER)
            )
            self.context.injector.bind_instance(IndyIssuer, issuer)

            cred_def_record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE,
                CRED_DEF_ID,
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": schema_id_parts[0],
                    "schema_name": schema_id_parts[-2],
                    "schema_version": schema_id_parts[-1],
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                    "epoch": str(int(time())),
                },
            )
            await self.session.storage.add_record(cred_def_record)

            (ret_exchange, ret_offer) = await self.manager.create_offer(
                cred_ex_record=exchange,
                counter_proposal=None,
                comment=comment,
            )
            assert ret_exchange is exchange
            save_ex.assert_called_once()

            issuer.create_credential_offer.assert_called_once_with(CRED_DEF_ID)

            assert exchange.credential_exchange_id == ret_exchange._id  # cover property
            assert exchange.thread_id == ret_offer._thread_id
            assert exchange.credential_definition_id == CRED_DEF_ID
            assert exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert exchange.schema_id == SCHEMA_ID
            assert exchange.state == V10CredentialExchange.STATE_OFFER_SENT
            assert exchange.credential_offer.serialize() == INDY_OFFER

            (ret_exchange, ret_offer) = await self.manager.create_offer(
                cred_ex_record=exchange,
                counter_proposal=None,
                comment=comment,
            )  # once more to cover case where offer is available in cache

    async def test_create_free_offer_attr_mismatch(self):
        connection_id = "test_conn_id"
        comment = "comment"
        schema_id_parts = SCHEMA_ID.split(":")

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legal name", value="value"),
                CredAttrSpec(name="jurisdiction id", value="value"),
                CredAttrSpec(name="incorporation date", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=None
        )

        exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_definition_id=CRED_DEF_ID,
            role=V10CredentialExchange.ROLE_ISSUER,
            credential_proposal_dict=proposal.serialize(),
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            self.cache = InMemoryCache()
            self.context.injector.bind_instance(BaseCache, self.cache)

            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.create_credential_offer = async_mock.CoroutineMock(
                return_value=json.dumps(INDY_OFFER)
            )
            self.context.injector.bind_instance(IndyIssuer, issuer)

            cred_def_record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE,
                CRED_DEF_ID,
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": schema_id_parts[0],
                    "schema_name": schema_id_parts[-2],
                    "schema_version": schema_id_parts[-1],
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                    "epoch": str(int(time())),
                },
            )
            await self.session.storage.add_record(cred_def_record)

            with self.assertRaises(CredentialManagerError):
                await self.manager.create_offer(
                    cred_ex_record=exchange,
                    counter_proposal=None,
                    comment=comment,
                )

    async def test_create_bound_offer(self):
        TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
        schema_id_parts = SCHEMA_ID.split(":")
        connection_id = "test_conn_id"
        comment = "comment"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(credential_proposal=preview)
        exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_proposal_dict=proposal.serialize(),
            role=V10CredentialExchange.ROLE_ISSUER,
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange, "get_cached_key", autospec=True
        ) as get_cached_key, async_mock.patch.object(
            V10CredentialExchange, "set_cached_key", autospec=True
        ) as set_cached_key:
            get_cached_key.return_value = None
            issuer = async_mock.MagicMock(IndyIssuer, autospec=True)
            issuer.create_credential_offer = async_mock.CoroutineMock(
                return_value=json.dumps(INDY_OFFER)
            )
            self.context.injector.bind_instance(IndyIssuer, issuer)

            cred_def_record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE,
                CRED_DEF_ID,
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": schema_id_parts[0],
                    "schema_name": schema_id_parts[-2],
                    "schema_version": schema_id_parts[-1],
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                    "epoch": str(int(time())),
                },
            )
            await self.session.storage.add_record(cred_def_record)

            (ret_exchange, ret_offer) = await self.manager.create_offer(
                cred_ex_record=exchange,
                counter_proposal=None,
                comment=comment,
            )
            assert ret_exchange is exchange
            save_ex.assert_called_once()

            issuer.create_credential_offer.assert_called_once_with(CRED_DEF_ID)

            assert exchange.thread_id == ret_offer._thread_id
            assert exchange.schema_id == SCHEMA_ID
            assert exchange.credential_definition_id == CRED_DEF_ID
            assert exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert exchange.state == V10CredentialExchange.STATE_OFFER_SENT
            assert exchange.credential_offer.serialize() == INDY_OFFER

            # additionally check that credential preview was passed through
            assert ret_offer.credential_preview.attributes == preview.attributes

    async def test_create_bound_offer_no_cred_def(self):
        TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
        schema_id_parts = SCHEMA_ID.split(":")
        connection_id = "test_conn_id"
        comment = "comment"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(credential_proposal=preview)
        exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_proposal_dict=proposal.serialize(),
            role=V10CredentialExchange.ROLE_ISSUER,
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange, "get_cached_key", autospec=True
        ) as get_cached_key, async_mock.patch.object(
            V10CredentialExchange, "set_cached_key", autospec=True
        ) as set_cached_key:
            get_cached_key.return_value = None
            issuer = async_mock.MagicMock()
            issuer.create_credential_offer = async_mock.CoroutineMock(
                return_value=INDY_OFFER
            )
            self.context.injector.bind_instance(IndyIssuer, issuer)

            with self.assertRaises(CredentialManagerError):
                await self.manager.create_offer(
                    cred_ex_record=exchange,
                    counter_proposal=None,
                    comment=comment,
                )

    async def test_receive_offer_proposed(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(credential_proposal=preview)

        offer = CredentialOffer(
            credential_preview=preview,
            offers_attach=[CredentialOffer.wrap_indy_offer(INDY_OFFER)],
        )
        offer.assign_thread_id(thread_id)

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_proposal_dict=proposal.serialize(),
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange,
            "retrieve_by_connection_and_thread",
            async_mock.CoroutineMock(return_value=stored_exchange),
        ) as retrieve_ex:
            exchange = await self.manager.receive_offer(offer, connection_id)

            assert exchange.connection_id == connection_id
            assert exchange.credential_definition_id == CRED_DEF_ID
            assert exchange.schema_id == SCHEMA_ID
            assert exchange.thread_id == offer._thread_id
            assert exchange.role == V10CredentialExchange.ROLE_HOLDER
            assert exchange.state == V10CredentialExchange.STATE_OFFER_RECEIVED
            assert exchange.credential_offer.serialize() == INDY_OFFER

            proposal = CredentialProposal.deserialize(exchange.credential_proposal_dict)
            assert proposal.credential_proposal.attributes == preview.attributes

    async def test_receive_free_offer(self):
        connection_id = "test_conn_id"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )

        offer = CredentialOffer(
            credential_preview=preview,
            offers_attach=[CredentialOffer.wrap_indy_offer(INDY_OFFER)],
        )
        self.context.message = offer
        self.context.connection_record = async_mock.MagicMock()
        self.context.connection_record.connection_id = connection_id

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange,
            "retrieve_by_connection_and_thread",
            async_mock.CoroutineMock(side_effect=StorageNotFoundError),
        ) as retrieve_ex:
            exchange = await self.manager.receive_offer(offer, connection_id)

            assert exchange.connection_id == connection_id
            assert exchange.credential_definition_id == CRED_DEF_ID
            assert exchange.schema_id == SCHEMA_ID
            assert exchange.thread_id == offer._thread_id
            assert exchange.role == V10CredentialExchange.ROLE_HOLDER
            assert exchange.state == V10CredentialExchange.STATE_OFFER_RECEIVED
            assert exchange.credential_offer.serialize() == INDY_OFFER
            assert exchange.credential_proposal_dict

    async def test_create_request(self):
        connection_id = "test_conn_id"
        nonce = "0"
        thread_id = "thread-id"
        holder_did = "did"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_OFFER_RECEIVED,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
        )

        self.cache = InMemoryCache()
        self.context.injector.bind_instance(BaseCache, self.cache)

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            cred_def = {"cred": "def"}
            self.ledger.get_credential_definition = async_mock.CoroutineMock(
                return_value=cred_def
            )

            cred_req_meta = {}
            holder = async_mock.MagicMock()
            holder.create_credential_request = async_mock.CoroutineMock(
                return_value=(json.dumps(INDY_CRED_REQ), json.dumps(cred_req_meta))
            )
            self.context.injector.bind_instance(IndyHolder, holder)

            ret_exchange, ret_request = await self.manager.create_request(
                stored_exchange, holder_did
            )

            holder.create_credential_request.assert_called_once_with(
                INDY_OFFER, cred_def, holder_did
            )

            assert ret_request.indy_cred_req() == INDY_CRED_REQ
            assert ret_request._thread_id == thread_id

            assert ret_exchange.state == V10CredentialExchange.STATE_REQUEST_SENT

            # cover case with request in cache
            stored_exchange.credential_request = None
            stored_exchange.state = V10CredentialExchange.STATE_OFFER_RECEIVED
            await self.manager.create_request(stored_exchange, holder_did)

            # cover case with existing cred req
            stored_exchange.state = V10CredentialExchange.STATE_OFFER_RECEIVED
            stored_exchange.credential_request = INDY_CRED_REQ
            (
                ret_existing_exchange,
                ret_existing_request,
            ) = await self.manager.create_request(stored_exchange, holder_did)
            assert ret_existing_exchange == ret_exchange
            assert ret_existing_request._thread_id == thread_id

    async def test_create_request_no_cache(self):
        connection_id = "test_conn_id"
        nonce = "0"
        thread_id = "thread-id"
        holder_did = "did"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_OFFER_RECEIVED,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            cred_def = {"cred": "def"}
            self.ledger.get_credential_definition = async_mock.CoroutineMock(
                return_value=cred_def
            )

            cred_req_meta = {}
            holder = async_mock.MagicMock()
            holder.create_credential_request = async_mock.CoroutineMock(
                return_value=(json.dumps(INDY_CRED_REQ), json.dumps(cred_req_meta))
            )
            self.context.injector.bind_instance(IndyHolder, holder)

            ret_exchange, ret_request = await self.manager.create_request(
                stored_exchange, holder_did
            )

            holder.create_credential_request.assert_called_once_with(
                INDY_OFFER, cred_def, holder_did
            )

            assert ret_request.indy_cred_req() == INDY_CRED_REQ
            assert ret_request._thread_id == thread_id

            assert ret_exchange.state == V10CredentialExchange.STATE_REQUEST_SENT

    async def test_create_request_bad_state(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"
        holder_did = "did"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_PROPOSAL_SENT,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
        )

        with self.assertRaises(CredentialManagerError):
            await self.manager.create_request(stored_exchange, holder_did)

    async def test_receive_request(self):
        connection_id = "test_conn_id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_ISSUER,
        )

        request = CredentialRequest(
            requests_attach=[CredentialRequest.wrap_indy_cred_req(INDY_CRED_REQ)]
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange,
            "retrieve_by_connection_and_thread",
            async_mock.CoroutineMock(return_value=stored_exchange),
        ) as retrieve_ex:
            exchange = await self.manager.receive_request(request, connection_id)

            retrieve_ex.assert_called_once_with(
                self.session, connection_id, request._thread_id
            )
            save_ex.assert_called_once()

            assert exchange.state == V10CredentialExchange.STATE_REQUEST_RECEIVED
            assert exchange.credential_request.serialize() == INDY_CRED_REQ

    async def test_issue_credential(self):
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
        )

        issuer = async_mock.MagicMock()
        cred = {
            "referent": "12345",
            "attrs": cred_values,
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID
        }
        cred_rev_id = "1000"
        issuer.create_credential = async_mock.CoroutineMock(
            return_value=(json.dumps(cred), cred_rev_id)
        )
        self.context.injector.bind_instance(IndyIssuer, issuer)

        with async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc, async_mock.patch.object(
            asyncio, "ensure_future", autospec=True
        ) as asyncio_mock, async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            revoc.return_value.get_active_issuer_rev_reg_record = (
                async_mock.CoroutineMock(
                    return_value=async_mock.MagicMock(  # active_rev_reg_rec
                        revoc_reg_id=REV_REG_ID,
                        get_registry=async_mock.CoroutineMock(
                            return_value=async_mock.MagicMock(  # rev_reg
                                tails_local_path="dummy-path",
                                get_or_fetch_local_tails_path=(
                                    async_mock.CoroutineMock()
                                ),
                            )
                        ),
                    )
                )
            )
            (ret_exchange, ret_cred_issue) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=1
            )

            save_ex.assert_called_once()

            issuer.create_credential.assert_called_once_with(
                SCHEMA,
                INDY_OFFER,
                INDY_CRED_REQ,
                cred_values,
                stored_exchange.credential_exchange_id,
                REV_REG_ID,
                "dummy-path",
            )

            assert ret_exchange.credential.serialize() == cred
            assert ret_cred_issue.indy_credential() == cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ISSUED
            assert ret_cred_issue._thread_id == thread_id

            # cover case with existing cred
            stored_exchange.credential = cred
            stored_exchange.state = V10CredentialExchange.STATE_REQUEST_RECEIVED
            (
                ret_existing_exchange,
                ret_existing_cred,
            ) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=0
            )
            assert ret_existing_exchange == ret_exchange
            assert ret_existing_cred._thread_id == thread_id

    async def test_issue_credential_non_revocable(self):
        CRED_DEF_NR = deepcopy(CRED_DEF)
        CRED_DEF_NR["value"]["revocation"] = None
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
        )

        issuer = async_mock.MagicMock()
        cred = {
            "referent": "12345",
            "attrs": cred_values,
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID
        }
        issuer.create_credential = async_mock.CoroutineMock(
            return_value=(json.dumps(cred), None)
        )
        self.context.injector.bind_instance(IndyIssuer, issuer)

        Ledger = async_mock.MagicMock()
        self.ledger = Ledger()
        self.ledger.get_schema = async_mock.CoroutineMock(return_value=SCHEMA)
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value=CRED_DEF_NR
        )
        self.ledger.__aenter__ = async_mock.CoroutineMock(return_value=self.ledger)
        self.context.injector.clear_binding(BaseLedger)
        self.context.injector.bind_instance(BaseLedger, self.ledger)

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            (ret_exchange, ret_cred_issue) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=0
            )

            save_ex.assert_called_once()

            issuer.create_credential.assert_called_once_with(
                SCHEMA,
                INDY_OFFER,
                INDY_CRED_REQ,
                cred_values,
                stored_exchange.credential_exchange_id,
                None,
                None,
            )

            assert ret_exchange.credential.serialize() == cred
            assert ret_cred_issue.indy_credential() == cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ISSUED
            assert ret_cred_issue._thread_id == thread_id

    async def test_issue_credential_fills_rr(self):
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
            revocation_id="1000",
        )

        issuer = async_mock.MagicMock()
        cred = {
            "referent": "12345",
            "attrs": cred_values,
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID
        }
        issuer.create_credential = async_mock.CoroutineMock(
            return_value=(json.dumps(cred), stored_exchange.revocation_id)
        )
        self.context.injector.bind_instance(IndyIssuer, issuer)

        with async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc, async_mock.patch.object(
            asyncio, "ensure_future", autospec=True
        ) as asyncio_mock, async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            revoc.return_value = async_mock.MagicMock(
                get_active_issuer_rev_reg_record=(
                    async_mock.CoroutineMock(
                        return_value=async_mock.MagicMock(  # active_rev_reg_rec
                            revoc_reg_id=REV_REG_ID,
                            get_registry=async_mock.CoroutineMock(
                                return_value=async_mock.MagicMock(  # rev_reg
                                    tails_local_path="dummy-path",
                                    max_creds=1000,
                                    get_or_fetch_local_tails_path=(
                                        async_mock.CoroutineMock()
                                    ),
                                )
                            ),
                            set_state=async_mock.CoroutineMock(),
                        )
                    )
                ),
                init_issuer_registry=async_mock.CoroutineMock(
                    return_value=async_mock.MagicMock(  # pending_rev_reg_rec
                        stage_pending_registry=async_mock.CoroutineMock()
                    )
                ),
            )
            (ret_exchange, ret_cred_issue) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=0
            )

            save_ex.assert_called_once()

            issuer.create_credential.assert_called_once_with(
                SCHEMA,
                INDY_OFFER,
                INDY_CRED_REQ,
                cred_values,
                stored_exchange.credential_exchange_id,
                REV_REG_ID,
                "dummy-path",
            )

            assert ret_exchange.credential.serialize() == cred
            assert ret_cred_issue.indy_credential() == cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ISSUED
            assert ret_cred_issue._thread_id == thread_id

    async def test_issue_credential_request_bad_state(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_PROPOSAL_SENT,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
        )

        with self.assertRaises(CredentialManagerError):
            await self.manager.issue_credential(stored_exchange)

    async def test_issue_credential_no_active_rr_no_retries(self):
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
        )

        issuer = async_mock.MagicMock()
        cred = {"indy": "credential"}
        cred_rev_id = "1"
        issuer.create_credential = async_mock.CoroutineMock(
            return_value=(json.dumps(cred), cred_rev_id)
        )
        self.context.injector.bind_instance(IndyIssuer, issuer)

        with async_mock.patch.object(
            test_module, "IssuerRevRegRecord", autospec=True
        ) as issuer_rr_rec, async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc, async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            revoc.return_value.get_active_issuer_rev_reg_record = (
                async_mock.CoroutineMock(side_effect=test_module.StorageNotFoundError())
            )
            revoc.return_value.init_issuer_registry = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(  # pending_rev_reg_rec
                    stage_pending_registry=async_mock.CoroutineMock()
                )
            )
            issuer_rr_rec.query_by_cred_def_id = async_mock.CoroutineMock(
                return_value=[]
            )
            with self.assertRaises(CredentialManagerError) as x_cred_mgr:
                await self.manager.issue_credential(
                    stored_exchange, comment=comment, retries=0
                )
                assert "has no active revocation registry" in x_cred_mgr.message

    async def test_issue_credential_no_active_rr_retry(self):
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
        )

        issuer = async_mock.MagicMock()
        cred = {"indy": "credential"}
        cred_rev_id = "1"
        issuer.create_credential = async_mock.CoroutineMock(
            return_value=(json.dumps(cred), cred_rev_id)
        )
        self.context.injector.bind_instance(IndyIssuer, issuer)

        with async_mock.patch.object(
            test_module, "IssuerRevRegRecord", autospec=True
        ) as issuer_rr_rec, async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc, async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex:
            revoc.return_value.get_active_issuer_rev_reg_record = (
                async_mock.CoroutineMock(side_effect=test_module.StorageNotFoundError())
            )
            issuer_rr_rec.query_by_cred_def_id = async_mock.CoroutineMock(
                side_effect=[
                    [],  # posted_rev_reg_recs
                    [async_mock.MagicMock(max_cred_num=1000)],  # old_rev_reg_recs
                ]
                * 2
            )
            revoc.return_value.init_issuer_registry = async_mock.CoroutineMock(
                return_value=async_mock.MagicMock(  # pending_rev_reg_rec
                    stage_pending_registry=async_mock.CoroutineMock()
                )
            )
            with self.assertRaises(CredentialManagerError) as x_cred_mgr:
                await self.manager.issue_credential(
                    stored_exchange, comment=comment, retries=1
                )
                assert "has no active revocation registry" in x_cred_mgr.message

    async def test_issue_credential_rr_full(self):
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
        )

        issuer = async_mock.MagicMock()
        cred = {"indy": "credential"}
        issuer.create_credential = async_mock.CoroutineMock(
            side_effect=test_module.IndyIssuerRevocationRegistryFullError("Nope")
        )
        self.context.injector.bind_instance(IndyIssuer, issuer)

        with async_mock.patch.object(
            test_module, "IndyRevocation", autospec=True
        ) as revoc:
            revoc.return_value.get_active_issuer_rev_reg_record = (
                async_mock.CoroutineMock(
                    return_value=async_mock.MagicMock(  # active_rev_reg_rec
                        revoc_reg_id=REV_REG_ID,
                        set_state=async_mock.CoroutineMock(),
                        get_registry=async_mock.CoroutineMock(
                            return_value=async_mock.MagicMock(  # rev_reg
                                tails_local_path="dummy-path",
                                get_or_fetch_local_tails_path=(
                                    async_mock.CoroutineMock()
                                ),
                            )
                        ),
                    )
                )
            )

            with self.assertRaises(test_module.IndyIssuerRevocationRegistryFullError):
                await self.manager.issue_credential(
                    stored_exchange, comment=comment, retries=1
                )

    async def test_receive_credential(self):
        connection_id = "test_conn_id"
        indy_cred = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "values": {
                "a": {
                    "raw": "1",
                    "encoded": "1"
                }
            },
            "signature": {"...": "..."},
            "signature_correctness_proof": {"...": "..."},
            "witness": {"...": "..."}
        }

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_ISSUER,
        )

        issue = CredentialIssue(
            credentials_attach=[CredentialIssue.wrap_indy_credential(indy_cred)]
        )

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange,
            "retrieve_by_connection_and_thread",
            async_mock.CoroutineMock(return_value=stored_exchange),
        ) as retrieve_ex:
            exchange = await self.manager.receive_credential(issue, connection_id)

            retrieve_ex.assert_called_once_with(
                self.session, connection_id, issue._thread_id
            )
            save_ex.assert_called_once()

            assert exchange.raw_credential.serialize() == indy_cred
            assert exchange.state == V10CredentialExchange.STATE_CREDENTIAL_RECEIVED

    async def test_store_credential(self):
        connection_id = "test_conn_id"
        indy_cred = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "values": {
                "a": {
                    "raw": "1",
                    "encoded": "1"
                }
            },
            "signature": {"...": "..."},
            "signature_correctness_proof": {"...": "..."},
            "witness": {"...": "..."}
        }
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=SCHEMA_ID
        )

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=proposal,
            raw_credential=indy_cred,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id=thread_id,
            auto_remove=True,
        )

        cred_id = "cred-id"
        holder = async_mock.MagicMock()
        holder.store_credential = async_mock.CoroutineMock(return_value=cred_id)
        cred_values = {"attr": "value"}
        stored_cred = {
            "referent": cred_id,
            "attrs": cred_values,
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID
        }
        indy_cred = {
            "schema_id": SCHEMA_ID,
            "cred_def_id": CRED_DEF_ID,
            "values": {
                "a": {
                    "raw": "1",
                    "encoded": "1"
                }
            },
            "signature": {"...": "..."},
            "signature_correctness_proof": {"...": "..."},
            "witness": {"...": "..."},
        }
        holder.get_credential = async_mock.CoroutineMock(
            return_value=json.dumps(stored_cred)
        )
        self.context.injector.bind_instance(IndyHolder, holder)

        with async_mock.patch.object(
            test_module, "RevocationRegistry", autospec=True
        ) as mock_rev_reg, async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange, "delete_record", autospec=True
        ) as delete_ex:

            mock_rev_reg.from_definition = async_mock.MagicMock(
                return_value=async_mock.MagicMock(
                    get_or_fetch_local_tails_path=async_mock.CoroutineMock()
                )
            )
            ret_exchange, ret_cred_ack = await self.manager.store_credential(
                stored_exchange, credential_id=cred_id
            )

            save_ex.assert_called_once()

            self.ledger.get_credential_definition.assert_called_once_with(CRED_DEF_ID)

            holder.store_credential.assert_called_once_with(
                CRED_DEF,
                IndyCredential.deserialize(indy_cred),
                cred_req_meta,
                {},
                credential_id=cred_id,
                rev_reg_def=None,
            )

            holder.get_credential.assert_called_once_with(cred_id)

            assert ret_exchange.credential_id == cred_id
            assert ret_exchange.credential.serialize() == stored_cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ACKED
            assert ret_cred_ack._thread_id == thread_id

    async def test_store_credential_bad_state(self):
        connection_id = "test_conn_id"
        cred = {"cred_def_id": CRED_DEF_ID}
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=None,
            raw_credential=cred,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_OFFER_RECEIVED,
            thread_id=thread_id,
        )
        cred_id = "cred-id"

        with self.assertRaises(CredentialManagerError):
            await self.manager.store_credential(stored_exchange, credential_id=cred_id)

    async def test_store_credential_no_preview(self):
        connection_id = "test_conn_id"
        cred = {"cred_def_id": CRED_DEF_ID}
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=None,
            raw_credential=cred,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id=thread_id,
        )

        cred_def = async_mock.MagicMock()
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value=cred_def
        )

        cred_id = "cred-id"
        holder = async_mock.MagicMock()
        holder.store_credential = async_mock.CoroutineMock(return_value=cred_id)
        stored_cred = {"stored": "cred"}
        holder.get_credential = async_mock.CoroutineMock(
            return_value=json.dumps(stored_cred)
        )
        self.context.injector.bind_instance(IndyHolder, holder)

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange, "delete_record", autospec=True
        ) as delete_ex:
            ret_exchange, ret_cred_ack = await self.manager.store_credential(
                stored_exchange
            )

            save_ex.assert_called_once()

            self.ledger.get_credential_definition.assert_called_once_with(CRED_DEF_ID)

            holder.store_credential.assert_called_once_with(
                cred_def,
                cred,
                cred_req_meta,
                None,
                credential_id=None,
                rev_reg_def=None,
            )

            holder.get_credential.assert_called_once_with(cred_id)

            assert ret_exchange.credential_id == cred_id
            assert ret_exchange.credential == stored_cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ACKED
            assert ret_cred_ack._thread_id == thread_id

    async def test_store_credential_holder_store_indy_error(self):
        connection_id = "test_conn_id"
        cred = {"cred_def_id": CRED_DEF_ID}
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=None,
            raw_credential=cred,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id=thread_id,
        )

        cred_def = async_mock.MagicMock()
        self.ledger.get_credential_definition = async_mock.CoroutineMock(
            return_value=cred_def
        )

        cred_id = "cred-id"
        holder = async_mock.MagicMock()
        holder.store_credential = async_mock.CoroutineMock(
            side_effect=test_module.IndyHolderError("Problem", {"message": "Nope"})
        )
        self.context.injector.bind_instance(IndyHolder, holder)

        with self.assertRaises(test_module.IndyHolderError):
            await self.manager.store_credential(
                cred_ex_record=stored_exchange, credential_id=cred_id
            )

    async def test_credential_ack(self):
        connection_id = "connection-id"
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
        )

        ack = CredentialAck()

        with async_mock.patch.object(
            V10CredentialExchange, "save", autospec=True
        ) as save_ex, async_mock.patch.object(
            V10CredentialExchange, "delete_record", autospec=True
        ) as delete_ex, async_mock.patch.object(
            V10CredentialExchange,
            "retrieve_by_connection_and_thread",
            async_mock.CoroutineMock(return_value=stored_exchange),
        ) as retrieve_ex:
            ret_exchange = await self.manager.receive_credential_ack(ack, connection_id)

            retrieve_ex.assert_called_once_with(
                self.session, connection_id, ack._thread_id
            )
            save_ex.assert_called_once()

            assert ret_exchange.state == V10CredentialExchange.STATE_ACKED
            delete_ex.assert_called_once()

    async def test_retrieve_records(self):
        self.cache = InMemoryCache()
        self.session.context.injector.bind_instance(BaseCache, self.cache)

        for index in range(2):
            exchange_record = V10CredentialExchange(
                connection_id=str(index),
                thread_id=str(1000 + index),
                initiator=V10CredentialExchange.INITIATOR_SELF,
                role=V10CredentialExchange.ROLE_ISSUER,
            )
            await exchange_record.save(self.session)

        for i in range(2):  # second pass gets from cache
            for index in range(2):
                ret_ex = await V10CredentialExchange.retrieve_by_connection_and_thread(
                    self.session, str(index), str(1000 + index)
                )
                assert ret_ex.connection_id == str(index)
                assert ret_ex.thread_id == str(1000 + index)
