import json

from asynctest import TestCase as AsyncTestCase, mock as async_mock

from ..invitation_model import InvitationModel, InvitationModelSchema


class TestInvitationModel(AsyncTestCase):
    def test_invitation_model(self):
        """Test invitation model."""
        invi = InvitationModel(invitation_id="0")
        assert isinstance(invi, InvitationModel)
        assert invi.invitation_id == "0"
        assert invi.record_value == {
            "invitation_id": "0",
            "invitation": None,
            "state": None,
            "trace": False,
        }

        another = InvitationModel(invitation_id="1")
        assert invi != another


class TestInvitationModelSchema(AsyncTestCase):
    def test_make_model(self):
        """Test making model."""
        print(f"\n\n:: TEST making model {InvitationModelSchema.Meta.model_class}")
        data = {
            "invitation_id": "0",
            "state": InvitationModel.STATE_AWAIT_RESPONSE,
            "invitation": {"sample": "value"},
        }
        model_instance = InvitationModel.deserialize(data)
        assert isinstance(model_instance, InvitationModel)
