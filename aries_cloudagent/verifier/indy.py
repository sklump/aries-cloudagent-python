"""Indy verifier implementation."""

import json
import logging

from enum import Enum

import indy.anoncreds

from indy.error import IndyError

from ..ledger.base import BaseLedger
from ..messaging.util import canon, encode
from ..utils.frill import Ink, ppjson

from .base import BaseVerifier

LOGGER = logging.getLogger(__name__)


class PreVerifyResult(Enum):
    """Represent the result of IndyVerifier.pre_verify."""

    OK = "ok"
    INCOMPLETE = "missing essential components"
    ENCODING_MISMATCH = "demonstrates tampering with raw values"


class IndyVerifier(BaseVerifier):
    """Indy verifier class."""

    def __init__(self, ledger: BaseLedger):
        """
        Initialize an IndyVerifier instance.

        Args:
            ledger: ledger instance

        """
        self.ledger = ledger

    def non_revoc_intervals(self, pres_req: dict, pres: dict):
        """
        Remove superfluous non-revocation intervals in presentation request.

        Indy rejects proof requests with non-revocation intervals lining up
        with non-revocable credentials in proof: seek and remove.

        Args:
            pres_req: presentation request
            pres: corresponding presentation

        """

        print(Ink.CYAN(f"\n  >> VERIFIER seeking superfluous non-revoc intervals"))
        for (req_proof_key, pres_key) in {
            "revealed_attrs": "requested_attributes",
            "revealed_attr_groups": "requested_attributes",
            "predicates": "requested_predicates",
        }.items():
            for (uuid, spec) in pres["requested_proof"].get(req_proof_key, {}).items():
                if (
                    pres["identifiers"][spec["sub_proof_index"]].get("timestamp")
                    is None
                ):
                    if pres_req[pres_key][uuid].pop("non_revoked", None):
                        print(Ink.CYAN(f"    .. removed NRI at referent {uuid}"))
                        LOGGER.warning(
                            (
                                "Amended presentation request (nonce=%s): removed "
                                "non-revocation interval at %s referent "
                                "%s; no corresponding revocable credential in proof"
                            ),
                            pres_req["nonce"],
                            pres_key,
                            uuid,
                        )

        if all(spec.get("timestamp") is None for spec in pres["identifiers"]):
            pres_req.pop("non_revoked", None)
            print(Ink.CYAN(f"    .. removed top-level NRI"))
            LOGGER.warning(
                (
                    "Amended presentation request (nonce=%s); removed global "
                    "non-revocation interval; no revocable credentials in proof"
                ),
                pres_req["nonce"],
            )

    async def pre_verify(self, pres_req: dict, pres: dict) -> (PreVerifyResult, str):
        """
        Check for essential components and tampering in presentation.

        Visit encoded attribute values against raw, and predicate bounds,
        in presentation, cross-reference against presentation request.

        Args:
            pres_req: presentation request
            pres: corresponding presentation

        Returns:
            A tuple with `PreVerifyResult` representing the validation result and
            reason text for failure or None for OK.

        """
        print(Ink.CYAN(f"\n  >> VERIFIER conducting pre-verification sniff tests"))

        if not (
            pres_req
            and "requested_predicates" in pres_req
            and "requested_attributes" in pres_req
        ):
            return (PreVerifyResult.INCOMPLETE, "Incomplete or missing proof request")
        if not pres:
            return (PreVerifyResult.INCOMPLETE, "No proof provided")
        if "requested_proof" not in pres:
            return (PreVerifyResult.INCOMPLETE, "Missing 'requested_proof'")
        if "proof" not in pres:
            return (PreVerifyResult.INCOMPLETE, "Missing 'proof'")

        async with self.ledger:
            for (index, ident) in enumerate(pres["identifiers"]):
                if not ident.get("timestamp"):
                    cred_def_id = ident["cred_def_id"]
                    cred_def = await self.ledger.get_credential_definition(cred_def_id)
                    if cred_def["value"].get("revocation"):
                        print(Ink.CYAN(f"    .. Fail -1: #{index} for {cred_def_id}"))
                        return (
                            PreVerifyResult.INCOMPLETE,
                            (
                                f"Missing timestamp in presentation identifier "
                                f"#{index} for cred def id {cred_def_id}"
                            ),
                        )

        for (uuid, req_pred) in pres_req["requested_predicates"].items():
            try:
                canon_attr = canon(req_pred["name"])
                for ge_proof in pres["proof"]["proofs"][
                    pres["requested_proof"]["predicates"][uuid]["sub_proof_index"]
                ]["primary_proof"]["ge_proofs"]:
                    pred = ge_proof["predicate"]
                    if pred["attr_name"] == canon_attr:
                        if pred["value"] != req_pred["p_value"]:
                            print(Ink.CYAN(f"    .. Fail -2: {pred['attr_name']}"))
                            return (
                                PreVerifyResult.INCOMPLETE,
                                f"Predicate value != p_value: {pred['attr_name']}",
                            )
                        break
                else:
                    print(Ink.CYAN(f"    .. Fail -3: {uuid}"))
                    return (
                        PreVerifyResult.INCOMPLETE,
                        f"Missing requested predicate '{uuid}'",
                    )
            except (KeyError, TypeError):
                print(Ink.CYAN(f"    .. Fail -4: {uuid}"))
                return (
                    PreVerifyResult.INCOMPLETE,
                    f"Missing requested predicate '{uuid}'",
                )

        revealed_attrs = pres["requested_proof"].get("revealed_attrs", {})
        revealed_groups = pres["requested_proof"].get("revealed_attr_groups", {})
        self_attested = pres["requested_proof"].get("self_attested_attrs", {})
        for (uuid, req_attr) in pres_req["requested_attributes"].items():
            if "name" in req_attr:
                if uuid in revealed_attrs:
                    pres_req_attr_spec = {req_attr["name"]: revealed_attrs[uuid]}
                elif uuid in self_attested:
                    if not req_attr.get("restrictions"):
                        continue
                    else:
                        print(Ink.CYAN(f"    .. Fail -5: {req_attr['name']}"))
                        return (
                            PreVerifyResult.INCOMPLETE,
                            "Attribute with restrictions cannot be self-attested "
                            f"'{req_attr['name']}'",
                        )
                else:
                    print(Ink.CYAN(f"    .. Fail -6: {req_attr['name']}"))
                    return (
                        PreVerifyResult.INCOMPLETE,
                        f"Missing requested attribute '{req_attr['name']}'",
                    )
            elif "names" in req_attr:
                group_spec = revealed_groups.get(uuid)
                if (
                    group_spec is None
                    or "sub_proof_index" not in group_spec
                    or "values" not in group_spec
                ):
                    print(Ink.CYAN(f"    .. Fail -7: attr group {uuid}"))
                    return (
                        PreVerifyResult.INCOMPLETE,
                        f"Missing requested attribute group '{uuid}'",
                    )
                pres_req_attr_spec = {
                    attr: {
                        "sub_proof_index": group_spec["sub_proof_index"],
                        **group_spec["values"].get(attr),
                    }
                    for attr in req_attr["names"]
                }
            else:
                print(Ink.CYAN(f"    .. Fail -8: name/names {uuid}"))
                return (
                    PreVerifyResult.INCOMPLETE,
                    f"Request attribute missing 'name' and 'names': '{uuid}'",
                )

            for (attr, spec) in pres_req_attr_spec.items():
                try:
                    primary_enco = pres["proof"]["proofs"][spec["sub_proof_index"]][
                        "primary_proof"
                    ]["eq_proof"]["revealed_attrs"][canon(attr)]
                except (KeyError, TypeError):
                    print(Ink.CYAN(f"    .. Fail -9: {attr}"))
                    return (
                        PreVerifyResult.INCOMPLETE,
                        f"Missing revealed attribute: '{attr}'",
                    )
                if primary_enco != spec["encoded"]:
                    print(Ink.CYAN(f"    .. Fail -10: {attr}"))
                    return (
                        PreVerifyResult.ENCODING_MISMATCH,
                        f"Encoded representation mismatch for '{attr}'",
                    )
                if primary_enco != encode(spec["raw"]):
                    print(Ink.CYAN(f"    .. Fail -11: {attr}"))
                    return (
                        PreVerifyResult.ENCODING_MISMATCH,
                        f"Encoded representation mismatch for '{attr}'",
                    )

        return (PreVerifyResult.OK, None)

    async def verify_presentation(
        self,
        presentation_request,
        presentation,
        schemas,
        credential_definitions,
        rev_reg_defs,
        rev_reg_entries,
    ) -> bool:
        """
        Verify a presentation.

        Args:
            presentation_request: Presentation request data
            presentation: Presentation data
            schemas: Schema data
            credential_definitions: credential definition data
            rev_reg_defs: revocation registry definitions
            rev_reg_entries: revocation registry entries
        """

        print(Ink.CYAN(f"\n\n$$ $$ VERIFIER verifying pres"))
        print(Ink.CYAN(f".. pres req {ppjson(presentation_request)}"))
        print(Ink.CYAN(f".. pres {ppjson(presentation, 256)}"))
        self.non_revoc_intervals(presentation_request, presentation)

        (pv_result, pv_msg) = await self.pre_verify(presentation_request, presentation)
        if pv_result != PreVerifyResult.OK:
            LOGGER.error(
                f"Presentation on nonce={presentation_request['nonce']} "
                f"cannot be validated: {pv_result.value} [{pv_msg}]"
            )
            return False

        try:
            verified = await indy.anoncreds.verifier_verify_proof(
                json.dumps(presentation_request),
                json.dumps(presentation),
                json.dumps(schemas),
                json.dumps(credential_definitions),
                json.dumps(rev_reg_defs),
                json.dumps(rev_reg_entries),
            )
        except IndyError as err:
            print(Ink.CYAN(f".. Indy exception: {err}"))
            LOGGER.exception(
                f"Validation of presentation on nonce={presentation_request['nonce']} "
                "failed with error"
            )
            verified = False

        print(Ink.CYAN(f".. verified = {verified}"))
        return verified
