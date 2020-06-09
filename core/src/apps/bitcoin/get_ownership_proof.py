from ubinascii import hexlify

from trezor import ui, wire
from trezor.messages.GetOwnershipProof import GetOwnershipProof
from trezor.messages.OwnershipProof import OwnershipProof
from trezor.ui.text import Text

from apps.common import coininfo
from apps.common.confirm import require_confirm

from . import addresses, common, scripts
from .keychain import with_keychain
from .ownership import generate_proof, get_identifier

if False:
    from apps.common.seed import Keychain


@with_keychain
async def get_ownership_proof(
    ctx, msg: GetOwnershipProof, keychain: Keychain, coin: coininfo.CoinInfo
):
    if msg.script_type not in common.INTERNAL_INPUT_SCRIPT_TYPES:
        raise wire.DataError("Invalid script type")

    node = keychain.derive(msg.address_n)
    address = addresses.get_address(msg.script_type, coin, node, msg.multisig)
    script_pubkey = scripts.output_derive_script(address, coin)
    ownership_id = get_identifier(script_pubkey, keychain)

    if msg.multisig:
        if ownership_id not in msg.ownership_ids:
            raise wire.DataError("Missing ownership identifier")
    else:
        msg.ownership_ids = [ownership_id]

    if msg.user_confirmation:
        text = Text("Proof of ownership", ui.ICON_CONFIG)
        text.normal("Do you really want to")
        text.normal("generate a proof of")
        if msg.commitment_data:
            text.normal("ownership for")
            text.normal(hexlify.decode(msg.commitment_data))
        else:
            text.normal("ownership?")
        await require_confirm(ctx, text)

    ownership_proof = generate_proof(
        node,
        msg.script_type,
        msg.multisig,
        msg.user_confirmation,
        msg.ownership_ids,
        script_pubkey,
        msg.commitment_data,
    )

    return OwnershipProof(ownership_proof)
