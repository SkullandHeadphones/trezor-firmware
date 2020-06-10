from common import unhexlify, unittest
from trezor.crypto import bip39
from trezor.messages import InputScriptType

from apps.common import coins
from apps.common.seed import Keychain
from apps.common.paths import HARDENED
from apps.bitcoin import ownership, scripts
from apps.bitcoin.addresses import address_p2wpkh, address_p2wpkh_in_p2sh


class TestOwnershipProof(unittest.TestCase):

    def test_p2wpkh_gen_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), 'TREZOR')
        keychain = Keychain(seed, [[coin.curve_name, [84 | HARDENED]], ["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        node = keychain.derive([84 | HARDENED, 1 | HARDENED, 0 | HARDENED, 1, 0])
        address = address_p2wpkh(node.public_key(), coin)
        script_pubkey = scripts.output_derive_script(address, coin)
        ownership_id = ownership.get_identifier(script_pubkey, keychain)

        self.assertEqual(ownership_id, unhexlify("79545dade6a5e05f21cf6a3c7fea17c12415fe11a8f9a32245aea50aad1a9a5b"))

        proof = ownership.generate_proof(
            node=node,
            script_type=InputScriptType.SPENDWITNESS,
            multisig=None,
            coin=coin,
            user_confirmed=False,
            ownership_ids=[ownership_id],
            script_pubkey=script_pubkey,
            commitment_data=b"",
        )

        self.assertEqual(proof, unhexlify("534c0019000179545dade6a5e05f21cf6a3c7fea17c12415fe11a8f9a32245aea50aad1a9a5b0002473044022029fe554f67a74d867eee84d1eb2410a863bff3fecbcb81ed7dba1cba2db35a8a0220175fedbc3140f518a27b9f63e3ba4fcb09e09840b6efc73bfd3df78b6aeefd3f012103bfda1fc7f507697f341523e6c28fa3e2bd10450c9c7099eaddb48020a7923865"))

        self.assertFalse(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))

    def test_p2wpkh_in_p2sh_gen_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), 'TREZOR')
        keychain = Keychain(seed, [[coin.curve_name, [49 | HARDENED]], ["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        node = keychain.derive([49 | HARDENED, 1 | HARDENED, 0 | HARDENED, 1, 0])
        address = address_p2wpkh_in_p2sh(node.public_key(), coin)
        script_pubkey = scripts.output_derive_script(address, coin)
        ownership_id = ownership.get_identifier(script_pubkey, keychain)

        self.assertEqual(ownership_id, unhexlify("a3e8dafa493aaed51046fa7c537c6b0d1c918c755ec86be16005fcb6355da8d2"))

        proof = ownership.generate_proof(
            node=node,
            script_type=InputScriptType.SPENDP2SHWITNESS,
            multisig=None,
            coin=coin,
            user_confirmed=False,
            ownership_ids=[ownership_id],
            script_pubkey=script_pubkey,
            commitment_data=b"",
        )

        self.assertEqual(proof, unhexlify("534c00190001a3e8dafa493aaed51046fa7c537c6b0d1c918c755ec86be16005fcb6355da8d2171600141f323c6463b090925b277f8de42421a6d30ae1aa02483045022100f5c79bb4d779ef3cc37b79341ef3f7324071bbfa05c24d818778069e54df42bc02204b11966520a19908fdaee7148c557e9c40a608cf36c57bfc982ed566ee89129301210328b9a0c96606460f38bf08385cbcf25ef770d894a6d1360f01512272bc7267b4"))

        self.assertFalse(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))

    def test_p2pkh_gen_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), 'TREZOR')
        keychain = Keychain(seed, [[coin.curve_name, [44 | HARDENED]], ["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        node = keychain.derive([44 | HARDENED, 1 | HARDENED, 0 | HARDENED, 1, 0])
        address = node.address(coin.address_type)
        script_pubkey = scripts.output_derive_script(address, coin)
        ownership_id = ownership.get_identifier(script_pubkey, keychain)
        self.assertEqual(ownership_id, unhexlify("728918adf44fda28450987b58a7e67f6548777a6aca38b2847b155c375c0582c"))

        proof = ownership.generate_proof(
            node=node,
            script_type=InputScriptType.SPENDADDRESS,
            multisig=None,
            coin=coin,
            user_confirmed=False,
            ownership_ids=[ownership_id],
            script_pubkey=script_pubkey,
            commitment_data=b"",
        )

        self.assertEqual(proof, unhexlify("534c00190001728918adf44fda28450987b58a7e67f6548777a6aca38b2847b155c375c0582c6a47304402201a47ce5eb4ffb0155391ec469e46f7b43b8d4bd31a65c4814aba9838dc98fdbc022031651462e6ced87eb0f222bdf6cbd2d9074436d889d391c10f878dcedab17b8601210225fc2b64441a8b2cf6e12a10f72852e111398811f4a32757621906062ec178b100"))

        self.assertFalse(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))

    def test_p2wpkh_verify_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), 'TREZOR')
        keychain = Keychain(seed, [["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        # Proof for "all all ... all" seed without passphrase.
        script_pubkey = unhexlify("0014cc8067093f6f843d6d3e22004a4290cd0c0f336b")
        proof = unhexlify("534c00190001f3ce2cb33599634353452b60b38e311282b6fca743eb6147d3d492066c8963de0002483045022100f27a609a3746f29c4ec0d2bfca21ac1ac05ef25aeaf42b42f9ab25c548c9bbcd0220797fb5cf575ed808c74de2a8dc5aca02a44da550c791f0d7252122a21cc525b8012103505647c017ff2156eb6da20fae72173d3b681a1d0a629f95f49e884db300689f")
        self.assertTrue(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))


if __name__ == '__main__':
    unittest.main()
