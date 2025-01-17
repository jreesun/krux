# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# pylint: disable=W0102
import time

try:
    import urandom as random
except:
    import random
from binascii import hexlify
from hashlib import sha256
from embit import bip32, bip39
from embit.wordlists.bip39 import WORDLIST
from embit.networks import NETWORKS
from .settings import (
    TEST_TXT,
    THIN_SPACE,
    NAME_SINGLE_SIG,
    NAME_MULTISIG,
    NAME_MINISCRIPT,
)

DER_SINGLE = "m/%dh/%dh/%dh"
DER_MULTI = "m/%dh/%dh/%dh/2h"
DER_MINISCRIPT = "m/%dh/%dh/%dh/2h"
HARDENED_STR_REPLACE = "'"

# Pay To Public Key Hash - 44' Legacy single-sig
# address starts with 1 (mainnet) or m (testnet)
P2PKH = "p2pkh"

# Pay To Script Hash - 45' Legacy multisig
# address starts with 3 (mainnet) or 2 (testnet)
P2SH = "p2sh"

# Pay To Witness Public Key Hash Wrapped In P2SH - 49' Nested Segwit single-sig
# address starts with 3 (mainnet) or 2 (testnet)
P2SH_P2WPKH = "p2sh-p2wpkh"

# Pay To Witness Script Hash Wrapped In P2SH - 48'/0'/0'/1' Nested Segwit multisig
# address starts with 3 (mainnet) or 2 (testnet)
P2SH_P2WSH = "p2sh-p2wsh"

# Pay To Witness Public Key Hash - 84' Native Segwit single-sig
# address starts with bc1q (mainnet) or tb1q (testnet)
P2WPKH = "p2wpkh"

# Pay To Witness Script Hash - 48'/0'/0'/2' Native Segwit multisig
# address starts with bc1q (mainnet) or tb1q (testnet)
P2WSH = "p2wsh"

# Pay To Taproot - 86' Taproot single-sig
# address starts with bc1p (mainnet) or tb1p (testnet)
P2TR = "p2tr"

SCRIPT_LONG_NAMES = {
    "Legacy - 44": P2PKH,
    "Nested Segwit - 49": P2SH_P2WPKH,
    "Native Segwit - 84": P2WPKH,
    "Taproot - 86": P2TR,
}

SINGLESIG_SCRIPT_PURPOSE = {
    P2PKH: 44,
    P2SH_P2WPKH: 49,
    P2WPKH: 84,
    P2TR: 86,
}

TYPE_SINGLESIG = 0
TYPE_MULTISIG = 1
TYPE_MINISCRIPT = 2

POLICY_TYPE_IDS = {
    NAME_SINGLE_SIG: TYPE_SINGLESIG,
    NAME_MULTISIG: TYPE_MULTISIG,
    NAME_MINISCRIPT: TYPE_MINISCRIPT,
}

MULTISIG_SCRIPT_PURPOSE = 48
MINISCRIPT_PURPOSE = 48

FINGERPRINT_SYMBOL = "⊚"
DERIVATION_PATH_SYMBOL = "↳"


class Key:
    """Represents a BIP-39 mnemonic-based private key"""

    def __init__(
        self,
        mnemonic,
        policy_type,
        network=NETWORKS[TEST_TXT],
        passphrase="",
        account_index=0,
        script_type=P2WPKH,
        custom_derivation="",
    ):
        self.mnemonic = mnemonic
        self.policy_type = policy_type
        self.network = network
        self.passphrase = passphrase
        self.account_index = account_index
        if policy_type == TYPE_MULTISIG and script_type != P2WSH:
            script_type = P2WSH
        if policy_type == TYPE_MINISCRIPT and script_type not in (P2WSH, P2TR):
            script_type = P2WSH
        self.script_type = script_type
        self.root = bip32.HDKey.from_seed(
            bip39.mnemonic_to_seed(mnemonic, passphrase), version=network["xprv"]
        )
        self.fingerprint = self.root.child(0).fingerprint
        if not custom_derivation:
            self.derivation = self.get_default_derivation(
                self.policy_type, self.network, self.account_index, self.script_type
            )
            self.custom_derivation = False
        else:
            self.derivation = custom_derivation
            self.custom_derivation = True
        self.account = self.root.derive(self.derivation).to_public()

    def xpub(self, version=None):
        """Returns the xpub representation of the extended master public key"""
        return self.account.to_base58(version)

    def get_xpub(self, path):
        """Returns the xpub for the provided path"""
        return self.root.derive(path).to_public()

    def key_expression(self, version=None):
        """Returns the extended master public key (xpub/ypub/zpub) in key expression format
        per https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions,
        prefixed with fingerprint and derivation.
        """
        return "[%s%s]%s" % (
            self.fingerprint_hex_str(False),
            self.derivation[
                1:
            ],  # remove leading m, necessary for creating a descriptor
            self.account_pubkey_str(version),
        )

    def account_pubkey_str(self, version=None):
        """Returns the account extended public key (xpub/ypub/zpub)"""
        return self.account.to_base58(version)

    def fingerprint_hex_str(self, pretty=False):
        """Returns the master key fingerprint in hex format"""
        return Key.format_fingerprint(self.fingerprint, pretty)

    def derivation_str(self, pretty=False):
        """Returns the derivation path for the HD Wallet as string"""
        return Key.format_derivation(self.derivation, pretty)

    def sign(self, message_hash):
        """Signs a message with the extended master private key"""
        return self.root.derive(self.derivation).sign(message_hash)

    def sign_at(self, derivation, message_hash):
        """Signs a message at an adress derived from master key (code adapted from specterDIY)"""
        from embit import ec
        from embit.util import secp256k1

        prv = self.root.derive(derivation).key
        sig = secp256k1.ecdsa_sign_recoverable(
            message_hash, prv._secret  # pylint: disable=W0212
        )
        flag = sig[64]
        flag = bytes([27 + flag + 4])
        ec_signature = ec.Signature(sig[:64])
        ser = flag + secp256k1.ecdsa_signature_serialize_compact(
            ec_signature._sig  # pylint: disable=W0212
        )
        return ser

    @staticmethod
    def pick_final_word(entropy, words):
        """Returns a random final word with a valid checksum for the given list of
        either 11 or 23 words
        """
        if len(words) != 11 and len(words) != 23:
            raise ValueError("must provide 11 or 23 words")

        random.seed(int(time.ticks_ms() + entropy))
        return random.choice(Key.get_final_word_candidates(words))

    @staticmethod
    def get_default_derivation(policy_type, network, account=0, script_type=P2WPKH):
        """Return the Krux default derivation path for single-sig or multisig"""
        if policy_type == TYPE_SINGLESIG:
            return DER_SINGLE % (
                SINGLESIG_SCRIPT_PURPOSE[script_type],
                network["bip32"],
                account,
            )
        if policy_type == TYPE_MULTISIG:
            return DER_MULTI % (MULTISIG_SCRIPT_PURPOSE, network["bip32"], account)
        if policy_type == TYPE_MINISCRIPT:
            return DER_MINISCRIPT % (MINISCRIPT_PURPOSE, network["bip32"], account)
        raise ValueError("Invalid policy type")

    @staticmethod
    def format_derivation(derivation, pretty=False):
        """Helper method to display the derivation path formatted"""
        formatted_txt = DERIVATION_PATH_SYMBOL + THIN_SPACE + "%s" if pretty else "%s"
        return (formatted_txt % derivation).replace("h", HARDENED_STR_REPLACE)

    @staticmethod
    def format_fingerprint(fingerprint, pretty=False):
        """Helper method to display the fingerprint formatted"""
        formatted_txt = FINGERPRINT_SYMBOL + THIN_SPACE + "%s" if pretty else "%s"
        return formatted_txt % hexlify(fingerprint).decode("utf-8")

    @staticmethod
    def get_final_word_candidates(words):
        """Returns a list of valid final words"""
        if len(words) != 11 and len(words) != 23:
            raise ValueError("must provide 11 or 23 words")

        accu = 0
        for index in [WORDLIST.index(x) for x in words]:
            accu = (accu << 11) + index

        # in bits: final entropy, needed entropy, checksum
        len_target = (len(words) * 11 + 11) // 33 * 32
        len_needed = len_target - (len(words) * 11)
        len_cksum = len_target // 32

        candidates = []
        for i in range(2**len_needed):
            entropy = (accu << len_needed) + i
            ck_bytes = sha256(entropy.to_bytes(len_target // 8, "big")).digest()
            cksum = int.from_bytes(ck_bytes, "big") >> 256 - len_cksum
            last_word = WORDLIST[(i << len_cksum) + cksum]
            candidates.append(last_word)

        return candidates
