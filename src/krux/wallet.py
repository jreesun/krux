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

from embit.descriptor.descriptor import Descriptor
from embit.descriptor.arguments import Key
from embit.networks import NETWORKS
from embit.bip32 import HARDENED_INDEX
from .krux_settings import t
from .qr import FORMAT_BBQR
from .key import (
    P2PKH,
    P2SH_P2WPKH,
    P2WPKH,
    P2WSH,
    P2TR,
    SINGLESIG_SCRIPT_PURPOSE,
    MULTISIG_SCRIPT_PURPOSE,
    TYPE_SINGLESIG,
    TYPE_MULTISIG,
    TYPE_MINISCRIPT,
)

# Liana uses a example NUMS (Nothing-Up-My-Sleeve) key from BIP341 to create unspendable keys
# https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
# https://delvingbitcoin.org/t/unspendable-keys-in-descriptors/304/21
# H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
BIP_341_NUMS_EXAMPLE = (
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)


class AssumptionWarning(Exception):
    """An exception for assumptions that require user acceptance"""


class Wallet:
    """Represents the wallet that the current key belongs to"""

    def __init__(self, key):
        self.key = key
        self.wallet_data = None
        self.wallet_qr_format = None
        self.descriptor = None
        self.label = None
        self.policy = None
        self.persisted = False
        self._network = None
        if self.key and self.key.policy_type == TYPE_SINGLESIG:
            if self.key.script_type == P2PKH:
                self.descriptor = Descriptor.from_string(
                    "pkh(%s/<0;1>/*)" % self.key.key_expression()
                )
            elif self.key.script_type == P2SH_P2WPKH:
                self.descriptor = Descriptor.from_string(
                    "sh(wpkh(%s/<0;1>/*))" % self.key.key_expression()
                )
            elif self.key.script_type == P2WPKH:
                self.descriptor = Descriptor.from_string(
                    "wpkh(%s/<0;1>/*)" % self.key.key_expression()
                )

            elif self.key.script_type == P2TR:
                self.descriptor = Descriptor.from_string(
                    "tr(%s/<0;1>/*)" % self.key.key_expression()
                )
            self.label = t("Single-sig")
            self.policy = {"type": self.descriptor.scriptpubkey_type()}

    def which_network(self):
        """Returns network (NETWORKS.keys()) using current wallet key, else from descriptor"""
        if self._network is None:
            if self.key:
                self._network = [
                    k for k, v in NETWORKS.items() if v == self.key.network
                ][0]
            else:
                # use first key; restrict networks to "main" and "test", version to pubkeys
                version = self.descriptor.keys[0].key.version
                for em_network in ("main", "test"):
                    for em_vertype in ("xpub", "ypub", "zpub", "Ypub", "Zpub"):
                        if version == NETWORKS[em_network][em_vertype]:
                            self._network = em_network
                            break
        return self._network

    def is_multisig(self):
        """Returns a boolean indicating whether or not the wallet is multisig"""
        if self.key:
            return self.key.policy_type == TYPE_MULTISIG
        if self.descriptor:
            return self.descriptor.is_basic_multisig
        return False

    def is_miniscript(self):
        """Returns a boolean indicating whether or not the wallet is miniscript"""
        if self.key:
            return self.key.policy_type == TYPE_MINISCRIPT
        if self.descriptor:
            if self.descriptor.is_basic_multisig:
                return False
            return (
                self.descriptor.miniscript is not None
                or self.descriptor.taptree  #  taptree is "" when not present
            )
        return False

    def is_loaded(self):
        """Returns a boolean indicating whether or not this wallet has been loaded"""
        return self.wallet_data is not None

    def _validate_descriptor(self, descriptor, descriptor_xpubs):
        """Validates the descriptor against the current key and policy type"""

        if self.is_multisig():
            if not descriptor.is_basic_multisig:
                raise ValueError("not multisig")
            if self.key.xpub() not in descriptor_xpubs:
                raise ValueError("xpub not a multisig cosigner")
        elif self.is_miniscript():
            if self.key.script_type == P2WSH:
                if descriptor.miniscript is None or descriptor.is_basic_multisig:
                    raise ValueError("not P2WSH miniscript")
            elif self.key.script_type == P2TR:
                if not descriptor.taptree:
                    raise ValueError("not P2TR miniscript")
            if self.key.xpub() not in descriptor_xpubs:
                raise ValueError("xpub not a miniscript cosigner")
        else:
            if not descriptor.key:
                if len(descriptor.keys) > 1:
                    raise ValueError("not single-sig")
            if self.key.xpub() != descriptor_xpubs[0]:
                raise ValueError("xpub does not match")

    def load(self, wallet_data, qr_format, allow_assumption=None):
        """Loads the wallet from the given data"""
        descriptor, label = parse_wallet(wallet_data, allow_assumption)

        # convert descriptor keys to 'xpub' on same network -- for comparison only
        descriptor_xpubs = []
        for key in descriptor.keys:
            network, _ = version_to_network_versiontype(key.key.version)
            descriptor_xpubs.append(
                key.key.to_base58(version=NETWORKS[network]["xpub"])
            )

        if self.key:
            try:
                self._validate_descriptor(descriptor, descriptor_xpubs)
            except ValueError as e:
                raise ValueError("Invalid Descriptor: %s" % e)

        self.wallet_data = wallet_data
        self.wallet_qr_format = qr_format
        self.descriptor = to_unambiguous_descriptor(descriptor)
        self.label = label
        if self.descriptor.key and not self.descriptor.taptree:
            if not self.label:
                self.label = t("Single-sig")
            self.policy = {"type": self.descriptor.scriptpubkey_type()}
        elif self.descriptor.is_basic_multisig:
            m = int(str(self.descriptor.miniscript.args[0]))
            n = len(self.descriptor.keys)
            cosigners = [key.key.to_base58() for key in self.descriptor.keys]
            if self.descriptor.is_sorted:
                cosigners = sorted(cosigners)
            if not self.label:
                self.label = t("%d of %d multisig") % (m, n)
            self.policy = {
                "type": self.descriptor.scriptpubkey_type(),
                "m": m,
                "n": n,
                "cosigners": cosigners,
            }
        elif self.descriptor.miniscript is not None or self.descriptor.taptree:
            if self.descriptor.taptree:
                if not descriptor.keys[0].origin:
                    import hashlib
                    from embit.ec import PublicKey
                    from embit.bip32 import HDKey

                    # In case internal key is disabled, check if NUMS is known

                    # Hash all pubkeys, except internal, to compute deterministic chain code
                    hasher = hashlib.sha256()
                    for key in descriptor.keys[1:]:
                        hasher.update(key.sec())
                    det_chain_code = hasher.digest()

                    # Use BIP341 NUMS as public key
                    public_key = PublicKey.from_string(BIP_341_NUMS_EXAMPLE)

                    # Create provably unspendable deterministic key
                    version = self.descriptor.keys[0].key.version
                    provably_unspendable = HDKey(
                        public_key, det_chain_code, version=version
                    )

                    # Compare expected provably unspendable key with first descriptor key
                    if (
                        descriptor.keys[0].key.to_base58()
                        != provably_unspendable.to_base58()
                    ):
                        raise ValueError("Internal key not provably unspendable")

                taproot_txt = "TR "
                miniscript_type = P2TR
            else:
                taproot_txt = ""
                miniscript_type = P2WSH
            if not self.label:
                self.label = taproot_txt + t("Miniscript")
            cosigners = [key.key.to_base58() for key in self.descriptor.keys]
            cosigners = sorted(cosigners)
            self.policy = {
                "type": self.descriptor.scriptpubkey_type(),
                "cosigners": cosigners,
                "miniscript": miniscript_type,
            }

    def wallet_qr(self):
        """Returns the original wallet data and qr format for display back as a QR code"""
        if self.wallet_qr_format == FORMAT_BBQR:
            from .bbqr import encode_bbqr

            wallet_data = (
                self.wallet_data.encode("utf-8")
                if isinstance(self.wallet_data, str)
                else self.wallet_data
            )
            return encode_bbqr(wallet_data, file_type="U"), FORMAT_BBQR
        return (self.wallet_data, self.wallet_qr_format)

    def obtain_addresses(self, i=0, limit=None, branch_index=0):
        """Returns an iterator deriving addresses (default branch_index is receive)
        for the wallet up to the provided limit"""

        if self.descriptor is None:
            raise ValueError("No descriptor to derive addresses from")

        starting_index = i

        while limit is None or i < starting_index + limit:
            yield self.descriptor.derive(i, branch_index=branch_index).address(
                network=NETWORKS[self.which_network()]
            )
            i += 1


def to_unambiguous_descriptor(descriptor):
    """If child derivation info is missing to generate receive addresses,
    use the default scheme
    """
    from embit.descriptor.arguments import KeyHash, AllowedDerivation

    if descriptor.key:
        if descriptor.key.allowed_derivation is None:
            descriptor.key.allowed_derivation = AllowedDerivation.default()
    else:
        for i in range(len(descriptor.miniscript.args)):
            key = descriptor.miniscript.args[i]
            if isinstance(key, (Key, KeyHash)):
                if key.allowed_derivation is None:
                    key.allowed_derivation = AllowedDerivation.default()
    return descriptor


def parse_key_value_file(wallet_data):
    """Tries to parse data as a key-value file"""
    key_vals = []
    for word in wallet_data.split(":"):
        for key_val in word.split("\n"):
            key_val = key_val.strip()
            if key_val != "":
                key_vals.append(key_val)

    keys_present = [key in key_vals for key in ["Format", "Policy", "Derivation"]]
    if any(keys_present):
        if not all(keys_present):
            raise KeyError(
                '"Format", "Policy", and "Derivation" keys not found in INI file'
            )

        script = key_vals[key_vals.index("Format") + 1].lower()
        if script != P2WSH:
            raise ValueError("invalid script type: %s" % script)

        policy = key_vals[key_vals.index("Policy") + 1]
        m = int(policy[: policy.index("of")].strip())
        n = int(policy[policy.index("of") + 2 :].strip())

        keys = []
        for i in range(len(key_vals)):
            kv = key_vals[i]
            kv_prefix = kv[:4].lower()
            if kv_prefix[1:] == "pub" and kv_prefix[0] in ["x", "z", "t", "v"]:
                xpub = Key.from_string(kv).key.to_base58()
                fingerprint = key_vals[i - 1]
                keys.append((xpub, fingerprint))

        if len(keys) != n:
            raise ValueError("expected %d keys, found %d" % (n, len(keys)))

        derivation = key_vals[key_vals.index("Derivation") + 1]

        keys.sort()
        keys = ["[%s/%s]%s" % (key[1], derivation[2:], key[0]) for key in keys]
        if len(keys) > 1:
            descriptor = Descriptor.from_string(
                ("wsh(sortedmulti(%d," % m) + ",".join(keys) + "))"
            )
        else:
            # Single-sig - assuming Native Segwit
            descriptor = Descriptor.from_string("wpkh(%s/<0;1>/*)" % keys[0])
        label = (
            key_vals[key_vals.index("Name") + 1]
            if key_vals.index("Name") >= 0
            else None
        )
        return descriptor, label
    return None, None


def parse_wallet(wallet_data, allow_assumption=None):
    """Exhaustively tries to parse the wallet data from a known format, returning
    a descriptor and label if possible.

    If the descriptor cannot be derived, an exception is raised.
    """
    # pylint: disable=R0912

    # Check if wallet_data is a UR object without loading the UR module
    if wallet_data.__class__.__name__ == "UR":
        import urtypes

        # Try to parse as a Crypto-Output type
        try:
            output = urtypes.crypto.Output.from_cbor(wallet_data.cbor)
            return Descriptor.from_string(output.descriptor()), None
        except:
            pass

        # Try to parse as a Crypto-Account type
        try:
            account = urtypes.crypto.Account.from_cbor(
                wallet_data.cbor
            ).output_descriptors[0]
            return Descriptor.from_string(account.descriptor()), None
        except:
            pass

        # Treat the UR as a generic UR bytes object and extract the data for further processing
        wallet_data = urtypes.Bytes.from_cbor(wallet_data.cbor).data

    # Process as a string
    wallet_data = (
        wallet_data.decode() if not isinstance(wallet_data, str) else wallet_data
    )

    # Try to parse as JSON and look for a 'descriptor' key
    try:
        try:
            import ujson as json
        except ImportError:
            import json

        wallet_json = json.loads(wallet_data)
        if "descriptor" in wallet_json:
            descriptor = Descriptor.from_string(wallet_json["descriptor"])
            label = wallet_json["label"] if "label" in wallet_json else None
            return descriptor, label
        raise KeyError('"descriptor" key not found in JSON')
    except KeyError:
        raise ValueError("invalid wallet format")
    except:
        pass

    # Try to parse as a key-value file
    try:
        descriptor, label = parse_key_value_file(wallet_data)
        if descriptor and label:
            return descriptor, label
    except:
        raise ValueError("invalid wallet format")

    # Try to parse directly as a descriptor
    try:
        descriptor = Descriptor.from_string(wallet_data.strip())
        return descriptor, None
    except:
        # If that fails, try to parse as an xpub as a last resort
        pubkey = Key.from_string(wallet_data.strip())
        if pubkey.is_extended:
            network, versiontype = version_to_network_versiontype(pubkey.key.version)

            xpub = pubkey.key.to_base58()

            fmt = None
            if pubkey.origin is None:
                # assume derivation if possible
                derivation = xpub_data_to_derivation(
                    versiontype,
                    network,
                    pubkey.key.child_number,
                    pubkey.key.depth,
                    allow_assumption=allow_assumption,
                )
                if derivation:
                    fmt = derivation_to_script_wrapper(derivation)
            else:
                fmt = derivation_to_script_wrapper(pubkey.origin.derivation)
                fmt = fmt.format("[" + str(pubkey.origin) + "]{}")

            descriptor = Descriptor.from_string(fmt.format(xpub))
            return descriptor, None

    raise ValueError("invalid wallet format")


def parse_address(address_data):
    """Exhaustively tries to parse an address from a known format, returning
    the address if possible.

    If the address cannot be derived, an exception is raised.
    """
    from embit.script import Script, address_to_scriptpubkey

    addr = address_data
    if address_data.lower().startswith("bitcoin:"):
        addr_end = address_data.find("?")
        if addr_end == -1:
            addr_end = len(address_data)
        addr = address_data[8:addr_end]

    try:
        sc = address_to_scriptpubkey(addr)
        if not isinstance(sc, Script):
            raise ValueError("invalid address")
    except:
        raise ValueError("invalid address")

    return addr


def version_to_network_versiontype(hdkey_version):
    """returns embit.networks.NETWORKS[network][versiontype] keys
    based on HDKey's version bytes"""
    network, versiontype = None, None
    for netname, versiontypes in NETWORKS.items():
        if hdkey_version in versiontypes.values():
            network = netname
            versiontype = [k for k, v in versiontypes.items() if v == hdkey_version][0]
            break
    return network, versiontype


def xpub_data_to_derivation(versiontype, network, child, depth, allow_assumption=None):
    """returns assumed derivation list for supported slip32 bips
    based on embit.networks.NETWORKS keys for versiontype, network,
    child_number (used as account for single-sig) and depth.  Depth
    is used as weak verification, it must match the expected depth.
    Where unsafe assumptions could be made, AssumptionWarning is raised
    (with warning text and assumed derivation as first two params)
    unless called with allow_assumption=assumed_derivation.
    """

    derivation, network_node, assumption_text = None, None, None

    if network == "main":
        network_node = 0 + HARDENED_INDEX
    elif network in ("test", "regtest", "signet"):
        network_node = 1 + HARDENED_INDEX

    if network_node and child >= HARDENED_INDEX:
        if versiontype == "xpub" and depth == 3:
            derivation = [
                SINGLESIG_SCRIPT_PURPOSE[P2WPKH] + HARDENED_INDEX,
                network_node,
                child,
            ]
            if allow_assumption != derivation:
                assumption_text = t("Native Segwit - 84 would be assumed")
        elif versiontype == "ypub" and depth == 3:
            derivation = [
                SINGLESIG_SCRIPT_PURPOSE[P2SH_P2WPKH] + HARDENED_INDEX,
                network_node,
                child,
            ]
        elif versiontype == "zpub" and depth == 3:
            derivation = [
                SINGLESIG_SCRIPT_PURPOSE[P2WPKH] + HARDENED_INDEX,
                network_node,
                child,
            ]
        elif versiontype == "Ypub" and depth == 4 and child == 1 + HARDENED_INDEX:
            derivation = [
                MULTISIG_SCRIPT_PURPOSE + HARDENED_INDEX,
                network_node,
                0 + HARDENED_INDEX,
                child,
            ]
            if allow_assumption != derivation:
                assumption_text = t("Account #0 would be assumed")
        elif versiontype == "Zpub" and depth == 4 and child == 2 + HARDENED_INDEX:
            derivation = [
                MULTISIG_SCRIPT_PURPOSE + HARDENED_INDEX,
                network_node,
                0 + HARDENED_INDEX,
                child,
            ]
            if allow_assumption != derivation:
                assumption_text = t("Account #0 would be assumed")

    if assumption_text:
        raise AssumptionWarning(assumption_text, derivation)

    return derivation


def derivation_to_script_wrapper(derivation):
    """returns format_str for wrapping xpub into wallet descriptor,
    supporting single-sig only for now, based on
    embit.descriptor.arguments.KeyOrigin.derivation list"""
    format_str = None

    if len(derivation) == 3:
        purpose = derivation[0]
        network = derivation[1]
        account = derivation[2]

        if (
            network in (0 + HARDENED_INDEX, 1 + HARDENED_INDEX)
            and account >= 0 + HARDENED_INDEX
        ):
            if purpose == SINGLESIG_SCRIPT_PURPOSE[P2PKH] + HARDENED_INDEX:
                format_str = "pkh({})"
            elif purpose == SINGLESIG_SCRIPT_PURPOSE[P2SH_P2WPKH] + HARDENED_INDEX:
                format_str = "sh(wpkh({}))"
            elif purpose == SINGLESIG_SCRIPT_PURPOSE[P2WPKH] + HARDENED_INDEX:
                format_str = "wpkh({})"
            elif purpose == SINGLESIG_SCRIPT_PURPOSE[P2TR] + HARDENED_INDEX:
                format_str = "tr({})"

    return format_str


def is_double_mnemonic(mnemonic: str):
    """Check if the mnemonic is a double mnemonic (12+12+24)"""

    words = mnemonic.split(" ")
    if len(words) > 12:
        from krux.bip39 import mnemonic_is_valid

        if (
            mnemonic_is_valid(" ".join(words[:12]))
            and mnemonic_is_valid(" ".join(words[12:]))
            and mnemonic_is_valid(mnemonic)
        ):
            return True

    return False
