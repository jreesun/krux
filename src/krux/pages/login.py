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

import sys
from embit.networks import NETWORKS
from embit.wordlists.bip39 import WORDLIST
from . import (
    Page,
    Menu,
    DIGITS,
    MENU_CONTINUE,
    MENU_EXIT,
    ESC_KEY,
    LETTERS,
    choose_len_mnemonic,
)
from ..display import DEFAULT_PADDING, FONT_HEIGHT, BOTTOM_PROMPT_LINE
from ..krux_settings import Settings
from ..qr import FORMAT_UR
from ..key import (
    Key,
    P2WSH,
    P2TR,
    SCRIPT_LONG_NAMES,
    TYPE_SINGLESIG,
    TYPE_MULTISIG,
    TYPE_MINISCRIPT,
    POLICY_TYPE_IDS,
)
from ..krux_settings import t
from ..settings import NAME_SINGLE_SIG, NAME_MULTISIG, NAME_MINISCRIPT


DIGITS_HEX = "0123456789ABCDEF"
DIGITS_OCT = "01234567"


class Login(Page):
    """Represents the login page of the app"""

    # Used on boot.py when changing the locale on Settings
    SETTINGS_MENU_INDEX = 2

    def __init__(self, ctx):
        shtn_reboot_label = (
            t("Shutdown") if ctx.power_manager.has_battery() else t("Reboot")
        )
        super().__init__(
            ctx,
            Menu(
                ctx,
                [
                    (t("Load Mnemonic"), self.load_key),
                    (t("New Mnemonic"), self.new_key),
                    (t("Settings"), self.settings),
                    (t("Tools"), self.tools),
                    (t("About"), self.about),
                    (shtn_reboot_label, self.shutdown),
                ],
                back_label=None,
            ),
        )

    def load_key(self):
        """Handler for the 'load mnemonic' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("Via Camera"), self.load_key_from_camera),
                (t("Via Manual Input"), self.load_key_from_manual_input),
                (t("From Storage"), self.load_mnemonic_from_storage),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def load_key_from_camera(self):
        """Handler for the 'load mnemonic'>'via camera' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("QR Code"), self.load_key_from_qr_code),
                ("Tiny Seed", lambda: self.load_key_from_tiny_seed_image("Tiny Seed")),
                (
                    "OneKey KeyTag",
                    lambda: self.load_key_from_tiny_seed_image("OneKey KeyTag"),
                ),
                (
                    t("Binary Grid"),
                    lambda: self.load_key_from_tiny_seed_image("Binary Grid"),
                ),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def load_key_from_manual_input(self):
        """Handler for the 'load mnemonic'>'via manual input' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("Words"), self.load_key_from_text),
                (t("Word Numbers"), self.pre_load_key_from_digits),
                ("Tiny Seed (Bits)", self.load_key_from_tiny_seed),
                ("Stackbit 1248", self.load_key_from_1248),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def load_mnemonic_from_storage(self):
        """Handler to 'load mnemonic'>'from storage"""
        from .encryption_ui import LoadEncryptedMnemonic

        encrypted_mnemonics = LoadEncryptedMnemonic(self.ctx)
        words = encrypted_mnemonics.load_from_storage()
        if words == MENU_CONTINUE:
            return MENU_CONTINUE
        return self._load_key_from_words(words)

    def new_key(self):
        """Handler for the 'new mnemonic' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("Via Camera"), self.new_key_from_snapshot),
                (t("Via Words"), lambda: self.load_key_from_text(new=True)),
                (t("Via D6"), self.new_key_from_dice),
                (t("Via D20"), lambda: self.new_key_from_dice(True)),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def new_key_from_dice(self, d_20=False):
        """Handler for both 'new mnemonic'>'via D6/D20' menu items. Default is D6"""
        from .new_mnemonic.dice_rolls import DiceEntropy

        dice_entropy = DiceEntropy(self.ctx, d_20)
        captured_entropy = dice_entropy.new_key()
        if captured_entropy is not None:
            from embit.bip39 import mnemonic_from_bytes

            words = mnemonic_from_bytes(captured_entropy).split()
            return self._load_key_from_words(words, new=True)
        return MENU_CONTINUE

    def new_key_from_snapshot(self):
        """Use camera's entropy to create a new mnemonic"""
        extra_option = t("Double mnemonic")
        len_mnemonic = choose_len_mnemonic(self.ctx, extra_option)
        if not len_mnemonic:
            return MENU_CONTINUE

        self.ctx.display.draw_hcentered_text(
            t("Use camera's entropy to create a new mnemonic")
            + ". "
            + t("(Experimental)")
        )
        if self.prompt(t("Proceed?"), BOTTOM_PROMPT_LINE):
            from .capture_entropy import CameraEntropy

            camera_entropy = CameraEntropy(self.ctx)
            entropy_bytes = camera_entropy.capture()
            if entropy_bytes is not None:
                import binascii
                from embit.bip39 import mnemonic_from_bytes

                entropy_hash = binascii.hexlify(entropy_bytes).decode()
                self.ctx.display.clear()
                self.ctx.display.draw_centered_text(
                    t("SHA256 of snapshot:") + "\n\n%s" % entropy_hash
                )
                self.ctx.input.wait_for_button()

                self.ctx.display.clear()
                self.ctx.display.draw_centered_text(t("Processing.."))

                num_bytes = 16 if len_mnemonic == 12 else 32
                entropy_mnemonic = mnemonic_from_bytes(entropy_bytes[:num_bytes])

                # Double mnemonic check
                if len_mnemonic == 48:
                    from ..wallet import is_double_mnemonic

                    if not is_double_mnemonic(entropy_mnemonic):
                        from ..wdt import wdt
                        import time
                        from krux.bip39 import mnemonic_is_valid

                        pre_t = time.ticks_ms()
                        tries = 0

                        # create two 12w mnemonic with the provided entropy
                        first_12 = mnemonic_from_bytes(entropy_bytes[:16])
                        second_entropy_mnemonic_int = int.from_bytes(
                            entropy_bytes[16:32], "big"
                        )
                        double_mnemonic = False
                        while not double_mnemonic:
                            wdt.feed()
                            tries += 1
                            # increment the second mnemonic entropy
                            second_entropy_mnemonic_int += 1
                            second_12 = mnemonic_from_bytes(
                                second_entropy_mnemonic_int.to_bytes(16, "big")
                            )
                            entropy_mnemonic = first_12 + " " + second_12
                            double_mnemonic = mnemonic_is_valid(entropy_mnemonic)

                        print(
                            "Tries: %d" % tries,
                            "/ %d" % (time.ticks_ms() - pre_t),
                            "ms",
                        )

                return self._load_key_from_words(entropy_mnemonic.split(), new=True)
        return MENU_CONTINUE

    def _load_key_from_words(self, words, charset=LETTERS, new=False):
        mnemonic = " ".join(words)

        if charset != LETTERS:
            from .utils import Utils

            charset_type = {
                DIGITS: Utils.BASE_DEC,
                DIGITS_HEX: Utils.BASE_HEX,
                DIGITS_OCT: Utils.BASE_OCT,
            }
            suffix_dict = {
                DIGITS: Utils.BASE_DEC_SUFFIX,
                DIGITS_HEX: Utils.BASE_HEX_SUFFIX,
                DIGITS_OCT: Utils.BASE_OCT_SUFFIX,
            }
            numbers_str = Utils.get_mnemonic_numbers(mnemonic, charset_type[charset])
            self.display_mnemonic(numbers_str, suffix_dict[charset])
            if not self.prompt(t("Proceed?"), BOTTOM_PROMPT_LINE):
                return MENU_CONTINUE
            self.ctx.display.clear()

        # If the mnemonic is not hidden, show the mnemonic editor
        if not Settings().security.hide_mnemonic:
            from .mnemonic_editor import MnemonicEditor

            mnemonic = MnemonicEditor(self.ctx, mnemonic, new).edit()
        if mnemonic is None:
            return MENU_CONTINUE
        self.ctx.display.clear()

        passphrase = ""
        if not hasattr(Settings().wallet, "policy_type") and hasattr(
            Settings().wallet, "multisig"
        ):
            # Retro compatibility with old settings - Multisig (false or true)
            if Settings().wallet.multisig:
                Settings().wallet.policy_type = TYPE_MULTISIG
        else:
            # New settings - Policy type (single-sig, multisig, miniscript)
            policy_type = POLICY_TYPE_IDS.get(
                Settings().wallet.policy_type, TYPE_SINGLESIG
            )
        network = NETWORKS[Settings().wallet.network]
        account = 0
        if policy_type == TYPE_SINGLESIG:
            script_type = SCRIPT_LONG_NAMES.get(Settings().wallet.script_type)
        elif policy_type == TYPE_MINISCRIPT and Settings().wallet.script_type == P2TR:
            script_type = P2TR
        else:
            script_type = P2WSH
        derivation_path = ""
        from ..wallet import Wallet

        while True:
            key = Key(
                mnemonic,
                policy_type,
                network,
                passphrase,
                account,
                script_type,
                derivation_path,
            )
            if not derivation_path:
                derivation_path = key.derivation
            wallet_info = key.fingerprint_hex_str(True) + "\n"
            wallet_info += network["name"] + "\n"
            if policy_type == TYPE_SINGLESIG:
                wallet_info += NAME_SINGLE_SIG + "\n"
            elif policy_type == TYPE_MULTISIG:
                wallet_info += NAME_MULTISIG + "\n"
            elif policy_type == TYPE_MINISCRIPT:
                if script_type == P2TR:
                    wallet_info += "TR "
                wallet_info += NAME_MINISCRIPT + "\n"
            wallet_info += key.derivation_str(True) + "\n"
            wallet_info += (
                t("No Passphrase") if not passphrase else t("Passphrase") + ": *..*"
            )

            submenu = Menu(
                self.ctx,
                [
                    (t("Load Wallet"), lambda: None),
                    (t("Passphrase"), lambda: None),
                    (t("Customize"), lambda: None),
                ],
                offset=(
                    self.ctx.display.draw_hcentered_text(wallet_info, info_box=True)
                    * FONT_HEIGHT
                    + DEFAULT_PADDING
                ),
            )
            index, _ = submenu.run_loop()
            if index == len(submenu.menu) - 1:
                if self.prompt(t("Are you sure?"), self.ctx.display.height() // 2):
                    del key
                    return MENU_CONTINUE
            if index == 0:
                break
            if index == 1:
                from .wallet_settings import PassphraseEditor

                passphrase_editor = PassphraseEditor(self.ctx)
                temp_passphrase = passphrase_editor.load_passphrase_menu()
                if temp_passphrase is not None:
                    passphrase = temp_passphrase
            elif index == 2:
                from .wallet_settings import WalletSettings

                wallet_settings = WalletSettings(self.ctx)
                network, policy_type, script_type, account, derivation_path = (
                    wallet_settings.customize_wallet(key)
                )

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Loading.."))

        self.ctx.wallet = Wallet(key)
        return MENU_EXIT

    def _encrypted_qr_code(self, data):
        from ..encryption import EncryptedQRCode

        encrypted_qr = EncryptedQRCode()
        data_bytes = data.encode("latin-1") if isinstance(data, str) else data
        public_data = encrypted_qr.public_data(data_bytes)
        if public_data:
            self.ctx.display.clear()
            if self.prompt(
                public_data + "\n\n" + t("Decrypt?"), self.ctx.display.height() // 2
            ):
                from .encryption_ui import EncryptionKey
                from embit.bip39 import mnemonic_from_bytes

                key_capture = EncryptionKey(self.ctx)
                key = key_capture.encryption_key()
                if key in (None, "", ESC_KEY):
                    self.flash_error(t("Key was not provided"))
                    return MENU_CONTINUE
                self.ctx.display.clear()
                self.ctx.display.draw_centered_text(t("Processing.."))
                word_bytes = encrypted_qr.decrypt(key)
                if word_bytes is None:
                    self.flash_error(t("Failed to decrypt"))
                    return MENU_CONTINUE
                return mnemonic_from_bytes(word_bytes).split()
            return MENU_CONTINUE  # prompt NO
        return None

    def auto_complete_qr_words(self, words):
        """Ensure all words are in the wordlist, autocomplete if possible"""
        for i, word in enumerate(words):
            if word not in WORDLIST:
                word_lower = word.lower()
                # Try to autocomplete the word
                auto_complete = False
                for list_word in WORDLIST:
                    if list_word.startswith(word_lower):
                        words[i] = list_word
                        auto_complete = True
                        break
                if not auto_complete:
                    # Mark as invalid and clear the words list to indicate failure
                    return []
        return words

    def load_key_from_qr_code(self):
        """Handler for the 'via qr code' menu item"""
        from .qr_capture import QRCodeCapture

        qr_capture = QRCodeCapture(self.ctx)
        data, qr_format = qr_capture.qr_capture_loop()
        if data is None:
            self.flash_error(t("Failed to load"))
            return MENU_CONTINUE

        words = []
        if qr_format == FORMAT_UR:
            from urtypes.crypto.bip39 import BIP39

            words = BIP39.from_cbor(data.cbor).words
        else:
            try:
                data_str = data.decode() if not isinstance(data, str) else data
                words = data_str.split() if " " in data_str else []
                if len(words) in (12, 24):
                    words = self.auto_complete_qr_words(words)
                else:
                    words = []
            except:
                pass

            if not words:
                data_bytes = ""
                try:
                    data_bytes = (
                        data.encode("latin-1") if isinstance(data, str) else data
                    )
                except:
                    try:
                        data_bytes = (
                            data.encode("shift-jis") if isinstance(data, str) else data
                        )
                    except:
                        pass

                # CompactSeedQR format
                if len(data_bytes) in (16, 32):
                    from embit.bip39 import mnemonic_from_bytes

                    words = mnemonic_from_bytes(data_bytes).split()
                # SeedQR format
                elif len(data_bytes) in (48, 96):
                    words = [
                        WORDLIST[int(data_bytes[i : i + 4])]
                        for i in range(0, len(data_bytes), 4)
                    ]
            if not words:
                words = self._encrypted_qr_code(data)
                if words == MENU_CONTINUE:
                    return MENU_CONTINUE
        if not words or (len(words) != 12 and len(words) != 24):
            self.flash_error(t("Invalid mnemonic length"))
            return MENU_CONTINUE
        return self._load_key_from_words(words)

    def _load_key_from_keypad(
        self,
        title,
        charset,
        to_word,
        autocomplete_fn=None,
        possible_keys_fn=None,
        new=False,
        len_mnemonic=None,
    ):
        words = []
        self.ctx.display.draw_hcentered_text(title)
        if self.prompt(t("Proceed?"), BOTTOM_PROMPT_LINE):
            while len(words) < 24:
                if new:
                    if len(words) == len_mnemonic - 1:
                        self.ctx.display.clear()
                        self.ctx.display.draw_centered_text(
                            t(
                                "Leave blank if you'd like Krux to pick a valid final word"
                            )
                        )
                        self.ctx.input.wait_for_button()
                    elif len(words) == len_mnemonic:
                        break
                else:
                    if len(words) == 12:
                        self.ctx.display.clear()
                        if self.prompt(t("Done?"), self.ctx.display.height() // 2):
                            break

                word = ""
                word_num = ""
                while True:
                    word_num = ""

                    # if new and last word, lead input to a valid mnemonic
                    if new and len(words) == len_mnemonic - 1:
                        finalwords = Key.get_final_word_candidates(words)
                        word = self.capture_from_keypad(
                            t("Word %d") % (len(words) + 1),
                            [charset],
                            lambda x: autocomplete_fn(x, finalwords),
                            lambda x: possible_keys_fn(x, finalwords),
                        )
                    else:
                        word = self.capture_from_keypad(
                            t("Word %d") % (len(words) + 1),
                            [charset],
                            autocomplete_fn,
                            possible_keys_fn,
                        )

                    if word == ESC_KEY:
                        return MENU_CONTINUE

                    # If 'new' and the last 'word' is blank,
                    # pick a random final word that is a valid checksum
                    if new and word == "" and len(words) == len_mnemonic - 1:
                        break

                    if to_word is not None:
                        word_num = word
                        word = to_word(word)

                    if word not in WORDLIST:
                        word = ""

                    if word != "":
                        break

                if word not in WORDLIST and word == "":
                    word = Key.pick_final_word(self.ctx.input.entropy, words)

                self.ctx.display.clear()
                if word_num in (word, ""):
                    word_num = ""
                else:
                    word_num += ": "
                if self.prompt(
                    str(len(words) + 1) + ".\n\n" + word_num + word + "\n\n",
                    self.ctx.display.height() // 2,
                ):
                    words.append(word)

            return self._load_key_from_words(words, charset, new)

        return MENU_CONTINUE

    def load_key_from_text(self, new=False):
        """Handler for both 'new/load mnemonic'>[...]>'via words' menu items"""
        from .mnemonic_editor import MnemonicEditor

        if new:
            len_mnemonic = choose_len_mnemonic(self.ctx)
            if not len_mnemonic:
                return MENU_CONTINUE
            title = t("Enter %d BIP-39 words.") % len_mnemonic
        else:
            len_mnemonic = None
            title = t("Enter each word of your BIP-39 mnemonic.")

        mnemonic_editor = MnemonicEditor(self.ctx)
        mnemonic_editor.compute_search_ranges()

        return self._load_key_from_keypad(
            title,
            LETTERS,
            None,
            autocomplete_fn=mnemonic_editor.autocomplete,
            possible_keys_fn=mnemonic_editor.possible_letters,
            new=new,
            len_mnemonic=len_mnemonic,
        )

    def pre_load_key_from_digits(self):
        """Handler for the 'load mnemonic'>'via numbers' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("Decimal"), self.load_key_from_digits),
                (t("Hexadecimal"), self.load_key_from_hexadecimal),
                (t("Octal"), self.load_key_from_octal),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def load_key_from_octal(self):
        """Handler for the 'load mnemonic'>'via numbers'>'octal' submenu item"""
        title = t(
            "Enter each word of your BIP-39 mnemonic as a number in octal from 1 to 4000."
        )

        def autocomplete(prefix):
            # 256 in decimal is 400 in octal
            if len(prefix) == 4 or (len(prefix) == 3 and int(prefix, 8) > 256):
                return prefix
            return None

        def to_word(user_input):
            word_num = int(user_input, 8)
            if 0 < word_num <= 2048:
                return WORDLIST[word_num - 1]
            return ""

        def possible_letters(prefix):
            if prefix == "":
                return DIGITS_OCT.replace("0", "")
            if prefix == "400":
                return "0"
            return DIGITS_OCT

        return self._load_key_from_keypad(
            title,
            DIGITS_OCT,
            to_word,
            autocomplete_fn=autocomplete,
            possible_keys_fn=possible_letters,
        )

    def load_key_from_hexadecimal(self):
        """Handler for the 'load mnemonic'>'via numbers'>'hexadecimal' submenu item"""
        title = t(
            "Enter each word of your BIP-39 mnemonic as a number in hexadecimal from 1 to 800."
        )

        def autocomplete(prefix):
            # 128 decimal is 0x80
            if len(prefix) == 3 or (len(prefix) == 2 and int(prefix, 16) > 128):
                return prefix
            return None

        def to_word(user_input):
            word_num = int(user_input, 16)
            if 0 < word_num <= 2048:
                return WORDLIST[word_num - 1]
            return ""

        def possible_letters(prefix):
            if prefix == "":
                return DIGITS_HEX.replace("0", "")
            if prefix == "80":
                return "0"
            return DIGITS_HEX

        return self._load_key_from_keypad(
            title,
            DIGITS_HEX,
            to_word,
            autocomplete_fn=autocomplete,
            possible_keys_fn=possible_letters,
        )

    def load_key_from_digits(self):
        """Handler for the 'load mnemonic'>'via numbers'>'decimal' submenu item"""
        title = t("Enter each word of your BIP-39 mnemonic as a number from 1 to 2048.")

        def autocomplete(prefix):
            if len(prefix) == 4 or (len(prefix) == 3 and int(prefix) > 204):
                return prefix
            return None

        def to_word(user_input):
            word_num = int(user_input)
            if 0 < word_num <= 2048:
                return WORDLIST[word_num - 1]
            return ""

        def possible_letters(prefix):
            if prefix == "":
                return DIGITS.replace("0", "")
            if prefix == "204":
                return DIGITS.replace("9", "")
            return DIGITS

        return self._load_key_from_keypad(
            title,
            DIGITS,
            to_word,
            autocomplete_fn=autocomplete,
            possible_keys_fn=possible_letters,
        )

    def load_key_from_1248(self):
        """Menu handler to load key from Stackbit 1248 sheet metal storage method"""
        from .stack_1248 import Stackbit

        stackbit = Stackbit(self.ctx)
        words = stackbit.enter_1248()
        del stackbit
        if words is not None:
            return self._load_key_from_words(words)
        return MENU_CONTINUE

    def load_key_from_tiny_seed(self):
        """Menu handler to manually load key from Tiny Seed sheet metal storage method"""
        from .tiny_seed import TinySeed

        len_mnemonic = choose_len_mnemonic(self.ctx)
        if not len_mnemonic:
            return MENU_CONTINUE

        tiny_seed = TinySeed(self.ctx)
        words = tiny_seed.enter_tiny_seed(len_mnemonic == 24)
        del tiny_seed
        if words is not None:
            return self._load_key_from_words(words)
        return MENU_CONTINUE

    def load_key_from_tiny_seed_image(self, grid_type="Tiny Seed"):
        """Menu handler to scan key from Tiny Seed sheet metal storage method"""
        from .tiny_seed import TinyScanner

        len_mnemonic = choose_len_mnemonic(self.ctx)
        if not len_mnemonic:
            return MENU_CONTINUE

        intro = t("Paint punched dots black so they can be detected.") + " "
        intro += t("Use a black background surface.") + " "
        intro += t("Align camera and backup plate properly.")
        self.ctx.display.draw_hcentered_text(intro)
        if not self.prompt(t("Proceed?"), BOTTOM_PROMPT_LINE):
            return MENU_CONTINUE

        tiny_scanner = TinyScanner(self.ctx, grid_type)
        words = tiny_scanner.scanner(len_mnemonic == 24)
        del tiny_scanner
        if words is None:
            self.flash_error(t("Failed to load"))
            return MENU_CONTINUE
        return self._load_key_from_words(words)

    def tools(self):
        """Handler for the 'Tools' menu item"""
        from .tools import Tools

        while True:
            if Tools(self.ctx).run() == MENU_EXIT:
                break

        # Unimport tools
        sys.modules.pop("krux.pages.tools")
        del sys.modules["krux.pages"].tools

        return MENU_CONTINUE

    def settings(self):
        """Handler for the 'settings' menu item"""
        from .settings_page import SettingsPage

        settings_page = SettingsPage(self.ctx)
        return settings_page.settings()

    def about(self):
        """Handler for the 'about' menu item"""

        import board
        from ..metadata import VERSION

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(
            "Krux\n"
            + "selfcustody.github.io/krux\n\n"
            + t("Hardware")
            + "\n%s\n\n" % board.config["type"]
            + t("Version")
            + "\n%s" % VERSION
        )
        self.ctx.input.wait_for_button()
        return MENU_CONTINUE
