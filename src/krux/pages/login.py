# The MIT License (MIT)

# Copyright (c) 2021-2022 Krux contributors

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
# pylint: disable=C2801
import binascii
import hashlib
import lcd
from embit.networks import NETWORKS
from embit.wordlists.bip39 import WORDLIST
from embit import bip39
import urtypes
from ..metadata import VERSION
from ..settings import CategorySetting, NumberSetting, Settings
from ..input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV, BUTTON_TOUCH
from ..qr import FORMAT_UR
from ..key import Key, pick_final_word, to_mnemonic_words
from ..wallet import Wallet
from ..printers import create_printer
from ..i18n import t
from . import (
    Page,
    Menu,
    MENU_CONTINUE,
    MENU_EXIT,
    ESC_KEY,
    DEFAULT_PADDING,
)

SENTINEL_DIGITS = "11111"

D6_STATES = [str(i + 1) for i in range(6)]
D20_STATES = [str(i + 1) for i in range(20)]
BITS = "01"
DIGITS = "0123456789"
LETTERS = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUM_SPECIAL_1 = "0123456789 !#$%&'()*"
NUM_SPECIAL_2 = '+,-./:;<=>?@[\\]^_"{|}~'
NUMERALS = "0123456789."

D6_MIN_ROLLS = 50
D6_MAX_ROLLS = 100
D20_MIN_ROLLS = 30
D20_MAX_ROLLS = 60


class Login(Page):
    """Represents the login page of the app"""

    def __init__(self, ctx):
        Page.__init__(
            self,
            ctx,
            Menu(
                ctx,
                [
                    (t("Load Mnemonic"), self.load_key),
                    (t("New Mnemonic"), self.new_key),
                    (t("Settings"), self.settings),
                    (t("About"), self.about),
                    (t("Shutdown"), self.shutdown),
                ],
            ),
        )

    def load_key(self):
        """Handler for the 'load mnemonic' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("Via QR Code"), self.load_key_from_qr_code),
                (t("Via Text"), self.load_key_from_text),
                (t("Via Numbers"), self.load_key_from_digits),
                (t("Via Bits"), self.load_key_from_bits),
                (t("Back"), lambda: MENU_EXIT),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def new_key(self):
        """Handler for the 'new mnemonic' menu item"""
        submenu = Menu(
            self.ctx,
            [
                (t("Via D6"), self.new_key_from_d6),
                (t("Via D20"), self.new_key_from_d20),
                (t("Back"), lambda: MENU_EXIT),
            ],
        )
        index, status = submenu.run_loop()
        if index == len(submenu.menu) - 1:
            return MENU_CONTINUE
        return status

    def new_key_from_d6(self):
        """Handler for the 'via D6' menu item"""
        return self._new_key_from_die(D6_STATES, D6_MIN_ROLLS, D6_MAX_ROLLS)

    def new_key_from_d20(self):
        """Handler for the 'via D20' menu item"""
        return self._new_key_from_die(D20_STATES, D20_MIN_ROLLS, D20_MAX_ROLLS)

    def _new_key_from_die(self, roll_states, min_rolls, max_rolls):
        self.ctx.display.draw_hcentered_text(
            t(
                "Roll die %d or %d times to generate a 12- or 24-word mnemonic, respectively."
            )
            % (min_rolls, max_rolls)
        )
        if self.prompt(t("Proceed?"), self.ctx.display.bottom_prompt_line):
            rolls = []

            def delete_roll(buffer):
                nonlocal rolls
                if len(rolls) > 0:
                    rolls.pop()
                return buffer

            num_rolls = max_rolls
            while len(rolls) < max_rolls:
                if len(rolls) == min_rolls:
                    self.ctx.display.clear()
                    if self.prompt(t("Done?"), self.ctx.display.height() // 2):
                        num_rolls = min_rolls
                        break

                roll = ""
                while True:
                    dice_title = t("Rolls: %d\n") % len(rolls)
                    entropy = (
                        "".join(rolls) if len(roll_states) < 10 else "-".join(rolls)
                    )
                    if len(entropy) <= 10:
                        dice_title += entropy
                    else:
                        dice_title += "..." + entropy[-10:]
                    roll = self.capture_from_keypad(
                        dice_title,
                        [roll_states],
                        delete_key_fn=delete_roll,
                        go_on_change=True,
                    )
                    if roll == ESC_KEY:
                        return MENU_CONTINUE

                    if roll != "" and roll in roll_states:
                        break

                rolls.append(roll)

            entropy = "".join(rolls) if len(roll_states) < 10 else "-".join(rolls)

            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(t("Rolls:\n\n%s") % entropy)
            self.ctx.input.wait_for_button()

            entropy_bytes = entropy.encode()
            entropy_hash = binascii.hexlify(
                hashlib.sha256(entropy_bytes).digest()
            ).decode()
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(
                t("SHA256 of rolls:\n\n%s") % entropy_hash
            )
            self.ctx.input.wait_for_button()
            num_bytes = 16 if num_rolls == min_rolls else 32
            words = to_mnemonic_words(
                hashlib.sha256(entropy_bytes).digest()[:num_bytes]
            )
            return self._load_key_from_words(words)

        return MENU_CONTINUE

    def _load_key_from_words(self, words):
        mnemonic = " ".join(words)
        self.display_mnemonic(mnemonic)
        if not self.prompt(t("Continue?"), self.ctx.display.bottom_prompt_line):
            return MENU_CONTINUE
        self.ctx.display.clear()
        passphrase = ""
        if self.prompt(t("Add passphrase?"), self.ctx.display.height() // 2):
            passphrase = self.load_passphrase()
            if passphrase == ESC_KEY:
                return MENU_CONTINUE
        submenu = Menu(
            self.ctx,
            [
                (t("Single-key"), lambda: MENU_EXIT),
                (t("Multisig"), lambda: MENU_EXIT),
            ],
        )
        index, _ = submenu.run_loop()
        multisig = index == 1
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Loading.."))
        self.ctx.wallet = Wallet(
            Key(
                mnemonic,
                multisig,
                NETWORKS[Settings().bitcoin.network],
                passphrase,
            )
        )
        try:
            self.ctx.printer = create_printer()
        except:
            self.ctx.log.exception("Exception occurred connecting to printer")
        return MENU_EXIT

    def load_key_from_qr_code(self):
        """Handler for the 'via qr code' menu item"""
        data, qr_format = self.capture_qr_code()
        if data is None:
            self.ctx.display.flash_text(t("Failed to load mnemonic"), lcd.RED)
            return MENU_CONTINUE

        words = []
        if qr_format == FORMAT_UR:
            words = urtypes.crypto.BIP39.from_cbor(data.cbor).words
        else:
            try:
                data_str = data.decode() if not isinstance(data, str) else data
                if " " in data_str and len(data_str.split()) in (12, 24):
                    words = data_str.split()
            except:
                pass

            if not words:
                try:
                    data_bytes = data.encode() if isinstance(data, str) else data

                    # CompactSeedQR format
                    if len(data_bytes) in (16, 32):
                        words = bip39.mnemonic_from_bytes(data_bytes).split()
                    # SeedQR format
                    elif len(data_bytes) in (48, 96):
                        words = [
                            WORDLIST[int(data_bytes[i : i + 4])]
                            for i in range(0, len(data_bytes), 4)
                        ]
                except:
                    pass

        if not words or (len(words) != 12 and len(words) != 24):
            self.ctx.display.flash_text(t("Invalid mnemonic length"), lcd.RED)
            return MENU_CONTINUE
        return self._load_key_from_words(words)

    def _load_key_from_keypad(
        self,
        title,
        charset,
        to_word,
        test_phrase_sentinel=None,
        autocomplete_fn=None,
        possible_keys_fn=None,
    ):
        words = []
        self.ctx.display.draw_hcentered_text(title)
        if self.prompt(t("Proceed?"), self.ctx.display.bottom_prompt_line):
            for i in range(24):
                if i == 12:
                    self.ctx.display.clear()
                    if self.prompt(t("Done?"), self.ctx.display.height() // 2):
                        break

                word = ""
                while True:
                    word = self.capture_from_keypad(
                        t("Word %d") % (i + 1),
                        [charset],
                        autocomplete_fn,
                        possible_keys_fn,
                    )
                    if word == ESC_KEY:
                        return MENU_CONTINUE
                    # If the last 'word' is blank,
                    # pick a random final word that is a valid checksum
                    if (i in (11, 23)) and word == "":
                        break
                    # If the first 'word' is the test phrase sentinel,
                    # we're testing and just want the test words
                    if (
                        i == 0
                        and test_phrase_sentinel is not None
                        and word == test_phrase_sentinel
                    ):
                        break
                    if word != "":
                        word = to_word(word)
                    if word != "":
                        break

                if word not in WORDLIST:
                    if word == test_phrase_sentinel:
                        words = [
                            WORDLIST[0] if n + 1 < 12 else WORDLIST[1879]
                            for n in range(12)
                        ]
                        break

                    if word == "":
                        word = pick_final_word(self.ctx, words)

                self.ctx.display.clear()
                self.ctx.display.draw_centered_text(word)
                self.ctx.input.wait_for_button()

                words.append(word)

            return self._load_key_from_words(words)

        return MENU_CONTINUE

    def load_key_from_text(self):
        """Handler for the 'via text' menu item"""
        title = t("Enter each word of your BIP-39 mnemonic.")

        # Precompute start and stop indexes for each letter in the wordlist
        # to reduce the search space for autocomplete, possible_letters, etc.
        # This is much cheaper (memory-wise) than a trie.
        search_ranges = {}
        i = 0
        while i < len(WORDLIST):
            start_word = WORDLIST[i]
            start_letter = start_word[0]
            j = i + 1
            while j < len(WORDLIST):
                end_word = WORDLIST[j]
                end_letter = end_word[0]
                if end_letter != start_letter:
                    search_ranges[start_letter] = (i, j)
                    i = j - 1
                    break
                j += 1
            if start_letter not in search_ranges:
                search_ranges[start_letter] = (i, j)
            i += 1

        def autocomplete(prefix):
            if len(prefix) > 0:
                letter = prefix[0]
                if letter not in search_ranges:
                    return None
                start, stop = search_ranges[letter]
                matching_words = list(
                    filter(
                        lambda word: word.startswith(prefix),
                        WORDLIST[start:stop],
                    )
                )
                if len(matching_words) == 1:
                    return matching_words[0]
            return None

        def to_word(user_input):
            if len(user_input) > 0:
                letter = user_input[0]
                if letter not in search_ranges:
                    return ""
                start, stop = search_ranges[letter]
                if user_input in WORDLIST[start:stop]:
                    return user_input
            return ""

        def possible_letters(prefix):
            if len(prefix) == 0:
                return LETTERS
            letter = prefix[0]
            if letter not in search_ranges:
                return ""
            start, stop = search_ranges[letter]
            return {
                word[len(prefix)]
                for word in WORDLIST[start:stop]
                if word.startswith(prefix) and len(word) > len(prefix)
            }

        return self._load_key_from_keypad(
            title, LETTERS, to_word, None, autocomplete, possible_letters
        )

    def load_key_from_digits(self):
        """Handler for the 'via numbers' menu item"""
        title = t("Enter each word of your BIP-39 mnemonic as a number from 1 to 2048.")

        def to_word(user_input):
            word_num = int(user_input)
            if 0 < word_num <= 2048:
                return WORDLIST[word_num - 1]
            return ""

        return self._load_key_from_keypad(title, DIGITS, to_word, SENTINEL_DIGITS)

    def load_key_from_bits(self):
        """Handler for the 'via bits' menu item"""
        title = t(
            "Enter each word of your BIP-39 mnemonic as a series of binary digits."
        )

        def to_word(user_input):
            word_index = int("0b" + user_input, 0)
            if 0 <= word_index < 2048:
                return WORDLIST[word_index]
            return ""

        return self._load_key_from_keypad(title, BITS, to_word)

    def load_passphrase(self):
        """Loads and returns a passphrase from keypad"""
        return self.capture_from_keypad(
            t("Passphrase"), [LETTERS, UPPERCASE_LETTERS, NUM_SPECIAL_1, NUM_SPECIAL_2]
        )

    def _draw_settings_pad(self):
        """Draws buttons to change settings with touch"""
        if self.ctx.input.touch is not None:
            self.ctx.input.touch.clear_regions()
            offset_y = self.ctx.display.height() * 2 // 3
            self.ctx.input.touch.add_y_delimiter(offset_y)
            self.ctx.input.touch.add_y_delimiter(
                offset_y + self.ctx.display.font_height * 3
            )
            button_width = (self.ctx.display.width() - 2 * DEFAULT_PADDING) // 3
            for i in range(4):
                self.ctx.input.touch.add_x_delimiter(DEFAULT_PADDING + button_width * i)
            offset_y += self.ctx.display.font_height
            keys = ["<", t("Go"), ">"]
            for i, x in enumerate(self.ctx.input.touch.x_regions[:-1]):
                self.ctx.display.outline(
                    x,
                    self.ctx.input.touch.y_regions[0],
                    button_width - 1,
                    self.ctx.display.font_height * 3,
                    lcd.DARKGREY,
                )
                offset_x = x
                offset_x += (
                    button_width - len(keys[i]) * self.ctx.display.font_width
                ) // 2
                self.ctx.display.draw_string(offset_x, offset_y, keys[i], lcd.WHITE)

    def _touch_to_physical(self, index):
        """Mimics touch presses into physical button presses"""
        if index == 0:
            return BUTTON_PAGE_PREV
        if index == 1:
            return BUTTON_ENTER
        return BUTTON_PAGE

    def settings(self):
        """Handler for the 'settings' menu item"""
        return self.namespace(Settings())()

    def namespace(self, settings_namespace):
        """Handler for navigating a particular settings namespace"""

        def handler():
            setting_list = settings_namespace.setting_list()
            namespace_list = settings_namespace.namespace_list()
            items = [
                (
                    settings_namespace.label(setting.attr),
                    self.setting(settings_namespace, setting),
                )
                for setting in setting_list
            ]
            items.extend(
                [
                    (
                        settings_namespace.label(ns.namespace.split(".")[-1]),
                        self.namespace(ns),
                    )
                    for ns in namespace_list
                ]
            )

            # If there is only one item in the namespace, don't show a submenu
            # and instead jump straight to the item's menu
            if len(items) == 1:
                return items[0][1]()

            items.append((t("Back"), lambda: MENU_EXIT))

            submenu = Menu(self.ctx, items)
            index, status = submenu.run_loop()
            if index == len(submenu.menu) - 1:
                return MENU_CONTINUE
            return status

        return handler

    def setting(self, settings_namespace, setting):
        """Handler for viewing and editing a particular setting"""

        def handler():
            if isinstance(setting, CategorySetting):
                return self.category_setting(settings_namespace, setting)
            if isinstance(setting, NumberSetting):
                return self.number_setting(settings_namespace, setting)
            return MENU_CONTINUE

        return handler

    def category_setting(self, settings_namespace, setting):
        """Handler for viewing and editing a CategorySetting"""
        categories = setting.categories

        starting_category = setting.__get__(settings_namespace)
        while True:
            current_category = setting.__get__(settings_namespace)

            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(
                settings_namespace.label(setting.attr) + "\n" + str(current_category)
            )
            self._draw_settings_pad()
            btn = self.ctx.input.wait_for_button()
            if btn == BUTTON_TOUCH:
                btn = self._touch_to_physical(self.ctx.input.touch.current_index())
            if btn == BUTTON_ENTER:
                break
            for i, category in enumerate(categories):
                if current_category == category:
                    if btn == BUTTON_PAGE:
                        new_category = categories[(i + 1) % len(categories)]
                    elif btn == BUTTON_PAGE_PREV:
                        new_category = categories[(i - 1) % len(categories)]
                    setting.__set__(settings_namespace, new_category)
                    break
        if (
            setting.attr == "locale"
            and setting.__get__(settings_namespace) != starting_category
        ):
            return MENU_EXIT
        return MENU_CONTINUE

    def number_setting(self, settings_namespace, setting):
        """Handler for viewing and editing a NumberSetting"""

        starting_value = setting.numtype(setting.__get__(settings_namespace))
        new_value = self.capture_from_keypad(
            settings_namespace.label(setting.attr),
            [NUMERALS],
            starting_buffer=str(starting_value),
        )
        if new_value in (ESC_KEY, ""):
            return MENU_CONTINUE

        new_value = setting.numtype(new_value)
        if setting.value_range[0] <= new_value <= setting.value_range[1]:
            setting.__set__(settings_namespace, new_value)

        return MENU_CONTINUE

    def about(self):
        """Handler for the 'about' menu item"""
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Krux\n\n\nVersion\n%s") % VERSION)
        self.ctx.input.wait_for_button()
        return MENU_CONTINUE
