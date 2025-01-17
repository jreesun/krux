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

from .. import (
    Page,
    MENU_CONTINUE,
    LOAD_FROM_CAMERA,
    LOAD_FROM_SD,
)
from ...display import DEFAULT_PADDING, BOTTOM_PROMPT_LINE, FONT_HEIGHT, FONT_WIDTH
from ...krux_settings import t
from ...qr import FORMAT_NONE
from ...sd_card import DESCRIPTOR_FILE_EXTENSION, JSON_FILE_EXTENSION
from ...themes import theme
from ...key import FINGERPRINT_SYMBOL, DERIVATION_PATH_SYMBOL, P2TR


class WalletDescriptor(Page):
    """Page to load and export wallet descriptor"""

    def __init__(self, ctx):
        super().__init__(ctx, None)
        self.ctx = ctx

    def wallet(self):
        """Handler for the 'wallet descriptor' menu item"""
        title = t("Wallet output descriptor")
        self.ctx.display.clear()
        if self.ctx.wallet.key is None:
            # No key loaded, so it's being called from tools -> descriptor addresses
            text = t("Load a trusted wallet descriptor to view addresses?")
            text += "\n" + t("(watch-only)")
            if self.prompt(text, self.ctx.display.height() // 2):
                return self._load_wallet()
        elif not self.ctx.wallet.is_loaded():
            text = t("Wallet output descriptor not found.")
            self.ctx.display.draw_centered_text(text)
            if self.prompt(t("Load one?"), BOTTOM_PROMPT_LINE):
                return self._load_wallet()
        else:
            self.display_wallet(self.ctx.wallet)
            wallet_data, qr_format = self.ctx.wallet.wallet_qr()
            from ..utils import Utils

            utils = Utils(self.ctx)
            utils.print_standard_qr(wallet_data, qr_format, title)

            # Try to save the Wallet output descriptor on the SD card
            if self.has_sd_card() and not self.ctx.wallet.persisted:
                from ..file_operations import SaveFile

                save_page = SaveFile(self.ctx)
                self.ctx.wallet.persisted = save_page.save_file(
                    self.ctx.wallet.descriptor.to_string(),
                    self.ctx.wallet.label,
                    self.ctx.wallet.label,
                    title + ":",
                    DESCRIPTOR_FILE_EXTENSION,
                    save_as_binary=False,
                )

        return MENU_CONTINUE

    def _load_wallet(self):
        """Load a wallet output descriptor from the camera or SD card"""

        persisted = False
        load_method = self.load_method()
        if load_method == LOAD_FROM_CAMERA:
            from ..qr_capture import QRCodeCapture

            qr_capture = QRCodeCapture(self.ctx)
            wallet_data, qr_format = qr_capture.qr_capture_loop()
        elif load_method == LOAD_FROM_SD:
            # Try to read the wallet output descriptor from a file on the SD card
            qr_format = FORMAT_NONE
            try:
                from ..utils import Utils

                utils = Utils(self.ctx)
                _, wallet_data = utils.load_file(
                    (DESCRIPTOR_FILE_EXTENSION, JSON_FILE_EXTENSION), prompt=False
                )
                persisted = True
            except OSError:
                pass
        else:  # Cancel
            return MENU_CONTINUE

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Processing.."))
        if wallet_data is None:
            # Camera or SD card loading failed!
            self.flash_error(t("Failed to load"))
            return MENU_CONTINUE

        from ...wallet import Wallet, AssumptionWarning

        wallet = Wallet(self.ctx.wallet.key)
        wallet.persisted = persisted
        wallet_load_exception = None
        try:
            wallet.load(wallet_data, qr_format)
        except AssumptionWarning as e:
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(e.args[0], theme.error_color)
            if self.prompt(t("Accept assumption?"), BOTTOM_PROMPT_LINE):
                try:
                    wallet.load(wallet_data, qr_format, allow_assumption=e.args[1])
                except Exception as e_again:
                    wallet_load_exception = e_again
        except Exception as e:
            wallet_load_exception = e
        if wallet_load_exception:
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(
                t("Invalid wallet:") + "\n%s" % repr(wallet_load_exception),
                theme.error_color,
            )
            self.ctx.input.wait_for_button()

        if wallet.is_loaded():
            self.ctx.display.clear()
            self.display_loading_wallet(wallet)
            if self.prompt(t("Load?"), BOTTOM_PROMPT_LINE):
                self.ctx.wallet = wallet
                self.flash_text(t("Wallet output descriptor loaded!"))

        return MENU_CONTINUE

    def display_wallet(self, wallet):
        """Try to show the wallet output descriptor as a QRCode"""
        try:
            wallet_data, qr_format = wallet.wallet_qr()
            self.display_qr_codes(wallet_data, qr_format, title=wallet.label)
        except Exception as e:
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(
                t("Error:") + "\n%s" % repr(e), theme.error_color
            )
            self.ctx.input.wait_for_button()

    def display_loading_wallet(self, wallet):
        """Displays wallet descriptor attrbutes while loading"""

        offset_y = DEFAULT_PADDING
        self.ctx.display.draw_hcentered_text(wallet.label, offset_y)
        offset_y += (3 * FONT_HEIGHT) // 2
        our_key_indexes_chars = []
        unused_key_index = None
        for i, key in enumerate(wallet.descriptor.keys):
            label_color = theme.fg_color
            if wallet.is_multisig() or wallet.is_miniscript():
                label = chr(65 + i) + ": "
            else:
                label = " " * 3
            key_fingerprint = FINGERPRINT_SYMBOL + " "
            if key.origin:
                key_origin_str = str(key.origin)
                key_fingerprint += key_origin_str[:8]
            else:
                if (
                    i == 0
                    and wallet.is_miniscript()
                    and wallet.policy.get("type") == P2TR
                ):
                    key_fingerprint = t("TR internal key")
                    label_color = theme.disabled_color
                    unused_key_index = chr(65 + i)
                else:
                    key_fingerprint += t("unknown")
            #  Check if the key is the one loaded in the wallet
            if (
                self.ctx.wallet.key
                and len(wallet.descriptor.keys) > 1
                and key.fingerprint == self.ctx.wallet.key.fingerprint
            ):
                label_color = theme.highlight_color
                our_key_indexes_chars.append(chr(65 + i))
            self.ctx.display.draw_string(
                DEFAULT_PADDING,
                offset_y,
                label + key_fingerprint,
                label_color,
            )
            offset_y += FONT_HEIGHT
            if key.origin:
                key_derivation_str = DERIVATION_PATH_SYMBOL
                key_derivation_str += " m"
                key_derivation_str += key_origin_str[8:].replace("h", "'")
                self.ctx.display.draw_string(
                    DEFAULT_PADDING + 3 * FONT_WIDTH,
                    offset_y,
                    key_derivation_str,
                    label_color,
                )
            elif (
                i == 0 and wallet.is_miniscript() and wallet.policy.get("type") == P2TR
            ):
                self.ctx.display.draw_string(
                    DEFAULT_PADDING + 3 * FONT_WIDTH,
                    offset_y,
                    t("Provably unspendable"),
                    label_color,
                )
            offset_y += FONT_HEIGHT
            self.ctx.display.draw_hcentered_text(
                self.fit_to_line(key.key.to_base58(), " " * 3),
                offset_y,
                label_color,
            )
            offset_y += (FONT_HEIGHT * 3) // 2

            # Checks if there's another key and room for it
            if (
                i + 1 < len(wallet.descriptor.keys)
                and offset_y + (FONT_HEIGHT * 4) > self.ctx.display.height()
            ):
                # If there's no room for another key, create a new page
                self.ctx.input.wait_for_button()
                self.ctx.display.clear()
                offset_y = DEFAULT_PADDING
                self.ctx.display.draw_hcentered_text(wallet.label, offset_y)
                offset_y += (3 * FONT_HEIGHT) // 2

        # Display miniscrip policies
        if wallet.is_miniscript():
            from .miniscript_indenter import MiniScriptIndenter

            miniscript_policy = MiniScriptIndenter().indent(
                wallet.descriptor.full_policy
            )
            # miniscript_policy = self.ctx.display.to_lines(wallet.descriptor.full_policy)
            lines_left = (BOTTOM_PROMPT_LINE - offset_y) // FONT_HEIGHT
            if len(miniscript_policy) > lines_left:
                # If there's no room for the policy, create a new page
                self.ctx.input.wait_for_button()
                self.ctx.display.clear()
                offset_y = DEFAULT_PADDING
                self.ctx.display.draw_hcentered_text(wallet.label, offset_y)
                offset_y += (3 * FONT_HEIGHT) // 2

            for line in miniscript_policy:
                self.ctx.display.draw_string(
                    DEFAULT_PADDING,
                    offset_y,
                    line,
                )
                for i, char in enumerate(line):
                    if char == unused_key_index:
                        self.ctx.display.draw_string(
                            DEFAULT_PADDING + i * FONT_WIDTH,
                            offset_y,
                            char,
                            theme.disabled_color,
                        )
                    elif char in our_key_indexes_chars:
                        self.ctx.display.draw_string(
                            DEFAULT_PADDING + i * FONT_WIDTH,
                            offset_y,
                            char,
                            theme.highlight_color,
                        )
                offset_y += FONT_HEIGHT
                if offset_y > BOTTOM_PROMPT_LINE:
                    # If there's no room for another line, create a new page
                    self.ctx.display.draw_hcentered_text("...", offset_y)
                    self.ctx.input.wait_for_button()
                    self.ctx.display.clear()
                    offset_y = DEFAULT_PADDING
                    self.ctx.display.draw_hcentered_text(wallet.label, offset_y)
                    offset_y += FONT_HEIGHT
                    self.ctx.display.draw_hcentered_text("...", offset_y)
                    offset_y += FONT_HEIGHT
