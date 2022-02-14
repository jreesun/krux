# The MIT License (MIT)

# Copyright (c) 2021 Tom J. Sun

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
import gc
import lcd
from embit.networks import NETWORKS
from embit.script import Script, address_to_scriptpubkey
from ..settings import Settings
from ..display import DEFAULT_PADDING
from ..psbt import PSBTSigner
from ..qr import FORMAT_NONE, FORMAT_PMOFN
from ..input import BUTTON_ENTER
from ..wallet import Wallet
from . import Page, Menu, MENU_CONTINUE


#todo, object dict_view has no len()
class Home(Page):
    """Home is the main menu page of the app"""

    def __init__(self, ctx):
        Page.__init__(self, ctx, Menu(ctx, [
            (( 'Mnemonic' ), self.mnemonic),
            (( 'Public Key (xpub)' ), self.public_key),
            (( 'Wallet' ), self.wallet),
            (( 'Scan Address' ), self.scan_address),
            (( 'Sign PSBT' ), self.sign_psbt),
            (( 'Shutdown' ), self.shutdown)
        ]))

    def mnemonic(self):
        """Handler for the 'mnemonic' menu item"""
        self.display_mnemonic(self.ctx.wallet.key.mnemonic_words())
        self.ctx.input.wait_for_button()
        self.print_qr_prompt(self.ctx.wallet.key.mnemonic, FORMAT_NONE)
        return MENU_CONTINUE

    def public_key(self):
        """Handler for the 'xpub' menu item"""
        xpub = self.ctx.wallet.key.xpub_btc_core()
        subtitle = self.ctx.wallet.key.xpub()
        self.display_qr_codes(xpub, FORMAT_NONE, subtitle, DEFAULT_PADDING+1)
        self.print_qr_prompt(xpub, FORMAT_NONE)

        if self.ctx.wallet.is_multisig():
            zpub = self.ctx.wallet.key.p2wsh_zpub_btc_core()
            subtitle = self.ctx.wallet.key.p2wsh_zpub()
            self.display_qr_codes(zpub, FORMAT_NONE, subtitle, DEFAULT_PADDING+1)
            self.print_qr_prompt(zpub, FORMAT_NONE)
        else:
            zpub = self.ctx.wallet.key.p2wpkh_zpub_btc_core()
            subtitle = self.ctx.wallet.key.p2wpkh_zpub()
            self.display_qr_codes(zpub, FORMAT_NONE, subtitle, DEFAULT_PADDING+1)
            self.print_qr_prompt(zpub, FORMAT_NONE)
        return MENU_CONTINUE

    def wallet(self):
        """Handler for the 'wallet' menu item"""
        if not self.ctx.wallet.is_loaded():
            self.ctx.display.draw_centered_text(( 'Wallet not found.' ))
            self.ctx.display.draw_hcentered_text(( 'Load one?' ), offset_y=self.ctx.display.bottom_line)
            btn = self.ctx.input.wait_for_button()
            if btn == BUTTON_ENTER:
                return self._load_wallet()
        else:
            self.display_wallet(self.ctx.wallet)
            wallet_data, qr_format = self.ctx.wallet.wallet_qr()
            self.print_qr_prompt(wallet_data, qr_format)
        return MENU_CONTINUE

    def _load_wallet(self):
        wallet_data, qr_format = self.capture_qr_code()
        if wallet_data is None:
            self.ctx.display.flash_text(( 'Failed to load wallet' ), lcd.RED)
            return MENU_CONTINUE

        try:
            wallet = Wallet(self.ctx.wallet.key)
            wallet.load(wallet_data, qr_format)
            self.display_wallet(wallet, include_qr=False)
            self.ctx.display.draw_hcentered_text(( 'Load?' ), offset_y=self.ctx.display.bottom_line)
            btn = self.ctx.input.wait_for_button()
            if btn == BUTTON_ENTER:
                self.ctx.wallet = wallet
                self.ctx.log.debug('Wallet descriptor: %s' % self.ctx.wallet.descriptor.to_string())
                self.ctx.display.flash_text(( 'Loaded wallet' ))
        except Exception as e:
            self.ctx.log.exception('Exception occurred loading wallet')
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(( 'Invalid wallet:\n%s' ) % repr(e), lcd.RED)
            self.ctx.input.wait_for_button()
        return MENU_CONTINUE

    def scan_address(self):
        """Handler for the 'scan address' menu item"""
        data, qr_format = self.capture_qr_code()
        if data is None or qr_format != FORMAT_NONE:
            self.ctx.display.flash_text(( 'Failed to load address' ), lcd.RED)
            return MENU_CONTINUE

        addr = data
        if data.lower().startswith('bitcoin:'):
            addr_end = data.find('?')
            if addr_end == -1:
                addr_end = len(data)
            addr = data[8:addr_end]

        try:
            sc = address_to_scriptpubkey(addr)
            if sc is None or not isinstance(sc, Script):
                raise ValueError('invalid address')
        except:
            self.ctx.display.flash_text(( 'Invalid address' ), lcd.RED)
            return MENU_CONTINUE

        self.display_qr_codes(data, qr_format, title=addr)
        self.print_qr_prompt(data, qr_format)

        if self.ctx.wallet.is_loaded() or not self.ctx.wallet.is_multisig():
            self.ctx.display.clear()
            self.ctx.display.draw_centered_text(
                ( 'Check that address belongs to this wallet?' )
            )
            btn = self.ctx.input.wait_for_button()
            if btn != BUTTON_ENTER:
                return MENU_CONTINUE

            gc.collect()

            found = False
            i = 0
            while True:
                if (i + 1) % 100 == 0:
                    self.ctx.display.clear()
                    self.ctx.display.draw_centered_text(
                        ( 'Checked %d receive addresses with no matches.' ) % (i + 1)
                    )
                    self.ctx.display.draw_hcentered_text(( 'Try more?' ), offset_y=self.ctx.display.bottom_line)
                    btn = self.ctx.input.wait_for_button()
                    if btn != BUTTON_ENTER:
                        break

                self.ctx.display.clear()
                self.ctx.display.draw_centered_text(
                    ( 'Checking receive address %d for match..' ) % i
                )
                desc = self.ctx.wallet.descriptor
                child_addr = desc.derive(i, branch_index=0).address(
                    network=NETWORKS[Settings.network]
                )
                if addr == child_addr:
                    found = True
                    break
                i += 1

            gc.collect()

            self.ctx.display.clear()
            if found:
                self.ctx.display.draw_centered_text(
                    ( '%s\n\nis a valid receive address' ) % addr,
                    lcd.GREEN
                )
            else:
                self.ctx.display.draw_centered_text(
                    ( '%s\n\nwas NOT FOUND in the first %d receive addresses' ) % (addr, i + 1),
                    lcd.RED
                )
            self.ctx.input.wait_for_button()

        return MENU_CONTINUE

    def sign_psbt(self):
        """Handler for the 'sign psbt' menu item"""
        if not self.ctx.wallet.is_loaded():
            self.ctx.display.draw_centered_text(
                ( 'WARNING:\nWallet not loaded.\n\nSome checks cannot be performed.' ),
                lcd.WHITE
            )
            self.ctx.display.draw_hcentered_text(( 'Proceed?' ), offset_y=self.ctx.display.bottom_line)
            btn = self.ctx.input.wait_for_button()
            if btn != BUTTON_ENTER:
                return MENU_CONTINUE

        data, qr_format = self.capture_qr_code()
        qr_format = FORMAT_PMOFN if qr_format == FORMAT_NONE else qr_format
        if data is None:
            self.ctx.display.flash_text(( 'Failed to load PSBT' ), lcd.RED)
            return MENU_CONTINUE

        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(( 'Loading..' ))

        signer = PSBTSigner(self.ctx.wallet, data)
        self.ctx.log.debug('Received PSBT: %s' % signer.psbt)

        outputs = signer.outputs()
        self.ctx.display.clear()
        self.ctx.display.draw_hcentered_text('\n\n'.join(outputs))
        self.ctx.display.draw_hcentered_text(( 'Sign?' ), offset_y=self.ctx.display.bottom_line)

        btn = self.ctx.input.wait_for_button()
        if btn == BUTTON_ENTER:
            signed_psbt = signer.sign()
            self.ctx.log.debug('Signed PSBT: %s' % signer.psbt)
            signer = None
            gc.collect()
            self.display_qr_codes(signed_psbt, qr_format)
            self.print_qr_prompt(signed_psbt, qr_format)
        return MENU_CONTINUE

    def display_wallet(self, wallet, include_qr=True):
        """Displays a wallet, including its label and abbreviated xpubs.
           If include_qr is True, a QR code of the wallet will be shown
           which will contain the same data as was originally loaded, in
           the same QR format
        """
        about = wallet.label + '\n'
        if wallet.is_multisig():
            xpubs = []
            for i, xpub in enumerate(wallet.policy['cosigners']):
                xpubs.append(str(i+1) + '. ' + xpub[4:7] + '..' + xpub[len(xpub)-3:len(xpub)])
            about += '\n'.join(xpubs)
        else:
            xpub = wallet.key.xpub()
            about += xpub[4:7] + '..' + xpub[len(xpub)-3:len(xpub)]
        if include_qr:
            wallet_data, qr_format = wallet.wallet_qr()
            self.display_qr_codes(wallet_data, qr_format, title=about)
        else:
            self.ctx.display.draw_hcentered_text(about, offset_y=DEFAULT_PADDING)
