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
# pylint: disable=C0103

import sys
import time
import gc

sys.path.append("")
sys.path.append(".")

from krux.power import power_manager

MIN_SPLASH_WAIT_TIME = 1000


def draw_splash():
    """Display splash while loading modules"""
    from krux.display import display, SPLASH

    display.initialize_lcd()
    display.clear()
    display.draw_centered_text(SPLASH)


def check_for_updates():
    """Checks SD card, if a valid firmware is found asks if user wants to update the device"""
    import krux.firmware

    if krux.firmware.upgrade():
        power_manager.shutdown()

    # Unimport firware
    del krux.firmware
    del sys.modules["krux.firmware"]


def login(ctx_login):
    """Loads and run the Login page"""
    import krux.pages.login

    login_start_from = None
    while True:
        login_page = krux.pages.login.Login(ctx_login)
        if not login_page.run(login_start_from):
            break

        if ctx_login.wallet is not None:
            # Have a loaded wallet
            del login_page
            break

        # Login closed due to change of locale at Settings
        login_start_from = (
            krux.pages.login.Login.SETTINGS_MENU_INDEX
        )  # will start Login again from Settings index
        del login_page

    # Unimport login
    del krux.pages.login
    del sys.modules["krux.pages.login"]


def home(ctx_home):
    """Loads and run the Login page"""
    from krux.pages.home_pages.home import Home

    if ctx_home.is_logged_in():
        while True:
            if not Home(ctx_home).run():
                break


preimport_ticks = time.ticks_ms()
draw_splash()
check_for_updates()
gc.collect()

from krux.context import ctx
from krux.auto_shutdown import auto_shutdown

auto_shutdown.add_ctx(ctx)

ctx.power_manager = power_manager
postimport_ticks = time.ticks_ms()

# If importing happened too fast, sleep the difference so the logo
# will be shown
if preimport_ticks + MIN_SPLASH_WAIT_TIME > postimport_ticks:
    time.sleep_ms(preimport_ticks + MIN_SPLASH_WAIT_TIME - postimport_ticks)

login(ctx)
gc.collect()
home(ctx)

ctx.clear()
power_manager.shutdown()
