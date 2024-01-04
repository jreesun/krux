# The MIT License (MIT)

# Copyright (c) 2021-2023 Krux contributors

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
import os
import sys
import argparse
import threading
import pygame as pg
from kruxsim import devices, events

parser = argparse.ArgumentParser()
parser.add_argument(
    "--device",
    type=str,
    default=devices.PC,
    required=False,
)
parser.add_argument(
    "--sequence",
    type=str,
    default="",
    required=False,
)
parser.add_argument(
    "--printer",
    type=bool,
    default=False,
    required=False,
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "--sd",
    type=bool,
    default=False,
    required=False,
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "--exit-after-sequence",
    type=bool,
    default=True,
    required=False,
    action=argparse.BooleanOptionalAction,
)
parser.add_argument(
    "--screenshot-scale",
    type=bool,
    default=True,
    required=False,
    action=argparse.BooleanOptionalAction,
)

args = parser.parse_args()

# pylint: disable=no-member
pg.init()
pg.freetype.init()

from kruxsim.mocks import board

board.register_device(args.device)

if args.sd:
    # pylint: disable=unused-import
    from kruxsim.mocks import uopen

    # pylint: disable=unused-import
    from kruxsim.mocks import uos

# pylint: disable=unused-import
from kruxsim.mocks import uos_functions

# pylint: disable=unused-import
from kruxsim.mocks import usys

# pylint: disable=unused-import
from kruxsim.mocks import utime

# pylint: disable=unused-import
from kruxsim.mocks import fpioa_manager
from kruxsim.mocks import Maix

# pylint: disable=unused-import
from kruxsim.mocks import flash
from kruxsim.mocks import lcd
from kruxsim.mocks import machine

# pylint: disable=unused-import
from kruxsim.mocks import image
from kruxsim.mocks import pmu

if args.printer:
    machine.simulate_printer()

# pylint: disable=unused-import
from kruxsim.mocks import secp256k1

# pylint: disable=unused-import
from kruxsim.mocks import qrcode
from kruxsim.mocks import sensor
from kruxsim.mocks import ft6x36
from kruxsim.mocks import buttons

# pylint: disable=unused-import
from kruxsim.mocks import rotary
from kruxsim.sequence import SequenceExecutor

# pylint: disable=invalid-name
sequence_executor = None
if args.sequence:
    sequence_executor = SequenceExecutor(args.sequence)

buttons.register_sequence_executor(sequence_executor)
pmu.register_sequence_executor(sequence_executor)
sensor.register_sequence_executor(sequence_executor)
ft6x36.register_sequence_executor(sequence_executor)

##################################
# Handle absolute path for files #
##################################
dirname = os.path.dirname(os.path.abspath(__file__))


def run_krux():
    """
    Runs krux firmware from src/boot.py
    to simulate a properly krux device
    """
    boot_path = os.path.abspath(f"{dirname}/../src/boot.py")
    with open(boot_path, "r", encoding="utf-8") as boot_file:
        exec(boot_file.read())


# mock for SD
if args.sd:
    # pylint: disable=unused-import
    from kruxsim.mocks import sd_card

t = threading.Thread(target=run_krux)
t.daemon = True

screen = pg.display.set_mode(devices.WINDOW_SIZES[args.device], pg.SCALED, 32)
screen.fill(lcd.COLOR_BLACK)
buffer_image = screen.copy().convert()

pg.display.set_caption("Krux Simulator")

device_image = devices.load_image(args.device)

# Handle screenshots for docs scale
AMIGO_SIZE = (150, 252)
M5STICKV_SIZE = (125, 247)

device_screenshot_size = AMIGO_SIZE
if args.device == devices.M5STICKV:
    device_screenshot_size = M5STICKV_SIZE

###############################
# Handle screenshots alpha bg #
###############################
maixpy_amigo_mask_path = os.path.abspath(f"{dirname}/assets/maixpy_amigo_mask.png")
mask_img = pg.image.load(maixpy_amigo_mask_path).convert_alpha()


if args.device == devices.M5STICKV:
    maixpy_m5stickv_mask_path = os.path.abspath(
        f"{dirname}/assets/maixpy_m5stickv_mask.png"
    )
    mask_img = pg.image.load(maixpy_m5stickv_mask_path).convert_alpha()

# Handle screenshots filename suffix
from krux.krux_settings import Settings

# pylint: disable=invalid-name
screenshot_suffix = ""
if args.screenshot_scale:
    screenshot_suffix = "." + Settings().i18n.locale.split("-")[0]
    if args.device in (devices.AMIGO_IPS, devices.AMIGO_TFT):
        screenshot_suffix = "-150" + screenshot_suffix
    elif args.device == devices.M5STICKV:
        screenshot_suffix = "-125" + screenshot_suffix


if args.device == devices.PC:
    from kruxsim.mocks.board import BOARD_CONFIG

    BOARD_CONFIG["type"] = "amigo_type"

t.start()


def shutdown():
    """
    Shutdown device simulator
    """
    if t.is_alive():
        t.alive = False

    pg.quit()
    sys.exit()


try:
    clock = pg.time.Clock()
    while True:
        clock.tick(60)

        if sequence_executor:
            if not sequence_executor.commands and args.exit_after_sequence:
                shutdown()
            sequence_executor.execute()

        for event in pg.event.get():
            if event.type == pg.QUIT:
                shutdown()
            elif event.type >= pg.USEREVENT:
                if event.type == events.SCREENSHOT_EVENT:
                    sub = screen.subsurface(
                        devices.screenshot_rect(args.device)
                    ).convert_alpha()
                    sub.blit(mask_img, sub.get_rect(), None, pg.BLEND_RGBA_SUB)
                    if args.screenshot_scale:
                        sub = pg.transform.smoothscale(sub, device_screenshot_size)
                    pg.image.save(
                        sub,
                        os.path.join(
                            dirname,
                            "screenshots",
                            event.dict["filename"].replace(
                                ".png", screenshot_suffix + ".png"
                            ),
                        ),
                    )
                else:
                    event.dict["f"]()
            if event.type == pg.KEYDOWN:
                if event.key == pg.K_RETURN:
                    buttons.buttons_control.enter_event_flag = True
                if event.key == pg.K_DOWN:
                    buttons.buttons_control.page_event_flag = True
                if event.key == pg.K_UP:
                    buttons.buttons_control.page_prev_event_flag = True
            if event.type == pg.MOUSEBUTTONDOWN:
                ft6x36.touch_control.trigger_event()

        if lcd.screen:
            lcd_rect = lcd.screen.get_rect()
            lcd_rect.center = buffer_image.get_rect().center
            buffer_image.blit(lcd.screen, lcd_rect)

        if device_image:
            device_rect = device_image.get_rect()
            device_rect.center = buffer_image.get_rect().center
            buffer_image.blit(device_image, device_rect)

        scaled_image = buffer_image
        scaled_rect = scaled_image.get_rect()
        scaled_rect.center = buffer_image.get_rect().center
        if args.device == devices.M5STICKV:
            scaled_image = pg.transform.smoothscale(
                buffer_image, (screen.get_width() * 0.95, screen.get_height() * 0.85)
            )
            scaled_rect = scaled_image.get_rect()
            scaled_rect.center = buffer_image.get_rect().center
        screen.blit(scaled_image, scaled_rect)

        pg.display.flip()
except KeyboardInterrupt:
    shutdown()
