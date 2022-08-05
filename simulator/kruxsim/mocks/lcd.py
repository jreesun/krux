import sys
import os
from unittest import mock
import pygame as pg
import cv2
from kruxsim import events
from kruxsim.mocks.board import BOARD_CONFIG

COLOR_BLACK = (0, 0, 0)
COLOR_WHITE = (255, 255, 255)
COLOR_RED = (255, 0, 0)
COLOR_BLUE = (0, 0, 255)
COLOR_GREEN = (0, 255, 0)
COLOR_DARKGREY = (100, 100, 100)
COLOR_LIGHTGREY = (237, 237, 220)
COLOR_LIGHTBLACK = (10, 10, 20)

WIDTH = BOARD_CONFIG["lcd"]["width"]
HEIGHT = BOARD_CONFIG["lcd"]["height"]

screen = None
portrait = True


def clear():
    def run():
        if screen:
            screen.fill(COLOR_BLACK)

    pg.event.post(pg.event.Event(events.LCD_CLEAR_EVENT, {"f": run}))


def init(*args, **kwargs):
    pass


def register(addr, val):
    pass


def display(img):
    def run():
        frame = img.get_frame()
        frame = cv2.resize(
            frame,
            (screen.get_width(), screen.get_height()),
            interpolation=cv2.INTER_AREA,
        )
        frame = frame.swapaxes(0, 1)
        pg.surfarray.blit_array(screen, frame)

    pg.event.post(pg.event.Event(events.LCD_DISPLAY_EVENT, {"f": run}))


def rotation(r):
    global screen
    global portrait

    def run():
        global screen
        global portrait
        if not screen:
            if r == BOARD_CONFIG["krux"]["display"]["orientation"][0]:
                portrait = True
                screen = pg.Surface((HEIGHT, WIDTH)).convert()
            else:
                portrait = False
                screen = pg.Surface((WIDTH, HEIGHT)).convert()

    pg.event.post(pg.event.Event(events.LCD_ROTATION_EVENT, {"f": run}))


def width():
    return HEIGHT if portrait else WIDTH


def height():
    return WIDTH if portrait else HEIGHT


def draw_string(x, y, s, color, bgcolor=COLOR_BLACK):
    def run():
        from kruxsim import devices

        text, _ = devices.load_font(BOARD_CONFIG["type"]).render(s, color, bgcolor)
        screen.blit(
            text,
            (
                width() - text.get_width() - x
                if BOARD_CONFIG["krux"]["display"]["inverted_coordinates"]
                else x,
                y,
            ),
        )

    pg.event.post(pg.event.Event(events.LCD_DRAW_STRING_EVENT, {"f": run}))


def draw_qr_code(offset_y, code_str, max_width, dark_color, light_color):
    offset_y += 5
    def run():
        starting_size = 0
        while code_str[starting_size] != "\n":
            starting_size += 1
        scale = max_width // starting_size
        qr_width = starting_size * scale
        offset_x = (max_width - qr_width) // 2
        for og_y in range(starting_size):
            for i in range(scale):
                y = og_y * scale + i
                for og_x in range(starting_size):
                    for j in range(scale):
                        x = og_x * scale + j
                        og_yx_index = og_y * (starting_size + 1) + og_x
                        screen.set_at(
                            (offset_x + x, offset_y + y),
                            COLOR_BLACK
                            if code_str[og_yx_index] == "1"
                            else COLOR_WHITE,
                        )

    pg.event.post(pg.event.Event(events.LCD_DRAW_QR_CODE_EVENT, {"f": run}))


def fill_rectangle(x, y, w, h, color):
    def run():
        pg.draw.rect(
            screen,
            color,
            (
                width() - w - x
                if BOARD_CONFIG["krux"]["display"]["inverted_coordinates"]
                else x,
                y,
                w,
                h,
            ),
        )

    pg.event.post(pg.event.Event(events.LCD_FILL_RECTANGLE_EVENT, {"f": run}))


if "lcd" not in sys.modules:
    sys.modules["lcd"] = mock.MagicMock(
        init=init,
        register=register,
        display=display,
        clear=clear,
        rotation=rotation,
        width=width,
        height=height,
        draw_string=draw_string,
        draw_qr_code=draw_qr_code,
        fill_rectangle=fill_rectangle,
        BLACK=COLOR_BLACK,
        WHITE=COLOR_WHITE,
        RED=COLOR_RED,
        BLUE=COLOR_BLUE,
        GREEN=COLOR_GREEN,
        LIGHTGREY=COLOR_LIGHTGREY,
        DARKGREY=COLOR_DARKGREY,
        LIGHTBLACK=COLOR_LIGHTBLACK,
    )
