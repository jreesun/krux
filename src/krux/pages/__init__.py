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
import math
import time
import lcd
import board
from ur.ur import UR
from ..input import (
    BUTTON_ENTER,
    BUTTON_PAGE,
    BUTTON_PAGE_PREV,
    BUTTON_TOUCH,
    SWIPE_RIGHT,
    SWIPE_LEFT,
)
from ..display import DEFAULT_PADDING
from ..qr import to_qr_codes
from ..i18n import t

MENU_CONTINUE = 0
MENU_EXIT = 1
MENU_SHUTDOWN = 2

ESC_KEY = 1
FIXED_KEYS = 3  # 'More' key only appears when there are multiple keysets


class Page:
    """Represents a page in the app, with helper methods for common display and
    input operations.

    Must be subclassed.
    """

    def __init__(self, ctx, menu):
        self.ctx = ctx
        self.menu = menu
        self._time_frame = 0
        # context has its own keypad mapping in case touch is not used
        self.y_keypad_map = []
        self.x_keypad_map = []

    def wait_for_proceed(self, block=True):
        """Wrap acknowledgements which can be answared with multiple buttons"""
        return self.ctx.input.wait_for_button(block) in (BUTTON_ENTER, BUTTON_TOUCH)

    def esc_prompt(self):
        """Prompts user for leaving"""
        self.ctx.display.clear()
        answer = self.prompt(t("Are you sure?"), self.ctx.display.height() // 2)
        if self.ctx.input.has_touch:
            self.ctx.input.touch.clear_regions()
        if answer:
            return ESC_KEY
        return None

    def capture_from_keypad(
        self,
        title,
        keysets,
        autocomplete_fn=None,
        possible_keys_fn=None,
        delete_key_fn=None,
        go_on_change=False,
    ):
        """Displays a key pad and captures a series of keys until the user returns.
        Returns a string.
        """
        buffer = ""
        pad = Keypad(self.ctx, keysets)
        while True:
            self.ctx.display.clear()
            offset_y = DEFAULT_PADDING
            if (
                len(buffer) + 1
            ) * self.ctx.display.font_width < self.ctx.display.width():
                self.ctx.display.draw_hcentered_text(title, offset_y)
                offset_y += self.ctx.display.font_height * 3 // 2
            self.ctx.display.draw_hcentered_text(buffer, offset_y)
            offset_y = pad.keypad_offset()
            possible_keys = pad.keys
            if possible_keys_fn is not None:
                possible_keys = possible_keys_fn(buffer)
                pad.get_valid_index(possible_keys)
            pad.draw_keys(possible_keys)
            btn = self.ctx.input.wait_for_button()
            if self.ctx.input.has_touch:
                if btn == BUTTON_TOUCH:
                    btn = pad.touch_to_physical(possible_keys)
            if btn == BUTTON_ENTER:
                pad.moving_forward = True
                changed = False
                if pad.cur_key_index == pad.del_index:
                    if delete_key_fn is not None:
                        buffer = delete_key_fn(buffer)
                    else:
                        buffer = buffer[: len(buffer) - 1]
                    changed = True
                elif pad.cur_key_index == pad.esc_index:
                    if self.esc_prompt() == ESC_KEY:
                        return ESC_KEY
                    # remap keypad touch array
                    pad.map_keys_array(pad.width, pad.height)
                elif pad.cur_key_index == pad.go_index:
                    break
                elif pad.cur_key_index == pad.more_index:
                    pad.next_keyset()
                else:
                    buffer += pad.keys[pad.cur_key_index]
                    changed = True

                    # Don't autocomplete if deleting
                    if autocomplete_fn is not None:
                        new_buffer = autocomplete_fn(buffer)
                        if new_buffer is not None:
                            buffer = new_buffer
                            pad.cur_key_index = pad.go_index

                if changed and go_on_change:
                    break

            elif btn == BUTTON_PAGE:
                pad.next_key()

            elif btn == BUTTON_PAGE_PREV:
                pad.previous_key()

            elif btn == SWIPE_LEFT:
                pad.next_keyset()

            elif btn == SWIPE_RIGHT:
                pad.previous_keyset()

        if self.ctx.input.has_touch:
            self.ctx.input.touch.clear_regions()
        return buffer

    def capture_qr_code(self):
        """Captures a singular or animated series of QR codes and displays progress to the user.
        Returns the contents of the QR code(s).
        """
        self._time_frame = time.ticks_ms()

        def callback(part_total, num_parts_captured, new_part):
            # Turn on the light as long as the enter button is held down
            if time.ticks_ms() > self._time_frame + 1000:
                if self.ctx.light:
                    if not self.ctx.input.enter_value():
                        self.ctx.light.turn_on()
                    else:
                        self.ctx.light.turn_off()
                # If board don't have light, ENTER stops the capture
                elif not self.ctx.input.enter_value():
                    return True

                # Exit the capture loop if a button is pressed
                if (
                    not self.ctx.input.page_value()
                    or not self.ctx.input.page_prev_value()
                    or not self.ctx.input.touch_value()
                ):
                    return True

            # Indicate progress to the user that a new part was captured
            if new_part:
                self.ctx.display.to_portrait()
                self.ctx.display.draw_centered_text(
                    "%.0f%%" % (100 * float(num_parts_captured) / float(part_total))
                )
                time.sleep_ms(100)
                self.ctx.display.to_landscape()

            return False

        self.ctx.display.to_landscape()
        code = None
        qr_format = None
        try:
            code, qr_format = self.ctx.camera.capture_qr_code_loop(callback)
        except:
            self.ctx.log.exception("Exception occurred capturing QR code")
        if self.ctx.light:
            self.ctx.light.turn_off()
        self.ctx.display.to_portrait()
        if code is not None:
            data = code.cbor if isinstance(code, UR) else code
            self.ctx.log.debug(
                'Captured QR Code in format "%d": %s' % (qr_format, data)
            )
        return (code, qr_format)

    def display_qr_codes(self, data, qr_format, title=None):
        """Displays a QR code or an animated series of QR codes to the user, encoding them
        in the specified format
        """
        done = False
        i = 0
        code_generator = to_qr_codes(data, self.ctx.display.qr_data_width(), qr_format)
        while not done:
            self.ctx.display.clear()

            code = None
            num_parts = 0
            try:
                code, num_parts = next(code_generator)
            except:
                code_generator = to_qr_codes(
                    data, self.ctx.display.qr_data_width(), qr_format
                )
                code, num_parts = next(code_generator)
            self.ctx.display.draw_qr_code(5, code)
            subtitle = (
                t("Part\n%d / %d") % (i + 1, num_parts) if title is None else title
            )
            offset_y = self.ctx.display.qr_offset()
            if title is not None:
                offset_y += self.ctx.display.font_height
            self.ctx.display.draw_hcentered_text(subtitle, offset_y, color=lcd.WHITE)
            i = (i + 1) % num_parts
            if self.wait_for_proceed(block=num_parts == 1):
                done = True
            # interval done in input.py using timers

    def display_mnemonic(self, mnemonic):
        """Displays the 12 or 24-word list of words to the user"""
        words = mnemonic.split(" ")
        word_list = [
            str(i + 1) + "." + ("  " if i + 1 < 10 else " ") + word
            for i, word in enumerate(words)
        ]
        self.ctx.display.clear()
        self.ctx.display.draw_hcentered_text(t("BIP39 Mnemonic"))
        for i, word in enumerate(word_list[:12]):
            offset_x = DEFAULT_PADDING
            offset_y = 40 + (i * self.ctx.display.font_height)
            self.ctx.display.draw_string(offset_x, offset_y, word, lcd.WHITE, lcd.BLACK)
        if len(word_list) > 12:
            if board.config["type"] == "m5stickv":
                self.ctx.input.wait_for_button()
                self.ctx.display.clear()
                self.ctx.display.draw_hcentered_text(t("BIP39 Mnemonic"))
                for i, word in enumerate(word_list[12:]):
                    offset_x = DEFAULT_PADDING
                    offset_y = 40 + (i * self.ctx.display.font_height)
                    self.ctx.display.draw_string(
                        offset_x, offset_y, word, lcd.WHITE, lcd.BLACK
                    )
            else:
                for i, word in enumerate(word_list[12:]):
                    offset_x = self.ctx.display.width() // 2
                    offset_y = 40 + (i * self.ctx.display.font_height)
                    self.ctx.display.draw_string(
                        offset_x, offset_y, word, lcd.WHITE, lcd.BLACK
                    )

    def print_qr_prompt(self, data, qr_format):
        """Prompts the user to print a QR code in the specified format
        if a printer is connected
        """
        if self.ctx.printer is None:
            return
        self.ctx.display.clear()
        time.sleep_ms(1000)
        self.ctx.display.draw_centered_text(t("Print to QR?"))
        if self.wait_for_proceed():
            i = 0
            for qr_code, count in to_qr_codes(
                data, self.ctx.printer.qr_data_width(), qr_format
            ):
                if i == count:
                    break
                self.ctx.display.clear()
                self.ctx.display.draw_centered_text(
                    t("Printing\n%d / %d") % (i + 1, count)
                )
                self.ctx.printer.print_qr_code(qr_code)
                i += 1

    def prompt(self, text, offset_y=0):
        """Prompts user to answer Yes or No"""
        # Go up if question has multiple lines
        offset_y -= (
            len(self.ctx.display.to_lines(text)) - 1
        ) * self.ctx.display.font_height
        self.ctx.display.draw_hcentered_text(text, offset_y)
        answer = False
        self.y_keypad_map = []
        self.x_keypad_map = []
        if board.config["type"] == "m5stickv":
            answer = not self.ctx.input.wait_for_button()
        else:
            offset_y += (
                len(self.ctx.display.to_lines(text)) + 1
            ) * self.ctx.display.font_height
            self.x_keypad_map.append(DEFAULT_PADDING)
            self.x_keypad_map.append(self.ctx.display.width() // 2)
            self.x_keypad_map.append(self.ctx.display.width() - DEFAULT_PADDING)
            y_key_map = offset_y - self.ctx.display.font_height // 2
            self.y_keypad_map.append(y_key_map)
            y_key_map += 2 * self.ctx.display.font_height
            self.y_keypad_map.append(y_key_map)
            btn = None
            if self.ctx.input.has_touch:
                self.ctx.input.touch.clear_regions()
                self.ctx.input.touch.x_regions = self.x_keypad_map
                self.ctx.input.touch.y_regions = self.y_keypad_map
            while btn != BUTTON_ENTER:
                offset_x = self.ctx.display.width() // 4
                offset_x -= (len(t("Yes")) * self.ctx.display.font_width) // 2
                self.ctx.display.draw_string(offset_x, offset_y, t("Yes"), lcd.GREEN)
                offset_x = (self.ctx.display.width() * 3) // 4
                offset_x -= (len(t("No")) * self.ctx.display.font_width) // 2
                self.ctx.display.draw_string(offset_x, offset_y, t("No"), lcd.RED)
                if self.ctx.input.buttons_active:
                    if answer:
                        self.ctx.display.outline(
                            DEFAULT_PADDING,
                            offset_y - self.ctx.display.font_height // 2,
                            self.ctx.display.usable_width() // 2,
                            2 * self.ctx.display.font_height - 2,
                            lcd.GREEN,
                        )
                    else:
                        self.ctx.display.outline(
                            self.ctx.display.width() // 2,
                            offset_y - self.ctx.display.font_height // 2,
                            self.ctx.display.usable_width() // 2,
                            2 * self.ctx.display.font_height - 2,
                            lcd.RED,
                        )
                elif self.ctx.input.has_touch:
                    for region in self.x_keypad_map:
                        self.ctx.display.fill_rectangle(
                            region,
                            self.y_keypad_map[0],
                            1,
                            2 * self.ctx.display.font_height,
                            lcd.DARKGREY,
                        )
                btn = self.ctx.input.wait_for_button()
                if btn in (BUTTON_PAGE, BUTTON_PAGE_PREV):
                    answer = not answer
                    # erase yes/no area for next loop
                    self.ctx.display.fill_rectangle(
                        0,
                        offset_y - self.ctx.display.font_height,
                        self.ctx.display.width() + 1,
                        3 * self.ctx.display.font_height,
                        lcd.BLACK,
                    )
                elif btn == BUTTON_TOUCH:
                    self.ctx.input.touch.clear_regions()
                    # index 0 = Yes
                    # index 1 = No
                    if self.ctx.input.touch.current_index():
                        return False
                    return True
        return answer

    def shutdown(self):
        """Handler for the 'shutdown' menu item"""
        return MENU_SHUTDOWN

    def run(self):
        """Runs the page's menu loop"""
        _, status = self.menu.run_loop()
        return status != MENU_SHUTDOWN


class Menu:
    """Represents a menu that can render itself to the screen, handle item selection,
    and invoke menu item callbacks that return a status
    """

    def __init__(self, ctx, menu):
        self.ctx = ctx
        self.menu = menu

    def run_loop(self):
        """Runs the menu loop until one of the menu items returns either a MENU_EXIT
        or MENU_SHUTDOWN status
        """
        selected_item_index = 0
        while True:
            gc.collect()
            self.ctx.display.clear()
            if self.ctx.input.has_touch:
                self._draw_touch_menu(selected_item_index)
            else:
                self._draw_menu(selected_item_index)

            btn = self.ctx.input.wait_for_button(block=True)
            if self.ctx.input.has_touch:
                if btn == BUTTON_TOUCH:
                    selected_item_index = self.ctx.input.touch.current_index()
                    btn = BUTTON_ENTER
                self.ctx.input.touch.clear_regions()
            if btn == BUTTON_ENTER:
                try:
                    self.ctx.display.clear()
                    status = self.menu[selected_item_index][1]()
                    if status != MENU_CONTINUE:
                        return (selected_item_index, status)
                except Exception as e:
                    self.ctx.log.exception(
                        'Exception occurred in menu item "%s"'
                        % self.menu[selected_item_index][0]
                    )
                    self.ctx.display.clear()
                    self.ctx.display.draw_centered_text(
                        t("Error:\n%s") % repr(e), lcd.RED
                    )
                    self.ctx.input.wait_for_button()
            elif btn == BUTTON_PAGE:
                selected_item_index = (selected_item_index + 1) % len(self.menu)
            elif btn == BUTTON_PAGE_PREV:
                selected_item_index = (selected_item_index - 1) % len(self.menu)

    def _draw_touch_menu(self, selected_item_index):
        # map regions with dynamic height to fill screen
        self.ctx.input.touch.clear_regions()
        offset_y = 0
        Page.y_keypad_map = [offset_y]
        for menu_item in self.menu:
            offset_y += len(self.ctx.display.to_lines(menu_item[0])) + 1
            Page.y_keypad_map.append(offset_y)
        height_multiplier = self.ctx.display.height() - 2 * DEFAULT_PADDING
        height_multiplier //= offset_y
        Page.y_keypad_map = [
            n * height_multiplier + DEFAULT_PADDING for n in Page.y_keypad_map
        ]
        self.ctx.input.touch.y_regions = Page.y_keypad_map

        # draw dividers and outline
        for i, y in enumerate(Page.y_keypad_map[:-1]):
            if i and not self.ctx.input.buttons_active:
                self.ctx.display.fill_rectangle(
                    0, y, self.ctx.display.width(), 1, lcd.DARKGREY
                )
            height = Page.y_keypad_map[i + 1] - y
            if selected_item_index == i and self.ctx.input.buttons_active:
                self.ctx.display.outline(
                    DEFAULT_PADDING - 1,
                    y + 1,
                    self.ctx.display.usable_width(),
                    height - 2,
                )

        # draw centralized strings in regions
        for i, menu_item in enumerate(self.menu):
            menu_item_lines = self.ctx.display.to_lines(menu_item[0])
            offset_y = Page.y_keypad_map[i + 1] - Page.y_keypad_map[i]
            offset_y -= len(menu_item_lines) * self.ctx.display.font_height
            offset_y //= 2
            offset_y += Page.y_keypad_map[i]
            for j, text in enumerate(menu_item_lines):
                self.ctx.display.draw_hcentered_text(
                    text, offset_y + self.ctx.display.font_height * j
                )

    def _draw_menu(self, selected_item_index):
        offset_y = len(self.menu) * self.ctx.display.font_height * 2
        offset_y = self.ctx.display.height() - offset_y
        offset_y //= 2
        for i, menu_item in enumerate(self.menu):
            menu_item_lines = self.ctx.display.to_lines(menu_item[0])
            delta_y = (len(menu_item_lines) + 1) * self.ctx.display.font_height
            for j, text in enumerate(menu_item_lines):
                self.ctx.display.draw_hcentered_text(
                    text,
                    offset_y
                    + self.ctx.display.font_height // 2
                    + self.ctx.display.font_height * j,
                )
            if selected_item_index == i:
                self.ctx.display.outline(
                    DEFAULT_PADDING,
                    offset_y + 1,
                    self.ctx.display.usable_width(),
                    delta_y - 2,
                )
            offset_y += delta_y


class Keypad:
    """Controls keypad creation and management"""

    def __init__(self, ctx, keysets):
        self.ctx = ctx
        self.keysets = keysets
        self.keyset_index = 0
        self.key_h_spacing, self.key_v_spacing = self.map_keys_array(
            self.width, self.height
        )
        self.cur_key_index = 0
        self.moving_forward = True

    @property
    def keys(self):
        """Returns the current set of keys being displayed"""
        return self.keysets[self.keyset_index]

    @property
    def total_keys(self):
        """Returns the total number of keys in the current keyset, including fixed"""
        return len(self.keys) + FIXED_KEYS + (1 if len(self.keysets) > 1 else 0)

    @property
    def more_index(self):
        """Returns the index of the "More" key"""
        return len(self.keys)

    @property
    def del_index(self):
        """Returns the index of the "Del" key"""
        return len(self.keys) + (1 if len(self.keysets) > 1 else 0)

    @property
    def esc_index(self):
        """Returns the index of the "Esc" key"""
        return self.del_index + 1

    @property
    def go_index(self):
        """Returns the index of the "Go" key"""
        return self.esc_index + 1

    @property
    def width(self):
        """Returns the needed width for the current keyset"""
        return math.floor(math.sqrt(self.total_keys))

    @property
    def height(self):
        """Returns the needed height for the current keyset"""
        return math.ceil((self.total_keys) / self.width)

    def reset(self):
        """Reset parameters when switching a multi-keypad"""
        self.key_h_spacing, self.key_v_spacing = self.map_keys_array(
            self.width, self.height
        )
        self.cur_key_index = 0
        self.moving_forward = True

    def map_keys_array(self, width, height):
        """Maps an array of regions for keys to be placed in
        Returns horizontal and vertical spacing of keys
        """
        self.y_keypad_map = []
        self.x_keypad_map = []
        key_h_spacing = self.ctx.display.width() - DEFAULT_PADDING
        key_h_spacing //= width
        key_v_spacing = (
            self.ctx.display.height() - DEFAULT_PADDING - self.keypad_offset()
        )
        key_v_spacing //= height
        for y in range(height + 1):
            region = y * key_v_spacing + self.keypad_offset()
            self.y_keypad_map.append(region)
        for x in range(width + 1):
            region = x * key_h_spacing + DEFAULT_PADDING // 2
            self.x_keypad_map.append(region)
        if self.ctx.input.has_touch:
            self.ctx.input.touch.y_regions = self.y_keypad_map
            self.ctx.input.touch.x_regions = self.x_keypad_map
        return key_h_spacing, key_v_spacing

    def keypad_offset(self):
        """Returns keypad start position"""
        return DEFAULT_PADDING + self.ctx.display.font_height * 3

    def draw_keys(self, possible_keys):
        """Draws keypad on the screen"""
        key_index = 0
        for y in self.y_keypad_map[:-1]:
            offset_y = y + (self.key_v_spacing - self.ctx.display.font_height) // 2
            for x in self.x_keypad_map[:-1]:
                key = None
                if key_index < len(self.keys):
                    key = self.keys[key_index]
                elif key_index == self.del_index:
                    key = "<"
                elif key_index == self.esc_index:
                    key = t("Esc")
                elif key_index == self.go_index:
                    key = t("Go")
                elif key_index == self.more_index and len(self.keysets) > 1:
                    key = t("ABC")
                if key is not None:
                    offset_x = x
                    key_offset_x = (
                        self.key_h_spacing - len(key) * self.ctx.display.font_width
                    ) // 2
                    key_offset_x += offset_x
                    if (
                        key_index < len(self.keys)
                        and self.keys[key_index] not in possible_keys
                    ):
                        # faded text
                        self.ctx.display.draw_string(
                            key_offset_x, offset_y, key, lcd.LIGHTBLACK
                        )
                    else:
                        if self.ctx.input.has_touch:
                            self.ctx.display.outline(
                                offset_x + 1,
                                y + 1,
                                self.key_h_spacing - 2,
                                self.key_v_spacing - 2,
                                lcd.DARKGREY,
                            )
                        self.ctx.display.draw_string(
                            key_offset_x, offset_y, key, lcd.WHITE
                        )
                    if (
                        key_index == self.cur_key_index
                        and self.ctx.input.buttons_active
                    ):
                        if self.ctx.input.has_touch:
                            self.ctx.display.outline(
                                offset_x + 1,
                                y + 1,
                                self.key_h_spacing - 2,
                                self.key_v_spacing - 2,
                            )
                        else:
                            self.ctx.display.outline(
                                offset_x - 2,
                                y,
                                self.key_h_spacing + 1,
                                self.key_v_spacing - 1,
                            )
                key_index += 1

    def get_valid_index(self, possible_keys):
        """Moves current index to a valid position"""
        while (
            self.cur_key_index < len(self.keys)
            and self.keys[self.cur_key_index] not in possible_keys
        ):
            if self.moving_forward:
                self.cur_key_index = (self.cur_key_index + 1) % self.total_keys
            else:
                if self.cur_key_index:
                    self.cur_key_index -= 1
                else:
                    self.cur_key_index = self.total_keys - 1
        return self.cur_key_index

    def touch_to_physical(self, possible_keys):
        """Convert a touch press in button press"""
        self.cur_key_index = self.ctx.input.touch.current_index()
        actual_button = None
        if self.cur_key_index < len(self.keys):
            if self.keys[self.cur_key_index] in possible_keys:
                actual_button = BUTTON_ENTER
        elif self.cur_key_index < self.total_keys:
            actual_button = BUTTON_ENTER
        else:
            self.cur_key_index = 0
        return actual_button

    def next_key(self):
        """Increments cursor when page button is pressed"""
        self.moving_forward = True
        self.cur_key_index = (self.cur_key_index + 1) % self.total_keys

    def previous_key(self):
        """Decrements cursor when page_prev button is pressed"""
        self.moving_forward = False
        self.cur_key_index = (self.cur_key_index - 1) % self.total_keys

    def next_keyset(self):
        """Change keys for the next keyset"""
        if len(self.keysets) > 1:
            self.keyset_index = (self.keyset_index + 1) % len(self.keysets)
            self.reset()

    def previous_keyset(self):
        """Change keys for the previous keyset"""
        if len(self.keysets) > 1:
            self.keyset_index = (self.keyset_index - 1) % len(self.keysets)
            self.reset()
