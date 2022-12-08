import hashlib
import board
import lcd
import image
import sensor
import time
from embit.wordlists.bip39 import WORDLIST
from . import Page
from ..wdt import wdt
from ..krux_settings import t
from ..display import DEFAULT_PADDING
from ..camera import OV7740_ID, OV2640_ID, GC0328_ID
from ..input import (
    BUTTON_ENTER,
    BUTTON_PAGE,
    BUTTON_PAGE_PREV,
    BUTTON_TOUCH,
)

# Tiny Seed last bit index positions according to checksums
TS_LAST_BIT_NO_CS = 143
TS_LAST_BIT_12W_CS = 139
TS_LAST_BIT_24W_CS = 135
TS_ESC_POSITION = 161
TS_GO_POSITION = 167


class TinySeed(Page):
    """Class for handling Tinyseed fomat"""

    def __init__(self, ctx):
        super().__init__(ctx, None)
        self.ctx = ctx
        self.x_offset = DEFAULT_PADDING // 2 + 2 * self.ctx.display.font_width
        if self.ctx.display.width() > 135:
            self.y_offset = DEFAULT_PADDING + 3 * self.ctx.display.font_height
            self.x_pad = self.ctx.display.font_height
            self.y_pad = self.ctx.display.font_height
            self.y_pad += self.ctx.display.height() // 120
        else:
            self.y_offset = 2 * self.ctx.display.font_height
            self.x_pad = self.ctx.display.font_width + 1
            self.y_pad = self.ctx.display.font_height

    def _draw_grid(self):
        """Draws grid for import and export Tinyseed UI"""
        y_var = self.y_offset
        x_offset = self.x_offset
        for _ in range(13):
            self.ctx.display.fill_rectangle(
                x_offset,
                self.y_offset,
                1,
                12 * self.y_pad,
                lcd.DARKGREY,
            )
            x_offset += self.x_pad
            self.ctx.display.fill_rectangle(
                self.x_offset,
                y_var,
                12 * (self.x_pad),
                1,
                lcd.DARKGREY,
            )
            y_var += self.y_pad

    def _draw_labels(self, page):
        """Draws labels for import and export Tinyseed UI"""
        self.ctx.display.draw_hcentered_text("Tiny Seed")
        if self.ctx.display.width() > 135:
            self.ctx.display.to_landscape()
            bit_number = 2048
            bit_offset = DEFAULT_PADDING // 2 + 2 * self.ctx.display.font_height
            for _ in range(12):
                lcd.draw_string(
                    (7 - len(str(bit_number))) * self.ctx.display.font_width
                    - DEFAULT_PADDING // 2,
                    self.ctx.display.width() - bit_offset,
                    str(bit_number),
                    lcd.WHITE,
                )
                bit_number //= 2
                bit_offset += self.x_pad
            self.ctx.display.to_portrait()
        y_offset = self.y_offset
        y_offset += (self.y_pad - self.ctx.display.font_height) // 2
        for x in range(12):
            line = str(page * 12 + x + 1)
            if (page * 12 + x + 1) < 10:
                line = " " + line
            self.ctx.display.draw_string(
                DEFAULT_PADDING // 2, y_offset, line, lcd.WHITE
            )
            y_offset += self.y_pad

    def _draw_punched(self, words, page):
        """Draws punched bits for import and export Tinyseed UI"""
        y_offset = self.y_offset
        for x in range(12):
            if isinstance(words[0], str):
                word_list_index = WORDLIST.index(words[page * 12 + x]) + 1
            else:
                word_list_index = words[page * 12 + x]
            for y in range(12):
                if (word_list_index >> (11 - y)) & 1:
                    x_offset = self.x_offset + 3
                    x_offset += y * (self.x_pad)
                    self.ctx.display.fill_rectangle(
                        x_offset,
                        y_offset + 3,
                        self.x_pad - 5,
                        self.y_pad - 5,
                        lcd.BLUE,
                    )
            y_offset += self.y_pad

    def export(self):
        """Shows seed as a punch pattern for Tiny Seed layout"""
        words = self.ctx.wallet.key.mnemonic.split(" ")
        for page in range(len(words) // 12):
            self._draw_labels(page)
            self._draw_grid()
            self._draw_punched(words, page)
            self.ctx.input.wait_for_button()
            self.ctx.display.clear()

    def print_tiny_seed(self):
        """Creates a bitmap image of a punched Tiny Seed and sends it to a thermal printer"""
        # Scale from original: 1.5X
        words = self.ctx.wallet.key.mnemonic.split(" ")
        image_size = 312
        border_y = 16
        border_x = 32
        grid_x_offset = border_x + 34  # border + 4,3mm*8px
        grid_y_offset = border_y + 52  # border + 6,5mm*8px
        pad_x = 14  # 1,75mm*8px
        pad_y = 16  # 2mm*8px
        self.ctx.display.clear()
        self.ctx.display.draw_hcentered_text(
            t("Printing ..."), self.ctx.display.height() // 2
        )
        self.ctx.printer.print_string("Tiny Seed\n\n")
        for page in range(len(words) // 12):
            # creates an image
            ts_image = image.Image(size=(image_size, image_size), copy_to_fb=True)
            ts_image.clear()

            # Frame
            # Upper
            ts_image.draw_rectangle(
                0,
                0,
                218 + 2 * border_x,  # 27,2mm*8px + ...
                border_y,
                lcd.WHITE,
                fill=True,
            )
            # Lower
            ts_image.draw_rectangle(
                0,
                276 + border_y,
                218 + 2 * border_x,  # 27,2mm*8px + ...
                border_y,
                lcd.WHITE,
                fill=True,
            )
            # Left
            ts_image.draw_rectangle(0, border_y, border_x, 276, lcd.WHITE, fill=True)
            # Right
            ts_image.draw_rectangle(
                218 + border_x, border_y, border_x, 276, lcd.WHITE, fill=True
            )

            # labels
            y_offset = grid_y_offset
            if self.ctx.display.font_height > pad_y:
                y_offset -= (self.ctx.display.font_height - pad_y) // 2 + 1
            for x in range(12):
                line = str(page * 12 + x + 1)
                if (page * 12 + x + 1) < 10:
                    line = " " + line
                ts_image.draw_string(
                    border_x + self.ctx.display.font_width // 2,
                    y_offset,
                    line,
                    lcd.WHITE,
                )
                y_offset += pad_y

            # grid
            y_offset = grid_y_offset
            x_offset = grid_x_offset
            for _ in range(13):
                ts_image.draw_line(
                    x_offset,
                    y_offset,
                    x_offset,
                    y_offset + 12 * pad_y,
                    lcd.WHITE,
                )
                x_offset += pad_x
            for _ in range(13):
                ts_image.draw_line(
                    grid_x_offset,
                    y_offset,
                    grid_x_offset + 12 * pad_x,
                    y_offset,
                    lcd.WHITE,
                )
                y_offset += pad_y

            # draw punched
            y_offset = grid_y_offset
            for y in range(12):
                if isinstance(words[0], str):
                    word_list_index = WORDLIST.index(words[page * 12 + y]) + 1
                else:
                    word_list_index = words[page * 12 + y]
                for x in range(12):
                    if (word_list_index >> (11 - x)) & 1:
                        x_offset = grid_x_offset + pad_x // 2
                        x_offset += x * (pad_x)
                        ts_image.draw_circle(
                            x_offset, y_offset + pad_y // 2, 6, lcd.WHITE, fill=True
                        )
                y_offset += pad_y

            # Convert image to bitmap bytes
            ts_image.to_grayscale()
            ts_image.binary([(125, 255)])
            # # Debug image
            # lcd.display(ts_image, roi=(0, 0, image_size, image_size))
            # self.ctx.input.wait_for_button()

            # Print
            for y in range(image_size):
                line_bytes = bytes([])
                x = 0
                for _ in range(image_size // 8):
                    im_byte = 0
                    for _ in range(8):
                        im_byte <<= 1
                        if ts_image.get_pixel(x, y):
                            im_byte |= 1
                        x += 1
                    line_bytes += bytes([im_byte])
                # send line by line to be printed
                self.ctx.printer.print_bitmap_line(line_bytes)
                wdt.feed()
            grid_x_offset = border_x + 33  # 4,1mm*8px
            grid_y_offset = border_y + 50  # 6,2mm*8px
        self.ctx.printer.feed(3)
        self.ctx.display.clear()

    def _draw_index(self, index):
        """Outline index respective"""
        width = 6 * self.x_pad - 2
        if index >= 162:
            x_position = self.x_offset + 6 * self.x_pad + 1
        elif index >= 156:
            x_position = self.x_offset + 1
        elif index <= TS_LAST_BIT_NO_CS:
            x_position = index % 12
            x_position *= self.x_pad
            x_position += self.x_offset + 1
            width = self.x_pad - 2
        else:
            return
        y_position = index // 12
        y_position *= self.y_pad
        y_position += self.y_offset + 1
        self.ctx.display.outline(
            x_position,
            y_position,
            width,
            self.y_pad - 2,
            lcd.WHITE,
        )

    def _draw_menu(self):
        """Draws options to leave and proceed"""
        y_offset = self.y_offset + 13 * self.y_pad
        x_offset = self.x_offset
        self.ctx.display.draw_string(
            x_offset + (5 * self.x_pad) // 2, y_offset + 1, t("Esc"), lcd.WHITE
        )
        self.ctx.display.draw_string(
            x_offset + (17 * self.x_pad) // 2, y_offset + 1, t("Go"), lcd.WHITE
        )
        self.ctx.display.fill_rectangle(
            x_offset,
            y_offset,
            12 * self.x_pad,
            1,
            lcd.DARKGREY,
        )
        self.ctx.display.fill_rectangle(
            x_offset,
            y_offset + self.y_pad,
            12 * self.x_pad,
            1,
            lcd.DARKGREY,
        )
        for _ in range(3):
            self.ctx.display.fill_rectangle(
                x_offset,
                y_offset,
                1,
                self.y_pad,
                lcd.DARKGREY,
            )
            x_offset += 6 * self.x_pad

    def _map_keys_array(self):
        """Maps an array of regions for keys to be placed in"""
        if self.ctx.input.touch is not None:
            x_region = self.x_offset
            for _ in range(13):
                self.ctx.input.touch.x_regions.append(x_region)
                x_region += self.x_pad
            y_region = self.y_offset
            for _ in range(15):
                self.ctx.input.touch.y_regions.append(y_region)
                y_region += self.y_pad

    def _draw_disabled(self, w24=False):
        """Draws disabled section where checksum is automatically filled"""
        if not w24:

            self.ctx.display.fill_rectangle(
                self.x_offset + 8 * self.x_pad,
                self.y_offset + 11 * self.y_pad,
                4 * self.x_pad,
                self.y_pad,
                lcd.DARKGREY,
            )
            self.ctx.display.fill_rectangle(
                self.x_offset + 7 * self.x_pad,
                self.y_offset + 11 * self.y_pad,
                1 * self.x_pad,
                self.y_pad,
                lcd.LIGHTGREY,
            )
        else:
            self.ctx.display.fill_rectangle(
                self.x_offset + 4 * self.x_pad,
                self.y_offset + 11 * self.y_pad,
                8 * self.x_pad,
                self.y_pad,
                lcd.DARKGREY,
            )
            self.ctx.display.fill_rectangle(
                self.x_offset + 3 * self.x_pad,
                self.y_offset + 11 * self.y_pad,
                1 * self.x_pad,
                self.y_pad,
                lcd.LIGHTGREY,
            )

    def check_sum(self, tiny_seed_numbers):
        """Dinamically calculates checksum"""
        # Inspired in Jimmy Song's HDPrivateKey.from_mnemonic() method
        binary_seed = bytearray()
        offset = 0
        for tiny_seed_number in tiny_seed_numbers:
            index = tiny_seed_number - 1 if tiny_seed_number > 1 else 0
            remaining = 11
            while remaining > 0:
                bits_needed = 8 - offset
                if remaining == bits_needed:
                    if bits_needed == 8:
                        binary_seed.append(index)
                    else:
                        binary_seed[-1] |= index
                    offset = 0
                    remaining = 0
                elif remaining > bits_needed:
                    if bits_needed == 8:
                        binary_seed.append(index >> (remaining - 8))
                    else:
                        binary_seed[-1] |= index >> (remaining - bits_needed)
                    remaining -= bits_needed
                    offset = 0
                    # lop off the top 8 bits
                    index &= (1 << remaining) - 1
                else:
                    binary_seed.append(index << (8 - remaining))
                    offset = remaining
                    remaining = 0

        checksum_length_bits = len(tiny_seed_numbers) * 11 // 33
        num_remainder = checksum_length_bits % 8
        if num_remainder:
            checksum_length = checksum_length_bits // 8 + 1
        else:
            checksum_length = checksum_length_bits // 8
        raw = bytes(binary_seed)
        data = raw[:-checksum_length]
        computed_checksum = int.from_bytes(
            hashlib.sha256(data).digest()[:checksum_length], "big"
        )
        checksum = computed_checksum >> (8 - checksum_length_bits)
        return checksum

    def toggle_bit(self, word, bit):
        """Toggle bit state according to pressed index"""
        return word ^ (1 << bit)

    def to_words(self, tiny_seed_numbers):
        """Converts a list of numbers 1-2048 to a list of respective BIP39 words"""
        words = []
        for number in tiny_seed_numbers:
            words.append(WORDLIST[number - 1])
        return words

    def _auto_checksum(self, word_numbers):
        """Automatically modify last word do add checksum"""
        checksum = self.check_sum(word_numbers)
        if len(word_numbers) == 12:
            word_numbers[11] -= 1
            word_numbers[11] &= 0b11111110000
            word_numbers[11] += checksum + 1
        else:
            word_numbers[23] -= 1
            word_numbers[23] &= 0b11100000000
            word_numbers[23] += checksum + 1
        return word_numbers

    def _new_index(self, index, btn, w24, page):
        if btn == BUTTON_PAGE:
            if index >= TS_GO_POSITION:
                index = 0
            elif index >= TS_ESC_POSITION:
                index = TS_GO_POSITION
            elif (
                (w24 and page == 0 and index >= TS_LAST_BIT_NO_CS)
                or (w24 and page == 1 and index >= TS_LAST_BIT_24W_CS)
                or index >= TS_LAST_BIT_12W_CS
            ):
                index = TS_ESC_POSITION
            else:
                index += 1
        elif btn == BUTTON_PAGE_PREV:
            if index <= 0:
                index = TS_GO_POSITION
            elif (
                (w24 and page == 0 and index <= TS_LAST_BIT_NO_CS)
                or (w24 and page == 1 and index <= TS_LAST_BIT_24W_CS)
                or index <= TS_LAST_BIT_12W_CS
            ):
                index -= 1
            elif index <= TS_ESC_POSITION:
                if w24:
                    if not page:
                        index = TS_LAST_BIT_NO_CS
                    else:
                        index = TS_LAST_BIT_24W_CS
                else:
                    index = TS_LAST_BIT_12W_CS
            elif index <= TS_GO_POSITION:
                index = TS_ESC_POSITION
        return index


    def enter_tiny_seed(self, w24=False, seed_numbers=None, scanning=False):
        """UI to manually enter a Tiny Seed"""
        index = 0
        if seed_numbers:
            tiny_seed_numbers = seed_numbers
            # move index to Go position
            index = TS_GO_POSITION
        elif w24:
            tiny_seed_numbers = [2048] * 23 + [1]
        else:
            tiny_seed_numbers = [2048] * 11 + [433]
        btn = None
        self._map_keys_array()
        page = 0
        while True:
            self._draw_labels(page)
            self._draw_grid()
            if not w24 or page:
                self._draw_disabled(w24)
                tiny_seed_numbers = self._auto_checksum(tiny_seed_numbers)
            self._draw_punched(tiny_seed_numbers, page)
            self._draw_menu()
            if self.ctx.input.buttons_active:
                self._draw_index(index)
            btn = self.ctx.input.wait_for_button()
            if btn == BUTTON_TOUCH:
                btn = BUTTON_ENTER
                index = self.ctx.input.touch.current_index()
            if btn == BUTTON_ENTER:
                if index >= 162:  # go
                    if not w24 or (w24 and (page or scanning)):
                        if scanning:
                            return tiny_seed_numbers
                        return self.to_words(tiny_seed_numbers)
                    page += 1
                elif index >= 156:  # ESC
                    self.ctx.display.clear()
                    if self.prompt(t("Are you sure?"), self.ctx.display.height() // 2):
                        break
                    self._map_keys_array()
                elif (
                    index <= TS_LAST_BIT_12W_CS
                    or (w24 and page == 0 and index <= TS_LAST_BIT_NO_CS)
                    or (w24 and page == 1 and index <= TS_LAST_BIT_24W_CS)
                ):
                    word_index = index // 12
                    word_index += page * 12
                    bit = 11 - (index % 12)
                    if bit == 11:
                        tiny_seed_numbers[word_index] = 2048
                    else:
                        tiny_seed_numbers[word_index] = (
                            self.toggle_bit(tiny_seed_numbers[word_index], bit) % 2048
                        )
                    if tiny_seed_numbers[word_index] == 0:
                        tiny_seed_numbers[word_index] = 2048
            index = self._new_index(index, btn, w24, page)
            self.ctx.display.clear()


class TinyScanner(Page):
    """Uses camera sensor to detect punch pattern on a Tiny Seed, in metal or paper"""

    def __init__(self, ctx):
        super().__init__(ctx, None)
        self.ctx = ctx
        self.x_regions = []
        self.y_regions = []
        self.tiny_seed = TinySeed(self.ctx)

    def _map_dot_region(self, rect_size, page=0):
        # Think in portrait mode, with Tiny Seed tilted 90 degrees
        self.x_regions = []
        self.y_regions = []
        if not page:
            if board.config["type"].startswith("amigo"):
                x_offset = rect_size[0] + (rect_size[2] * 39) / 345
                y_offset = rect_size[1] + (rect_size[3] * 44) / 272
            else:
                x_offset = rect_size[0] + (rect_size[2] * 65) / 345
                y_offset = rect_size[1] + (rect_size[3] * 17) / 272
        else:
            if board.config["type"].startswith("amigo"):
                x_offset = rect_size[0] + (rect_size[2] * 42) / 345
                y_offset = rect_size[1] + (rect_size[3] * 41) / 272
            else:
                x_offset = rect_size[0] + (rect_size[2] * 62) / 345
                y_offset = rect_size[1] + (rect_size[3] * 22) / 272
        self.x_regions.append(int(x_offset))
        self.y_regions.append(int(y_offset))
        x_pad = rect_size[2] * 240 / (12 * 345)
        y_pad = rect_size[3] * 210 / (12 * 272)
        for _ in range(12):
            x_offset += x_pad
            y_offset += y_pad
            self.x_regions.append(int(round(x_offset)))
            self.y_regions.append(int(round(y_offset)))

    def _valid_numbers(self, data):
        for n in data:
            if not n or n > 2048:
                return False
        return True

    def _exit_camera(self):
        sensor.run(0)
        self.ctx.display.to_portrait()
        self.ctx.display.clear()


    def scanner(self, w24=False):
        """Uses camera sensor to scan punched pattern on Tiny Seed format"""

        def gradient(up_right, up_left, low_left, low_right, index):
            """Calculates a reference threshold acording to an interpolation
            gradient of luminosity from 4 corners of Tiny Seed"""
            y_position = index % 12
            x_position = index // 12
            gradient_upper_x = (
                up_left * x_position + up_right * (11 - x_position)
            ) // 11
            gradient_lower_x = (
                low_left * x_position + low_right * (11 - x_position)
            ) // 11
            return (
                gradient_upper_x * (11 - y_position) + gradient_lower_x * (y_position)
            ) // 11

        def _choose_rect(rects):
            for rect in rects:
                aspect = rect[2] / rect[3]
                if (
                    rect[0]
                    and rect[1]
                    and (rect[0] + rect[2]) < img.width()
                    and (rect[1] + rect[3]) < img.height()
                    and 1.2 < aspect < 1.3
                ):
                    return rect
            return None

        page = 0
        capturing = False
        if w24:
            w24_seed_numbers = [0] * 24
        previous_seed_numbers = [1] * 12
        intro = t(
            "Paint punched dots black so they can be detected. "
            + "Use a black background surface. "
            + "Align camera and Tiny Seed precisely using the tracking rectangle."
        )
        if w24:
            intro += t(" Press ENTER when punches are correctly mapped")
        self.ctx.display.draw_hcentered_text(intro)
        if not self.prompt(t("Proceed?"), self.ctx.display.bottom_prompt_line):
            return None
        self.ctx.display.clear()
        self.ctx.display.draw_centered_text(t("Loading Camera"))
        self._time_frame = time.ticks_ms()
        self.ctx.camera.initialize_sensor()
        if self.ctx.camera.cam_id == OV7740_ID:
            # reduce sensitivity to avoid saturated reflactions
            # luminance high level, default=0x78
            sensor.__write_reg(0x24, 0x48)  # pylint: disable=W0212
            # luminance low level, default=0x68
            sensor.__write_reg(0x25, 0x38)  # pylint: disable=W0212
            # Disable frame integrtation (night mode)
            sensor.__write_reg(0x15, 0x00)  # pylint: disable=W0212
        sensor.run(1)
        self.ctx.display.clear()
        if self.ctx.display.width() < 320:
            camera_offset = False
        else:
            camera_offset = True
            self.ctx.display.outline(
                39,
                1,
                241,
                321,
            )
        self.ctx.display.to_landscape()
        while True:
            wdt.feed()
            page_seed_numbers = [0] * 12
            img = sensor.snapshot()
            if self.ctx.camera.cam_id == OV2640_ID:
                img.rotation_corr(z_rotation=180)
            hist = img.get_histogram()
            if "histogram" not in str(type(hist)):
                continue
            luminosity_threshold = [
                (0, hist.get_threshold().l_value()),
                (-50, 50),
                (-50, 50),
            ]
            rects = img.find_blobs(
                luminosity_threshold,
                x_stride=5,
                y_stride=5,
                area_threshold=10000,
                invert=True,
            )
            # blobs_count = len(rects)
            rect = _choose_rect(rects)
            if rect is None:
                luminosity_threshold = [
                    (0, hist.get_threshold().l_value() * 8 // 10),
                    (-50, 50),
                    (-50, 50),
                ]
                rects = img.find_blobs(
                    luminosity_threshold,
                    x_stride=5,
                    y_stride=5,
                    area_threshold=10000,
                    invert=True,
                )
                rect = _choose_rect(rects)
            if rect:
                ##get statistics
                if board.config["type"].startswith("amigo"):
                    region_ul = (rect[0], rect[1], rect[2] // 4, rect[3] // 2)
                    region_ur = (
                        rect[0] + 3 * rect[2] // 4,
                        rect[1],
                        rect[2] // 4,
                        rect[3] // 2,
                    )
                    region_ll = (
                        rect[0],
                        rect[1] + rect[3] // 2,
                        rect[2] // 4,
                        rect[3] // 2,
                    )
                    region_lr = (
                        rect[0] + 3 * rect[2] // 4,
                        rect[1] + rect[3] // 2,
                        rect[2] // 4,
                        rect[3] // 2,
                    )
                else:
                    region_ul = (
                        rect[0] + 3 * rect[2] // 4,
                        rect[1] + rect[3] // 2,
                        rect[2] // 4,
                        rect[3] // 2,
                    )
                    region_ur = (
                        rect[0],
                        rect[1] + rect[3] // 2,
                        rect[2] // 4,
                        rect[3] // 2,
                    )
                    region_ll = (
                        rect[0] + 3 * rect[2] // 4,
                        rect[1],
                        rect[2] // 4,
                        rect[3] // 2,
                    )
                    region_lr = (rect[0], rect[1], rect[2] // 4, rect[3] // 2)

                # ul_lum = img.get_statistics(bins=8, roi=region_ul).l_mean()
                # ur_lum = img.get_statistics(bins=8, roi=region_ur).l_mean()
                # ll_lum = img.get_statistics(bins=8, roi=region_ll).l_mean()
                # lr_lum = img.get_statistics(bins=8, roi=region_lr).l_mean()

                ul_hist = img.get_histogram(roi=region_ul)
                if "histogram" not in str(type(ul_hist)):
                    continue
                ul_lum = ul_hist.get_threshold().l_value()

                ur_hist = img.get_histogram(roi=region_ur)
                if "histogram" not in str(type(ur_hist)):
                    continue
                ur_lum = ur_hist.get_threshold().l_value()

                ll_hist = img.get_histogram(roi=region_ll)
                if "histogram" not in str(type(ll_hist)):
                    continue
                ll_lum = ll_hist.get_threshold().l_value()

                lr_hist = img.get_histogram(roi=region_lr)
                if "histogram" not in str(type(lr_hist)):
                    continue
                lr_lum = lr_hist.get_threshold().l_value()

                # Debug Blobs Count
                # img.draw_string(10, 10, "Blobs: " + str(blobs_count))
                # img.draw_string(10, 30, "Blobs 2: " + str(len(rects)))

                # Outline Tiny Seed
                outline = (
                    rect.rect()[0] - 1,
                    rect.rect()[1] - 1,
                    rect.rect()[2] + 1,
                    rect.rect()[3] + 1,
                )
                if capturing:
                    img.draw_rectangle(outline, lcd.RED, thickness=2)
                else:
                    img.draw_rectangle(outline, lcd.BLUE, thickness=2)

                # map_regions
                self._map_dot_region(rect.rect(), page)
                pad_x = self.x_regions[1] - self.x_regions[0]
                pad_y = self.y_regions[1] - self.y_regions[0]
                if pad_x < 4 or pad_y < 4:
                    break
                index = 0
                # Think in portrait mode, with Tiny Seed tilted 90 degrees
                y_map = self.y_regions[0:-1]
                x_map = self.x_regions[0:-1]
                if board.config["type"].startswith("amigo"):
                    x_map.reverse()
                else:
                    y_map.reverse()
                for x in x_map:
                    for y in y_map:
                        eval_rect = (x + 2, y + 2, pad_x - 3, pad_y - 3)
                        dot_l = img.get_statistics(bins=8, roi=eval_rect).l_mean()
                        gradient_ref = gradient(ur_lum, ul_lum, ll_lum, lr_lum, index)

                        # # Debug gradient
                        # if index == 0:
                        #     img.draw_string(10,10,"0:"+str(gradient_ref))
                        # if index == 11:
                        #     img.draw_string(70,10,"11:"+str(gradient_ref))
                        # if index == 131:
                        #     img.draw_string(10,25,"131:"+str(gradient_ref))
                        # if index == 143:
                        #     img.draw_string(70,25,"143:"+str(gradient_ref))

                        # Seems this camera has better dynamic range
                        if self.ctx.camera.cam_id == GC0328_ID:
                            punch_threshold = (gradient_ref * 4) // 5  # ~-20%
                        else:
                            punch_threshold = (gradient_ref * 11) // 12  # ~-9%
                        punched = (dot_l < punch_threshold)
                        # Sensor image will be downscaled on small displays
                        punch_thickness = 1 if self.ctx.display.height() > 240 else 2
                        if punched:
                            _ = img.draw_rectangle(
                                eval_rect, thickness=punch_thickness, color=lcd.BLUE
                            )
                            word_index = index // 12
                            bit = 11 - (index % 12)
                            page_seed_numbers[word_index] = (
                                self.tiny_seed.toggle_bit(
                                    page_seed_numbers[word_index], bit
                                )
                                % 2048
                            )
                        index += 1
                if self.ctx.display.height() > 240:
                    for i in range(13):
                        img.draw_line(
                            self.x_regions[i],
                            self.y_regions[0],
                            self.x_regions[i],
                            self.y_regions[-1],
                            lcd.BLUE,
                        )
                        img.draw_line(
                            self.x_regions[0],
                            self.y_regions[i],
                            self.x_regions[-1],
                            self.y_regions[i],
                            lcd.BLUE,
                        )
            if board.config["type"] == "m5stickv":
                img.lens_corr(strength=1.0, zoom=0.56)
            if camera_offset:
                lcd.display(img, oft=(2, 40))  # 40 will centralize image in Amigo
            else:
                lcd.display(img)
            if not w24:
                if (
                    self.tiny_seed.check_sum(page_seed_numbers)
                    == (page_seed_numbers[11] - 1) & 0b00000001111
                ):
                    if page_seed_numbers == previous_seed_numbers:
                        self._exit_camera()
                        self.ctx.display.draw_centered_text(
                            t("Review scanned data, edit if necessary")
                        )
                        self.ctx.input.wait_for_button()
                        self.ctx.display.clear()
                        return self.tiny_seed.enter_tiny_seed(
                            seed_numbers=page_seed_numbers
                        )
                    previous_seed_numbers = page_seed_numbers
            else:
                if not page:
                    if page_seed_numbers == previous_seed_numbers and capturing:
                        self._exit_camera()
                        self.ctx.display.draw_centered_text(
                            t("Review scanned data, edit if necessary")
                        )
                        self.ctx.input.wait_for_button()
                        self.ctx.display.clear()
                        words = self.tiny_seed.enter_tiny_seed(
                            True, page_seed_numbers, True
                        )
                        if words is not None:
                            w24_seed_numbers[0:12] = words
                            page = 1
                        else:
                            self.ctx.display.clear()
                            self.ctx.display.flash_text(
                                t("Scanning words 1-12 again"), duration=700
                            )
                        sensor.run(1)
                        sensor.skip_frames()
                        self.ctx.display.clear()
                        self.ctx.display.to_landscape()
                        capturing = False
                    elif self._valid_numbers(page_seed_numbers):
                        previous_seed_numbers = page_seed_numbers
                else:
                    w24_seed_numbers[12:24] = page_seed_numbers
                    if (
                        self.tiny_seed.check_sum(w24_seed_numbers)
                        == (w24_seed_numbers[23] - 1) & 0b00011111111
                    ):
                        if page_seed_numbers == previous_seed_numbers:
                            self._exit_camera()
                            return self.tiny_seed.to_words(w24_seed_numbers)
                        previous_seed_numbers = page_seed_numbers

            if time.ticks_ms() > self._time_frame + 1000:
                if w24 and not page and not self.ctx.input.enter_value():
                    capturing = True
                if (
                    not self.ctx.input.page_value()
                    or not self.ctx.input.page_prev_value()
                ):
                    break
        self._exit_camera()
        lcd.clear()
        return None