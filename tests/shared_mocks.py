from unittest import mock


def get_mock_open(files: dict[str, str]):
    def open_mock(filename, *args, **kwargs):
        for expected_filename, content in files.items():
            if filename == expected_filename:
                if content == "Exception":
                    raise Exception()
                return mock.mock_open(read_data=content).return_value
        raise FileNotFoundError("(mock) Unable to open {filename}")

    return mock.MagicMock(side_effect=open_mock)


class MockPrinter:
    def __init__(self):
        pass

    def qr_data_width(self):
        return 33

    def clear(self):
        pass

    def print_qr_code(self, qr_code):
        pass


class MockQRPartParser:
    TOTAL = 10
    FORMAT = 0

    def __init__(self):
        self.count = 0
        self.parts = []
        self.format = MockQRPartParser.FORMAT

    def total_count(self):
        return MockQRPartParser.TOTAL

    def parsed_count(self):
        return len(self.parts)

    def parse(self, part):
        if part not in self.parts:
            self.parts.append(part)

    def is_complete(self):
        return len(self.parts) == self.total_count()

    def result(self):
        return "".join(self.parts)


class Mockhistogram_threshold:
    def value(self):
        return 1


class Mockhistogram:
    def get_threshold(self):
        return Mockhistogram_threshold()


class Mockqrcode:
    def __init__(self, data):
        self.data = data

    def payload(self):
        return self.data


SNAP_SUCCESS = 0
SNAP_HISTOGRAM_FAIL = 1
SNAP_FIND_QRCODES_FAIL = 2
SNAP_REPEAT_QRCODE = 3


def snapshot_generator(outcome=SNAP_SUCCESS):
    count = 0

    def snapshot():
        nonlocal count
        count += 1
        m = mock.MagicMock()
        if outcome == SNAP_HISTOGRAM_FAIL and count == 2:
            m.get_histogram.return_value = "failed"
            m.find_qrcodes.return_value = [Mockqrcode(str(count))]
        elif outcome == SNAP_FIND_QRCODES_FAIL and count == 2:
            m.get_histogram.return_value = Mockhistogram()
            m.find_qrcodes.return_value = []
        elif outcome == SNAP_REPEAT_QRCODE and count == 2:
            m.get_histogram.return_value = Mockhistogram()
            m.find_qrcodes.return_value = [Mockqrcode(str(count - 1))]
        else:
            m.get_histogram.return_value = Mockhistogram()
            m.find_qrcodes.return_value = [Mockqrcode(str(count))]
        return m

    return snapshot


def board_m5stickv():
    return mock.MagicMock(
        config={
            "type": "m5stickv",
            "lcd": {"height": 135, "width": 240, "invert": 0, "dir": 40, "lcd_type": 3},
            "sdcard": {"sclk": 30, "mosi": 33, "miso": 31, "cs": 32},
            "board_info": {
                "ISP_RX": 4,
                "ISP_TX": 5,
                "WIFI_TX": 39,
                "WIFI_RX": 38,
                "CONNEXT_A": 35,
                "CONNEXT_B": 34,
                "MPU_SDA": 29,
                "MPU_SCL": 28,
                "MPU_INT": 23,
                "SPK_LRCLK": 14,
                "SPK_BCLK": 15,
                "SPK_DIN": 17,
                "SPK_SD": 25,
                "MIC_LRCLK": 10,
                "MIC_DAT": 12,
                "MIC_CLK": 13,
                "LED_W": 7,
                "LED_R": 6,
                "LED_G": 9,
                "LED_B": 8,
                "BUTTON_A": 36,
                "BUTTON_B": 37,
            },
            "krux": {
                "pins": {
                    "BUTTON_A": 36,
                    "BUTTON_B": 37,
                    "LED_W": 7,
                    "UART2_TX": 35,
                    "UART2_RX": 34,
                    "I2C_SCL": 28,
                    "I2C_SDA": 29,
                },
                "display": {
                    "touch": False,
                    "font": [8, 14],
                    "orientation": [1, 2],
                    "qr_colors": [16904, 61307],
                },
                "sensor": {"flipped": False, "lenses": False},
            },
        }
    )


def board_amigo():
    return mock.MagicMock(
        config={
            "type": "amigo_ips",
            "lcd": {"height": 320, "width": 480, "invert": 1, "dir": 40, "lcd_type": 2},
            "sdcard": {"sclk": 11, "mosi": 10, "miso": 6, "cs": 26},
            "board_info": {
                "BOOT_KEY": 16,
                "LED_R": 14,
                "LED_G": 15,
                "LED_B": 17,
                "LED_W": 32,
                "BACK": 31,
                "ENTER": 23,
                "NEXT": 20,
                "WIFI_TX": 6,
                "WIFI_RX": 7,
                "WIFI_EN": 8,
                "I2S0_MCLK": 13,
                "I2S0_SCLK": 21,
                "I2S0_WS": 18,
                "I2S0_IN_D0": 35,
                "I2S0_OUT_D2": 34,
                "I2C_SDA": 27,
                "I2C_SCL": 24,
                "SPI_SCLK": 11,
                "SPI_MOSI": 10,
                "SPI_MISO": 6,
                "SPI_CS": 12,
            },
            "krux": {
                "pins": {
                    "BUTTON_A": 16,
                    "BUTTON_B": 20,
                    "BUTTON_C": 23,
                    "LED_W": 32,
                    "I2C_SDA": 27,
                    "I2C_SCL": 24,
                },
                "display": {
                    "touch": True,
                    "font": [12, 24],
                    "orientation": [1, 0],
                    "qr_colors": [0, 6342],
                },
                "sensor": {"flipped": True, "lenses": False},
            },
        }
    )


def board_dock():
    return mock.MagicMock(
        config={
            "type": "dock",
            "lcd": {"height": 240, "width": 320, "invert": 0, "lcd_type": 0},
            "sdcard": {"sclk": 27, "mosi": 28, "miso": 26, "cs": 29},
            "board_info": {
                "BOOT_KEY": 16,
                "LED_R": 13,
                "LED_G": 12,
                "LED_B": 14,
                "MIC0_WS": 19,
                "MIC0_DATA": 20,
                "MIC0_BCK": 18,
            },
            "krux": {
                "pins": {"BUTTON_A": 9, "ENCODER": [10, 11]},
                "display": {
                    "touch": False,
                    "font": [8, 16],
                    "orientation": [1, 0],
                    "qr_colors": [0, 6342],
                },
                "sensor": {"flipped": True, "lenses": False},
            },
        }
    )
