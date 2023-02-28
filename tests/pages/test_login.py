import pytest
from ..shared_mocks import mock_context


@pytest.fixture
def mocker_printer(mocker):
    mocker.patch("krux.printers.thermal.AdafruitPrinter", new=mocker.MagicMock())


def create_ctx(mocker, btn_seq, touch_seq=None):
    """Helper to create mocked context obj"""
    ctx = mock_context(mocker)
    ctx.power_manager.battery_charge_remaining.return_value = 1
    ctx.input.wait_for_button = mocker.MagicMock(side_effect=btn_seq)

    if touch_seq:
        ctx.input.touch = mocker.MagicMock(
            current_index=mocker.MagicMock(side_effect=touch_seq)
        )
    return ctx


################### new words from dice tests


def test_new_12w_from_d6(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login, D6_12W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press to proceed to 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D6_12W_MIN_ROLLS)]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to confirm roll string,
            BUTTON_ENTER,  # 1 press to confirm SHA
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_PAGE,  # 1 press to skip passphrase
            BUTTON_ENTER,  # 1 press to select single-key
        ]
    )
    MNEMONIC = "diet glad hat rural panther lawsuit act drop gallery urge where fit"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d6()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_24w_from_d6(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login, D6_24W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press change to 24 words and 1 press to proceed
        [BUTTON_PAGE, BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D6_24W_MIN_ROLLS)]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to confirm roll string,
            BUTTON_ENTER,  # 1 press to confirm SHA
            BUTTON_ENTER,  # 1 press to see the next 12 words (24 total)
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_PAGE,  # 1 press to skip passphrase
            BUTTON_ENTER,  # 1 press to select single-key
        ]
    )
    MNEMONIC = "wheel erase puppy pistol chapter accuse carpet drop quote final attend near scrap satisfy limit style crunch person south inspire lunch meadow enact tattoo"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d6()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_12w_from_d6_on_amigo_device(amigo_tft, mocker, mocker_printer):
    from krux.pages.login import Login, D6_12W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press to proceed to 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D6_12W_MIN_ROLLS)]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to confirm roll string,
            BUTTON_ENTER,  # 1 press to confirm SHA
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_PAGE,
            BUTTON_ENTER,  # 1 press change to btn No and 1 press to proceed (skip passphrase)
            BUTTON_ENTER,  # 1 press to select single-key
        ]
    )
    MNEMONIC = "diet glad hat rural panther lawsuit act drop gallery urge where fit"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d6()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_24w_from_d6_on_amigo_device(amigo_tft, mocker, mocker_printer):
    from krux.pages.login import Login, D6_24W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press change to 24 words and 1 press to proceed
        [BUTTON_PAGE, BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D6_24W_MIN_ROLLS)]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to confirm roll string,
            BUTTON_ENTER,  # 1 press to confirm SHA
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_PAGE,
            BUTTON_ENTER,  # 1 press change to btn No and 1 press to proceed (skip passphrase)
            BUTTON_ENTER,  # 1 press to select single-key
        ]
    )
    MNEMONIC = "wheel erase puppy pistol chapter accuse carpet drop quote final attend near scrap satisfy limit style crunch person south inspire lunch meadow enact tattoo"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d6()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_cancel_new_12w_from_d6_on_amigo_device(amigo_tft, mocker, mocker_printer):
    "Will test the Esc button on the roll screen"
    from krux.pages.login import Login, D6_12W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press to proceed to 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 2 press prev and 1 press on btn Esc
        [BUTTON_PAGE_PREV, BUTTON_PAGE_PREV, BUTTON_ENTER]
        +
        # 1 press to proceed confirm exit msg
        [BUTTON_ENTER]
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d6()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


def test_new_12w_from_d20(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login, D20_12W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press to proceed to 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D20_12W_MIN_ROLLS)]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to confirm roll string,
            BUTTON_ENTER,  # 1 press to confirm SHA
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_PAGE,  # 1 press to skip passphrase
            BUTTON_ENTER,  # 1 press to select single-key
        ]
    )
    MNEMONIC = (
        "erupt remain ride bleak year cabin orange sure ghost gospel husband oppose"
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d20()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_new_24w_from_d20(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login, D20_24W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press change to 24 words and 1 press to proceed
        [BUTTON_PAGE, BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D20_24W_MIN_ROLLS)]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        + [
            BUTTON_ENTER,  # 1 press to confirm roll string,
            BUTTON_ENTER,  # 1 press to confirm SHA
            BUTTON_ENTER,  # 1 press to see the next 12 words (24 total)
            BUTTON_ENTER,  # 1 press to continue loading key
            BUTTON_PAGE,  # 1 press to skip passphrase
            BUTTON_ENTER,  # 1 press to select single-key
        ]
    )
    MNEMONIC = "fun island vivid slide cable pyramid device tuition only essence thought gain silk jealous eternal anger response virus couple faculty ozone test key vocal"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d20()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_cancel_new_12w_from_d20(m5stickv, mocker, mocker_printer):
    "Will test the Deletion button and the minimum roll on the roll screen"
    from krux.pages.login import Login, D20_12W_MIN_ROLLS
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # 1 press to proceed to 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed msg
        [BUTTON_ENTER]
        +
        # 1 presses per roll
        [BUTTON_ENTER for _ in range(D20_12W_MIN_ROLLS)]
        +
        # 3 press prev and 1 press on btn < (delete last roll)
        [BUTTON_PAGE_PREV, BUTTON_PAGE_PREV, BUTTON_PAGE_PREV, BUTTON_ENTER]
        +
        # 1 press prev and 1 press on btn Go
        [BUTTON_PAGE_PREV, BUTTON_ENTER]
        +
        # 1 press for msg not enough rolls!
        [BUTTON_ENTER]
        +
        # 2 press prev and 1 press on btn Esc
        [BUTTON_PAGE_PREV, BUTTON_PAGE_PREV, BUTTON_ENTER]
        +
        # 1 press to proceed confirm exit msg
        [BUTTON_ENTER]
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    login.new_key_from_d20()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)


########## load words from qrcode tests


def test_load_12w_camera_qrcode_words(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = (
        "olympic term tissue route sense program under choose bean emerge velvet absurd"
    )

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login, "capture_qr_code", mocker.MagicMock(return_value=(MNEMONIC, QR_FORMAT))
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_load_12w_camera_qrcode_numbers(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = (
        "olympic term tissue route sense program under choose bean emerge velvet absurd"
    )
    ENCODED_MNEMONIC = "123417871814150815661375189403220156058119360008"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login,
        "capture_qr_code",
        mocker.MagicMock(return_value=(ENCODED_MNEMONIC, QR_FORMAT)),
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_load_12w_camera_qrcode_binary(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "forum undo fragile fade shy sign arrest garment culture tube off merit"
    BINARY_MNEMONIC = b"[\xbd\x9dq\xa8\xecy\x90\x83\x1a\xff5\x9dBeE"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login,
        "capture_qr_code",
        mocker.MagicMock(return_value=(BINARY_MNEMONIC, QR_FORMAT)),
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_load_24w_camera_qrcode_words(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed with the next 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "brush badge sing still venue panther kitchen please help panel bundle excess sign couch stove increase human once effort candy goat top tiny major"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login, "capture_qr_code", mocker.MagicMock(return_value=(MNEMONIC, QR_FORMAT))
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_load_24w_camera_qrcode_numbers(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed with the next 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "brush badge sing still venue panther kitchen please help panel bundle excess sign couch stove increase human once effort candy goat top tiny major"
    ENCODED_MNEMONIC = "023301391610171019391278098413310856127602420628160203911717091708861236056502660800183118111075"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login,
        "capture_qr_code",
        mocker.MagicMock(return_value=(ENCODED_MNEMONIC, QR_FORMAT)),
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_load_24w_camera_qrcode_binary(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_NONE

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to proceed with the next 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_NONE
    MNEMONIC = "attack pizza motion avocado network gather crop fresh patrol unusual wild holiday candy pony ranch winter theme error hybrid van cereal salon goddess expire"
    BINARY_MNEMONIC = b"\x0et\xb6A\x07\xf9L\xc0\xcc\xfa\xe6\xa1=\xcb\xec6b\x15O\xecg\xe0\xe0\t\x99\xc0x\x92Y}\x19\n"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login,
        "capture_qr_code",
        mocker.MagicMock(return_value=(BINARY_MNEMONIC, QR_FORMAT)),
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


def test_load_12w_camera_qrcode_format_ur(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.qr import FORMAT_UR
    import binascii
    from ur.ur import UR

    BTN_SEQUENCE = (
        # 1 press to proceed with the 12 words
        [BUTTON_ENTER]
        +
        # 1 press to skip passphrase
        [BUTTON_PAGE]
        +
        # 1 press to select single-key
        [BUTTON_ENTER]
    )
    QR_FORMAT = FORMAT_UR
    UR_DATA = UR(
        "crypto-bip39",
        bytearray(
            binascii.unhexlify(
                "A2018C66736869656C646567726F75706565726F6465656177616B65646C6F636B6773617573616765646361736865676C6172656477617665646372657765666C616D6565676C6F76650262656E"
            )
        ),
    )
    MNEMONIC = "shield group erode awake lock sausage cash glare wave crew flame glove"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    login = Login(ctx)
    mocker.patch.object(
        login, "capture_qr_code", mocker.MagicMock(return_value=(UR_DATA, QR_FORMAT))
    )
    login.load_key_from_qr_code()

    assert ctx.wallet.key.mnemonic == MNEMONIC


############### load words from text tests


def test_load_key_from_text(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    cases = [
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            + (
                # N
                [BUTTON_PAGE for _ in range(13)]
                + [BUTTON_ENTER]
                +
                # O
                [BUTTON_ENTER]
                +
                # R
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # T
                [BUTTON_ENTER]
                +
                # Go
                [BUTTON_ENTER]
            )
            +
            # Done?, 12 word confirm, No passphrase, Single-key
            [BUTTON_ENTER, BUTTON_ENTER, BUTTON_PAGE, BUTTON_ENTER],
            "ability ability ability ability ability ability ability ability ability ability ability north",
        ),
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            +
            # Go + Confirm word
            [BUTTON_PAGE for _ in range(28)] + [BUTTON_ENTER] + [BUTTON_ENTER] +
            # Done?, 12 word confirm, Continue?, No passphrase, Single-key
            [BUTTON_ENTER, BUTTON_ENTER, BUTTON_PAGE, BUTTON_ENTER],
            "ability ability ability ability ability ability ability ability ability ability ability",
        ),
    ]
    for case in cases:
        ctx = create_ctx(mocker, case[0])
        login = Login(ctx)

        login.load_key_from_text()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        if len(case[1].split()) == 11:
            assert ctx.wallet.key.mnemonic.startswith(case[1])
        else:
            assert ctx.wallet.key.mnemonic == case[1]


def test_load_key_from_text_on_amigo_tft_with_touch(amigo_tft, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV, BUTTON_TOUCH

    cases = [
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            + (
                # N
                [BUTTON_TOUCH]  # index 13 -> "n"
                +
                # Touch on del
                [BUTTON_TOUCH]  # index 26 -> "Del"
                +
                # Invalid Position
                [BUTTON_TOUCH]  # index 29 "empty"
                +
                # N
                [BUTTON_TOUCH]  # index 13 -> "n"
                +
                # O
                [BUTTON_PAGE, BUTTON_PAGE_PREV, BUTTON_ENTER]
                +
                # R going back
                [BUTTON_PAGE_PREV for _ in range(11)]
                + [BUTTON_ENTER]
                +
                # T
                [BUTTON_ENTER]
                +
                # Confirm word <north> -> index 0 (Yes)
                [BUTTON_TOUCH]
            )
            +
            # Done? Confirm, Words correct? Confirm, No passphrase, Single-key
            [
                BUTTON_ENTER,
                BUTTON_ENTER,
                BUTTON_PAGE,
                BUTTON_ENTER,
                BUTTON_ENTER,
            ],
            "ability ability ability ability ability ability ability ability ability ability ability north",
            [13, 26, 29, 13, 0],
        ),
        (
            [BUTTON_ENTER]
            + (
                # A
                [BUTTON_ENTER]
                +
                # B
                [BUTTON_ENTER]
                +
                # I
                [BUTTON_ENTER]
                +
                # Confirm
                [BUTTON_ENTER]
            )
            * 11
            +
            # Move to Go, press Go, confirm word
            [BUTTON_PAGE_PREV] + [BUTTON_ENTER] + [BUTTON_ENTER] +
            # Done? Confirm, Words correct? Confirm, No passphrase, Single-key
            [
                BUTTON_ENTER,
                BUTTON_ENTER,
                BUTTON_PAGE,
                BUTTON_ENTER,
                BUTTON_ENTER,
            ],
            "ability ability ability ability ability ability ability ability ability ability ability",
            [0],
        ),
    ]

    num = 0
    for case in cases:
        print(num)
        num = num + 1

        ctx = create_ctx(mocker, case[0], case[2])

        login = Login(ctx)
        login.load_key_from_text()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        if len(case[1].split()) == 11:
            assert ctx.wallet.key.mnemonic.startswith(case[1])
        else:
            assert ctx.wallet.key.mnemonic == case[1]


############## load words from digits tests


def test_load_key_from_digits(m5stickv, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    cases = [
        (
            [BUTTON_ENTER]  # 1 press confirm msg
            + (
                # 1 press change to number "2" and 1 press to select
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # 10 press to place on btn Go
                [BUTTON_PAGE for _ in range(10)]
                + [
                    BUTTON_ENTER,
                    BUTTON_ENTER,
                ]  # 1 press to select and 1 press to confirm
            )
            * 11  # repeat selection of word=2 (ability) eleven times
            + (
                # 1
                [BUTTON_ENTER]
                +
                # 2
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # 0
                [BUTTON_PAGE for _ in range(11)]
                + [BUTTON_ENTER]
                +
                # 3
                [
                    BUTTON_PAGE,
                    BUTTON_PAGE,
                    BUTTON_PAGE,
                    BUTTON_ENTER,
                ]  # twelve word=1203 (north)
                # Confirm
                + [BUTTON_ENTER]
            )
            +
            # Done?, 12 word confirm, Continue?, No passphrase, Single-key
            [BUTTON_ENTER, BUTTON_ENTER, BUTTON_PAGE, BUTTON_ENTER],
            "ability ability ability ability ability ability ability ability ability ability ability north",
        ),
        (
            [BUTTON_ENTER]
            + (
                # 2
                [BUTTON_PAGE, BUTTON_ENTER]
                +
                # Go + Confirm
                [BUTTON_PAGE for _ in range(10)]
                + [BUTTON_ENTER, BUTTON_ENTER]
            )
            * 11
            +
            # Go + Confirm
            [BUTTON_PAGE for _ in range(11)] + [BUTTON_ENTER] + [BUTTON_ENTER] +
            # Done?, 12 word confirm, Continue?, No passphrase, Single-key
            [BUTTON_ENTER, BUTTON_ENTER, BUTTON_PAGE, BUTTON_ENTER],
            "ability ability ability ability ability ability ability ability ability ability ability",
        ),
    ]
    num = 0
    for case in cases:
        print(num)
        num = num + 1
        ctx = create_ctx(mocker, case[0])
        login = Login(ctx)

        login.load_key_from_digits()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        if len(case[1].split()) == 11:
            assert ctx.wallet.key.mnemonic.startswith(case[1])
        else:
            assert ctx.wallet.key.mnemonic == case[1]


def test_leaving_keypad(mocker, amigo_tft):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    esc_keypad = [
        BUTTON_ENTER,  # Proceed
        BUTTON_PAGE_PREV,  # Move to Go
        BUTTON_PAGE_PREV,  # Move to ESC
        BUTTON_ENTER,  # Press ESC
        BUTTON_ENTER,  # Leave
    ]
    ctx = mock_context(mocker)
    ctx.input.wait_for_button = mocker.MagicMock(side_effect=esc_keypad)

    login = Login(ctx)
    login.load_key_from_text()
    assert ctx.input.wait_for_button.call_count == len(esc_keypad)


def test_passphrase_give_up(mocker, amigo_tft):
    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV

    case = (
        [BUTTON_ENTER]
        + (
            # A
            [BUTTON_ENTER]
            +
            # B
            [BUTTON_ENTER]
            +
            # I
            [BUTTON_ENTER]
            +
            # Confirm
            [BUTTON_ENTER]
        )
        * 11
        +
        # Move to Go, press Go, confirm word
        [BUTTON_PAGE_PREV]
        + [BUTTON_ENTER]
        + [BUTTON_ENTER]
        +
        # Done? Confirm
        [BUTTON_ENTER]
        +
        # Words correct? Confirm
        [BUTTON_ENTER]
        +
        # Passphrase, confirm
        [BUTTON_ENTER]
        +
        # In passphrase keypad:
        [
            BUTTON_PAGE_PREV,  # Move to Go
            BUTTON_PAGE_PREV,  # Move to ESC
            BUTTON_ENTER,  # Press ESC
            BUTTON_ENTER,  # Leave
        ]
    )

    ctx = mock_context(mocker)
    ctx.input.wait_for_button = mocker.MagicMock(side_effect=case)

    login = Login(ctx)
    login.load_key_from_text()
    assert ctx.input.wait_for_button.call_count == len(case)


def test_passphrase(amigo_tft, mocker, mocker_printer):
    from krux.pages.login import Login
    from krux.input import (
        BUTTON_ENTER,
        BUTTON_PAGE_PREV,
        SWIPE_LEFT,
        SWIPE_RIGHT,
    )

    case = (
        [BUTTON_ENTER]
        + (
            # A
            [BUTTON_ENTER]
            +
            # B
            [BUTTON_ENTER]
            +
            # I
            [BUTTON_ENTER]
            +
            # Confirm
            [BUTTON_ENTER]
        )
        * 11
        +
        # Move to Go, press Go, confirm word
        [BUTTON_PAGE_PREV]
        + [BUTTON_ENTER]
        + [BUTTON_ENTER]
        +
        # Done? Confirm
        [BUTTON_ENTER]
        +
        # Words correct? Confirm
        [BUTTON_ENTER]
        +
        # Passphrase, confirm
        [BUTTON_ENTER]
        +
        # In passphrase keypad:
        [
            SWIPE_RIGHT,  # Test keypad swaping
            BUTTON_ENTER,  # Add "+" character
            SWIPE_LEFT,  #
            BUTTON_ENTER,  # Add "a" character
            BUTTON_PAGE_PREV,  # Move to Go
            BUTTON_ENTER,  # Press Go
            BUTTON_ENTER,  # Single key
        ]
    )

    ctx = create_ctx(mocker, case)
    login = Login(ctx)
    login.load_key_from_text()
    assert ctx.input.wait_for_button.call_count == len(case)


# import unittest
# tc = unittest.TestCase()
# tc.assertEqual(Settings().i18n.locale, 'b')


def test_settings(m5stickv, mocker, mocker_printer):
    import krux

    from krux.pages.login import Login
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV
    from krux.krux_settings import Settings, CategorySetting, NumberSetting
    from krux.translations import translation_table

    tlist = list(translation_table)
    index_en = tlist.index("en-US")
    index_next = (index_en + 1) % (len(tlist))
    text_en = translation_table[tlist[index_en]][1177338798] + "\n" + tlist[index_en]
    text_next = (
        translation_table[tlist[index_next]][1177338798] + "\n" + tlist[index_next]
    )

    cases = [
        (
            (
                # Bitcoin
                BUTTON_ENTER,
                # Change network
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Leave Settings
                BUTTON_PAGE_PREV,
                BUTTON_ENTER,
            ),
            [
                mocker.call("Network\nmain"),
                mocker.call("Network\ntest"),
            ],
            lambda: Settings().bitcoin.network == "test",
            CategorySetting,
        ),
        (
            (
                # Printer
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Thermal
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Change Baudrate
                BUTTON_ENTER,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Back to Thermal
                BUTTON_PAGE_PREV,
                BUTTON_ENTER,
                # Back to Printer
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Leave Settings
                BUTTON_PAGE,
                BUTTON_ENTER,
            ),
            [
                mocker.call("Baudrate\n9600"),
                mocker.call("Baudrate\n19200"),
            ],
            lambda: Settings().printer.thermal.adafruit.baudrate == 19200,
            CategorySetting,
        ),
        (
            (
                # Language
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Change Locale
                BUTTON_PAGE,
                BUTTON_ENTER,
            ),
            [
                mocker.call(text_en),
                mocker.call(text_next),
            ],
            lambda: Settings().i18n.locale == tlist[index_next],
            CategorySetting,
        ),
        (
            (
                # Logging
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Change log level
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Leave Settings
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
            ),
            [
                mocker.call("Log Level\nNONE"),
                mocker.call("Log Level\nERROR"),
                mocker.call("Log Level\nWARN"),
                mocker.call("Log Level\nINFO"),
                mocker.call("Log Level\nDEBUG"),
            ],
            lambda: Settings().logging.level == "DEBUG",
            CategorySetting,
        ),
        (
            (
                # Printer
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Thermal
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Paper Width
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Change width
                # Remove digit
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_ENTER,
                # Add 9
                BUTTON_PAGE_PREV,
                BUTTON_PAGE_PREV,
                BUTTON_ENTER,
                # Go
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Back to Thermal
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Back to Printer
                BUTTON_PAGE,
                BUTTON_PAGE,
                BUTTON_ENTER,
                # Leave Settings
                BUTTON_PAGE,
                BUTTON_ENTER,
            ),
            [
                mocker.call("Paper Width", 10),
            ],
            lambda: Settings().printer.thermal.adafruit.paper_width == 389,
            NumberSetting,
        ),
    ]
    case_num = 0
    for case in cases:
        print("test_settings cases[" + str(case_num) + "]")
        case_num = case_num + 1

        ctx = create_ctx(mocker, case[0])
        login = Login(ctx)

        Settings().i18n.locale = "en-US"
        login.settings()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        if case[3] == NumberSetting:
            ctx.display.draw_hcentered_text.assert_has_calls(case[1])
        else:
            ctx.display.draw_centered_text.assert_has_calls(case[1])

        assert case[2]()


def test_settings_on_amigo_tft(amigo_tft, mocker, mocker_printer):
    import krux
    from krux.pages.login import Login
    from krux.input import BUTTON_TOUCH
    from krux.krux_settings import Settings, CategorySetting, NumberSetting

    from krux.translations import translation_table

    tlist = list(translation_table)
    index_en = tlist.index("en-US")
    index_next = (index_en + 1) % (len(tlist))
    text_en = translation_table[tlist[index_en]][1177338798] + "\n" + tlist[index_en]
    text_next = (
        translation_table[tlist[index_next]][1177338798] + "\n" + tlist[index_next]
    )

    PREV_INDEX = 0
    GO_INDEX = 1
    NEXT_INDEX = 2

    cases = [
        (
            (
                # Bitcoin
                0,
                # Change network
                NEXT_INDEX,
                GO_INDEX,
                # Leave Settings
                4,
            ),
            [
                mocker.call("Network\nmain"),
                mocker.call("Network\ntest"),
            ],
            lambda: Settings().bitcoin.network == "test",
            CategorySetting,
        ),
        (
            (
                # Printer
                3,
                # Thermal
                1,
                # Change Baudrate
                0,
                NEXT_INDEX,
                GO_INDEX,
                # Back to Thermal
                7,
                # Back to Printer
                3,
                # Leave Settings
                4,
            ),
            [
                mocker.call("Baudrate\n9600"),
                mocker.call("Baudrate\n19200"),
            ],
            lambda: Settings().printer.thermal.adafruit.baudrate == 19200,
            CategorySetting,
        ),
        (
            (
                # Language
                1,
                # Change Locale
                NEXT_INDEX,
                GO_INDEX,
            ),
            [
                mocker.call(text_en),
                mocker.call(text_next),
            ],
            lambda: Settings().i18n.locale == tlist[index_next],
            CategorySetting,
        ),
        (
            (
                # Logging
                2,
                # Change log level
                NEXT_INDEX,
                NEXT_INDEX,
                NEXT_INDEX,
                NEXT_INDEX,
                GO_INDEX,
                # Leave Settings
                4,
            ),
            [
                mocker.call("Log Level\nNONE"),
                mocker.call("Log Level\nERROR"),
                mocker.call("Log Level\nWARN"),
                mocker.call("Log Level\nINFO"),
                mocker.call("Log Level\nDEBUG"),
            ],
            lambda: Settings().logging.level == "DEBUG",
            CategorySetting,
        ),
    ]
    case_num = 0
    for case in cases:
        print("test_settings_on_amigo_tft cases[" + str(case_num) + "]")
        case_num = case_num + 1

        ctx = mock_context(mocker)
        ctx.power_manager.battery_charge_remaining.return_value = 1
        ctx.input.wait_for_button = mocker.MagicMock(return_value=BUTTON_TOUCH)
        ctx.input.touch = mocker.MagicMock(
            current_index=mocker.MagicMock(side_effect=case[0])
        )

        mocker.patch.object(ctx.input.touch, "x_regions", (0, 100, 200, 300))
        mocker.patch.object(ctx.input.touch, "y_regions", (100, 200))

        login = Login(ctx)

        Settings().i18n.locale = "en-US"
        login.settings()

        assert ctx.input.wait_for_button.call_count == len(case[0])
        if case[3] == NumberSetting:
            ctx.display.draw_hcentered_text.assert_has_calls(case[1])
        else:
            ctx.display.draw_centered_text.assert_has_calls(case[1])

        assert case[2]()


def test_about(mocker, m5stickv):
    import krux

    from krux.pages.login import Login
    from krux.metadata import VERSION
    from krux.input import BUTTON_ENTER

    ctx = mock_context(mocker)
    ctx.input.wait_for_button = mocker.MagicMock(return_value=BUTTON_ENTER)
    ctx.input.wait_for_button = mocker.MagicMock(return_value=BUTTON_ENTER)

    login = Login(ctx)

    login.about()

    ctx.input.wait_for_button.assert_called_once()
    ctx.display.draw_centered_text.assert_called_with("Krux\n\n\nVersion\n" + VERSION)
