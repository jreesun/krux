import sys
import pytest
from unittest import mock
from unittest.mock import patch
from Crypto.Cipher import AES
from ..shared_mocks import mock_context

if "ucryptolib" not in sys.modules:
    sys.modules["ucryptolib"] = mock.MagicMock(
        aes=AES.new, MODE_ECB=AES.MODE_ECB, MODE_CBC=AES.MODE_CBC
    )

TEST_KEY = "test key"
CBC_WORDS = "dog guitar hotel random owner gadget salute riot patrol work advice panic erode leader pass cross section laundry elder asset soul scale immune scatter"
ECB_WORDS = "brass creek fuel snack era success impulse dirt caution purity lottery lizard boil festival neither case swift smooth range mail gravity sample never ivory"
I_VECTOR = b"OR\xa1\x93l>2q \x9e\x9dd\x05\x9e\xd7\x8e"
SEEDS_JSON = """{
    "ecbID": {
        "version": 0,
        "key_iterations": 100000,
        "data": "sMCvAUvVpGSCsXsBl7EBNGPZLymZoyB8eAUHb2TMbarhqD4GJga/SW/AstxIvZz6MR1opXLfF7Pyd+IJBe3E0lDQCkvqytSQfVGnVSeYz+sNfd5T1CXS0/C2zYKTKFL7RTpHd0IXHZ+GQuzX1hoJMHkh0sx0VgorVdDj87ykUQIeC95MS98y/ha2q/vWfLyIZU1hc5VcehzmTA1B6ExMGA=="
    },
    "cbcID": {
        "version": 1,
        "key_iterations": 100000,
        "data": "GpNxj9kzdiTuIf1UYC6R0FHoUokBhiNLkxWgSOHBhmBHb0Ew8wk1M+VlsR4v/koCfSGOTkgjFshC36+n7mx0W0PI6NizAoPClO8DUVamd5hS6irS+Lfff0//VJWK1BcdvOJjzYw8TBiVaL1swAEEySjn5GsqF1RaJXzAMMgu03Kq32iDIDy7h/jHJTiIPCoVQAle/C9vXq2HQeVx43c0LhGXTZmIhhkHPMgDzFTsMGM="
    }
}"""


@pytest.fixture
def mock_file_operations(mocker):
    mocker.patch(
        "os.listdir",
        new=mocker.MagicMock(return_value=["somefile", "otherfile"]),
    )
    mocker.patch("builtins.open", mocker.mock_open(read_data="SEEDS_JSON"))


def create_ctx(mocker, btn_seq):
    """Helper to create mocked context obj"""
    ctx = mock_context(mocker)
    ctx.power_manager.battery_charge_remaining.return_value = 1
    ctx.input.wait_for_button = mocker.MagicMock(side_effect=btn_seq)
    return ctx


def test_load_key_from_keypad(m5stickv, mocker):
    from krux.pages.encryption_ui import EncryptionKey
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # choose to type key
        + [BUTTON_PAGE]  # go to letter b
        + [BUTTON_ENTER]  # enter letter b
        + [BUTTON_PAGE_PREV] * 2  # move to "Go"
        + [BUTTON_ENTER]  # Go
        + [BUTTON_ENTER]  # Confirm
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    key_generator = EncryptionKey(ctx)
    key = key_generator.encryption_key()
    assert key == "b"


def test_load_key_from_qr_code(m5stickv, mocker):
    from krux.pages.encryption_ui import EncryptionKey, ENCRYPTION_KEY_MAX_LEN
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    BTN_SEQUENCE = (
        [BUTTON_PAGE]  # move to QR code key
        + [BUTTON_ENTER]  # choose QR code key
        + [BUTTON_ENTER]  # Confirm
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    key_generator = EncryptionKey(ctx)
    mocker.patch.object(
        key_generator,
        "capture_qr_code",
        mocker.MagicMock(return_value=(("qr key", None))),
    )
    key = key_generator.encryption_key()
    assert key == "qr key"

    # Repeat with too much characters >ENCRYPTION_KEY_MAX_LEN
    BTN_SEQUENCE = [BUTTON_PAGE] + [  # move to QR code key
        BUTTON_ENTER
    ]  # choose QR code key
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    key_generator = EncryptionKey(ctx)
    too_long_text = "l" * (ENCRYPTION_KEY_MAX_LEN + 1)
    mocker.patch.object(
        key_generator,
        "capture_qr_code",
        mocker.MagicMock(return_value=((too_long_text, None))),
    )
    key = key_generator.encryption_key()
    assert key == None


def test_encrypt_cbc_sd_ui(m5stickv, mocker, mock_file_operations):
    from krux.wallet import Wallet
    from krux.krux_settings import Settings
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV
    from krux.pages.encryption_ui import EncryptMnemonic
    from krux.key import Key
    from embit.networks import NETWORKS

    BTN_SEQUENCE = (
        [BUTTON_PAGE]  # Move to store on SD card
        + [BUTTON_ENTER]  # Confirm SD card
        + [BUTTON_ENTER]  # Confirm add CBC cam entropy
        + [BUTTON_PAGE]  # add custom ID - move to no
        + [BUTTON_ENTER]  # Confirm encryption ID
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    ctx.wallet = Wallet(Key(CBC_WORDS, False, NETWORKS["main"]))
    storage_ui = EncryptMnemonic(ctx)
    mocker.patch(
        "krux.pages.encryption_ui.EncryptionKey.encryption_key",
        mocker.MagicMock(return_value=TEST_KEY),
    )
    mocker.patch(
        "krux.pages.encryption_ui.EncryptMnemonic.capture_camera_entropy",
        mocker.MagicMock(return_value=I_VECTOR),
    )
    with patch("krux.sd_card.open", mocker.mock_open(read_data="{}")) as m:
        Settings().encryption.version = "AES-CBC"
        storage_ui.encrypt_menu()

    ctx.display.draw_centered_text.assert_has_calls(
        [mocker.call("Encrypted mnemonic was stored with ID: 353175d8")], any_order=True
    )


def test_encrypt_to_qrcode_ecb_ui(m5stickv, mocker):
    from krux.wallet import Wallet
    from krux.krux_settings import Settings
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.pages.encryption_ui import EncryptMnemonic
    from krux.key import Key
    from embit.networks import NETWORKS

    BTN_SEQUENCE = (
        [BUTTON_PAGE]  # Move to store on Encrypted QR
        + [BUTTON_ENTER]  # Confirm Encrypted QR
        + [BUTTON_PAGE]  # add custom ID - No
        + [BUTTON_ENTER]  # Confirm and leave
        + [BUTTON_ENTER]  # Confirm sure to leave
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    ctx.wallet = Wallet(Key(ECB_WORDS, False, NETWORKS["main"]))
    ctx.printer = None
    storage_ui = EncryptMnemonic(ctx)
    mocker.patch(
        "krux.pages.encryption_ui.EncryptionKey.encryption_key",
        mocker.MagicMock(return_value=TEST_KEY),
    )
    with patch("krux.sd_card.open", mocker.mock_open(read_data="{}")) as m:
        Settings().encryption.version = "AES-ECB"
        storage_ui.encrypt_menu()

    # TODO: Assertions


def test_encrypt_to_qrcode_cbc_ui(m5stickv, mocker):
    from krux.wallet import Wallet
    from krux.krux_settings import Settings
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.pages.encryption_ui import EncryptMnemonic
    from krux.key import Key
    from embit.networks import NETWORKS

    BTN_SEQUENCE = (
        [BUTTON_PAGE]  # Move to store on Encrypted QR
        + [BUTTON_ENTER]  # Confirm Encrypted QR
        + [BUTTON_ENTER]  # Confirm add CBC cam entropy
        + [BUTTON_PAGE]  # add custom ID - No
        + [BUTTON_ENTER]  # Confirm and leave
        + [BUTTON_ENTER]  # Confirm sure to leave
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    ctx.wallet = Wallet(Key(CBC_WORDS, False, NETWORKS["main"]))
    ctx.printer = None
    storage_ui = EncryptMnemonic(ctx)
    mocker.patch(
        "krux.pages.encryption_ui.EncryptionKey.encryption_key",
        mocker.MagicMock(return_value=TEST_KEY),
    )
    mocker.patch(
        "krux.pages.encryption_ui.EncryptMnemonic.capture_camera_entropy",
        mocker.MagicMock(return_value=I_VECTOR),
    )
    with patch("krux.sd_card.open", mocker.mock_open(read_data="{}")) as m:
        Settings().encryption.version = "AES-CBC"
        storage_ui.encrypt_menu()

    # TODO: Assertions


def test_load_encrypted_from_flash(m5stickv, mocker):
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.pages.encryption_ui import LoadEncryptedMnemonic

    BTN_SEQUENCE = [BUTTON_ENTER]  # First mnemonic
    mocker.patch(
        "krux.pages.encryption_ui.EncryptionKey.encryption_key",
        mocker.MagicMock(return_value=TEST_KEY),
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    with patch("krux.encryption.open", new=mocker.mock_open(read_data=SEEDS_JSON)) as m:
        encrypted_mnemonics = LoadEncryptedMnemonic(ctx)
        words = encrypted_mnemonics.load_from_storage()
    assert words == ECB_WORDS.split()


def test_load_encrypted_from_sd(m5stickv, mocker, mock_file_operations):
    from krux.input import BUTTON_ENTER, BUTTON_PAGE
    from krux.pages.encryption_ui import LoadEncryptedMnemonic

    BTN_SEQUENCE = [BUTTON_ENTER]  # First mnemonic
    mocker.patch(
        "krux.pages.encryption_ui.EncryptionKey.encryption_key",
        mocker.MagicMock(return_value=TEST_KEY),
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    with patch("krux.sd_card.open", new=mocker.mock_open(read_data=SEEDS_JSON)) as m:
        encrypted_mnemonics = LoadEncryptedMnemonic(ctx)
        words = encrypted_mnemonics.load_from_storage()
    assert words == ECB_WORDS.split()


def test_load_encrypted_from_flash_wrong_key(m5stickv, mocker):
    from krux.input import BUTTON_ENTER, BUTTON_PAGE_PREV
    from krux.pages.encryption_ui import LoadEncryptedMnemonic
    from krux.pages import MENU_CONTINUE

    BTN_SEQUENCE = (
        [BUTTON_ENTER]  # First mnemonic
        + [BUTTON_ENTER]  # Fail to decrypt
        + [BUTTON_PAGE_PREV]  # Go to back
        + [BUTTON_ENTER]  # Leave
    )
    mocker.patch(
        "krux.pages.encryption_ui.EncryptionKey.encryption_key",
        mocker.MagicMock(return_value="wrong key"),
    )
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    with patch("krux.encryption.open", new=mocker.mock_open(read_data=SEEDS_JSON)) as m:
        encrypted_mnemonics = LoadEncryptedMnemonic(ctx)
        words = encrypted_mnemonics.load_from_storage()
    assert words == MENU_CONTINUE