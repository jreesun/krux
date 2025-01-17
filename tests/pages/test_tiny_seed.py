from ..shared_mocks import MockPrinter, snapshot_generator
from .home_pages.test_home import tdata, create_ctx


def test_export_mnemonic_tiny_seed_menu(mocker, m5stickv, tdata):
    from krux.pages.home_pages.mnemonic_backup import MnemonicsView
    from krux.wallet import Wallet
    from krux.input import BUTTON_ENTER, BUTTON_PAGE

    case = [
        Wallet(tdata.SINGLESIG_24_WORD_KEY),
        MockPrinter(),
        [
            BUTTON_PAGE,
            BUTTON_PAGE,
            BUTTON_ENTER,  # Other
            BUTTON_PAGE,
            BUTTON_PAGE,
            BUTTON_PAGE,
            BUTTON_ENTER,  # Open TinySeed
            BUTTON_ENTER,  # PG2
            BUTTON_ENTER,  # Leave
            BUTTON_ENTER,  # Print
            BUTTON_PAGE,  # Go to "Back"
            BUTTON_ENTER,  # click on back to return Mnemonic Backup
            BUTTON_PAGE,
            BUTTON_ENTER,  # click on back to return to home init screen
        ],
    ]
    ctx = create_ctx(mocker, case[2], case[0], case[1])
    mnemonics = MnemonicsView(ctx)
    mocker.spy(mnemonics, "tiny_seed")
    mnemonics.mnemonic()
    mnemonics.tiny_seed.assert_called_once()
    assert ctx.input.wait_for_button.call_count == len(case[2])


def test_export_tiny_seed(m5stickv, mocker):
    from krux.pages.tiny_seed import TinySeed
    from krux.input import BUTTON_ENTER
    from krux.wallet import Wallet
    from krux.key import Key, TYPE_SINGLESIG
    from embit.networks import NETWORKS

    BTN_SEQUENCE = [
        BUTTON_ENTER,  # Page 1
        BUTTON_ENTER,  # Page 2
        BUTTON_ENTER,  # Print - yes
    ]
    TEST_24_WORD_MNEMONIC = "brush badge sing still venue panther kitchen please help panel bundle excess sign couch stove increase human once effort candy goat top tiny major"
    # Amount of rectangles filled for this mnemonic + menus
    FILLED_RECTANGLES = 137
    SINGLESIG_24_WORD_KEY = Key(TEST_24_WORD_MNEMONIC, TYPE_SINGLESIG, NETWORKS["main"])
    ctx = create_ctx(mocker, BTN_SEQUENCE, Wallet(SINGLESIG_24_WORD_KEY), MockPrinter())
    tiny_seed = TinySeed(ctx)
    tiny_seed.export()

    assert ctx.display.fill_rectangle.call_count == FILLED_RECTANGLES


def test_enter_tiny_seed_12w_m5stickv(m5stickv, mocker):
    from krux.pages.tiny_seed import TinySeed
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # Toggle line 1 bit "1024"
        [BUTTON_PAGE]
        + [BUTTON_ENTER]
        # Move to last editable bit and togle
        + [BUTTON_PAGE_PREV] * 4
        + [BUTTON_ENTER]
        # Move to line 2 and toggle bit "512"
        + [BUTTON_PAGE] * 17
        + [BUTTON_ENTER]
        # Move to line 3 and toggle bit "512"
        + [BUTTON_PAGE] * 12
        + [BUTTON_ENTER]
        # Press Enter to toggle again and reset line 3 to 2048 word
        + [BUTTON_ENTER]
        # Move to line 1 , toggle bit 2048 to reset line 1
        + [BUTTON_PAGE_PREV] * 26
        + [BUTTON_ENTER]
        # Move to "Go" and proceed
        + [BUTTON_PAGE_PREV]
        + [BUTTON_ENTER]
    )
    TEST_12_WORDS = "zoo divide zoo zoo zoo zoo zoo zoo zoo zoo zoo crouch"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    tiny_seed = TinySeed(ctx)
    words = tiny_seed.enter_tiny_seed()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert " ".join(words) == TEST_12_WORDS


def test_enter_tiny_seed_24w_m5stickv(m5stickv, mocker):
    from krux.pages.tiny_seed import TinySeed
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # Toggle line 1 bit "1024"
        [BUTTON_PAGE]
        + [BUTTON_ENTER]
        # Move to last editable bit and togle
        + [BUTTON_PAGE_PREV] * 4
        + [BUTTON_ENTER]
        # Move to line 2 and toggle bit "512"
        + [BUTTON_PAGE] * 17
        + [BUTTON_ENTER]
        # Move to "Go" and proceed to next page
        + [BUTTON_PAGE_PREV] * 15
        + [BUTTON_ENTER]
        # Toggle line 1 bit "256"
        + [BUTTON_PAGE] * 4
        + [BUTTON_ENTER]
        # Move to last editable bit and togle
        + [BUTTON_PAGE_PREV] * 6
        + [BUTTON_ENTER]
        # Move to "Go" and proceed
        + [BUTTON_PAGE] * 2
        + [BUTTON_ENTER]
    )
    TEST_24_WORDS = "lend divide zoo zoo zoo zoo zoo zoo zoo zoo zoo abandon cable zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo core"

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    tiny_seed = TinySeed(ctx)
    words = tiny_seed.enter_tiny_seed(w24=True)

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert " ".join(words) == TEST_24_WORDS


def test_enter_tiny_seed_24w_amigo(amigo, mocker):
    from krux.pages.tiny_seed import TinySeed, TS_GO_POSITION, TS_ESC_START_POSITION
    from krux.input import BUTTON_TOUCH

    TOUCH_SEQUENCE = (
        # Toggle line 1 bit "1024"
        [1]
        # Toggle last editable bit
        + [143]
        # On line 2 and toggle bit "512"
        + [14]
        # "Go" and proceed to next page
        + [TS_GO_POSITION]
        # Toggle line 1 bit "256"
        + [3]
        # Toggle to last editable bit
        + [135]
        # Press ESC
        + [TS_ESC_START_POSITION]
        # Give up from ESC
        + [0]  # Press "No"
        # "Go" and proceed
        + [TS_GO_POSITION]
    )
    BTN_SEQUENCE = [BUTTON_TOUCH] * len(TOUCH_SEQUENCE)

    TEST_24_WORDS = "lend divide zoo zoo zoo zoo zoo zoo zoo zoo zoo abandon cable zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo core"

    ctx = create_ctx(mocker, BTN_SEQUENCE, touch_seq=TOUCH_SEQUENCE)
    tiny_seed = TinySeed(ctx)
    words = tiny_seed.enter_tiny_seed(w24=True)

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert " ".join(words) == TEST_24_WORDS


def test_enter_tiny_seed_24w_pre_loaded_numbers(m5stickv, mocker):
    # This will be used when scanning 24 TinySeed
    # First scanned page will be loaded to be edited, then proceed to scan second page
    # Seed will be returned as its word index
    from krux.pages.tiny_seed import TinySeed
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV

    BTN_SEQUENCE = (
        # [BUTTON_ENTER]
        # Toggle line 1 bit "1024"
        [BUTTON_PAGE] * 2
        + [BUTTON_ENTER]
        # Move to last editable bit from page 1 and togle
        + [BUTTON_PAGE_PREV] * 4
        + [BUTTON_ENTER]
        # Move to line 2 and toggle bit "512"
        + [BUTTON_PAGE] * 17
        + [BUTTON_ENTER]
        # Move to "Go" and proceed to scan second page
        + [BUTTON_PAGE_PREV] * 15
        + [BUTTON_ENTER]
    )
    TEST_12_WORDS = [
        1025,
        513,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        2048,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
    ]

    ctx = create_ctx(mocker, BTN_SEQUENCE)
    tiny_seed = TinySeed(ctx)
    words = tiny_seed.enter_tiny_seed(w24=True, seed_numbers=[1] * 24, scanning_24=True)

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert words == TEST_12_WORDS


def test_scan_tiny_seed_12w(m5stickv, mocker):
    # This will be used when scanning 24 TinySeed
    # First scanned page will be loaded to be edited, then proceed to scan second page
    # Seed will be returned as its word index
    # TinySeed will be mocked with MockStats
    # Punched values will be returned values under 0x80
    import time
    from krux.pages.tiny_seed import TinyScanner
    from krux.input import BUTTON_ENTER
    from krux.camera import OV7740_ID

    BTN_SEQUENCE = [BUTTON_ENTER] + [BUTTON_ENTER]  # Intro  # Check OK
    TIME_STAMPS = (0, 1, 100)
    TEST_12_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    mocker.patch.object(time, "ticks_ms", mocker.MagicMock(side_effect=TIME_STAMPS))
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    tiny_seed = TinyScanner(ctx)
    mocker.patch.object(ctx.camera, "snapshot", new=snapshot_generator())
    ctx.camera.cam_id = OV7740_ID
    tiny_seed._gradient_corners = mocker.MagicMock(return_value=(50, 50, 50, 50))
    mocker.patch.object(tiny_seed, "_check_buttons", new=lambda w24, page: None)
    words = tiny_seed.scanner()

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert " ".join(words) == TEST_12_WORDS


def test_scan_tiny_seed_24w(multiple_devices, mocker):
    # This will be used when scanning 24 TinySeed
    # First scanned page will be loaded to be edited, then proceed to scan second page
    # Seed will be returned as its word index
    import time
    from krux.pages.tiny_seed import TinyScanner
    from krux.input import BUTTON_ENTER

    BTN_SEQUENCE = [BUTTON_ENTER] + [BUTTON_ENTER]  # Intro  # Check OK
    ENTER_SEQ = [False] + [True] + [False] * 3
    TIME_STAMPS = (0, 1, 1000, 2000, 3000, 4000, 5000)
    TINYSEED_RECTANGLE = (10, 10, 100, 100)
    TEST_WORDS_NUMBERS_1_12 = [
        1090,
        792,
        1005,
        1978,
        408,
        569,
        1498,
        589,
        192,
        134,
        617,
        663,
    ]
    TEST_WORDS_NUMBERS_13_24 = [
        1275,
        1982,
        1747,
        978,
        509,
        1588,
        1456,
        15,
        1592,
        1612,
        1056,
        771,
    ]
    NUMBERS_SEQUENCE = [TEST_WORDS_NUMBERS_1_12] * 3 + [TEST_WORDS_NUMBERS_13_24] * 2
    TEST_24_WORDS = "market glass laugh warm cream either robot end blood awful escape fan palm waste surge kick display shoe remove achieve shoulder siren loop gate"
    mocker.patch.object(time, "ticks_ms", mocker.MagicMock(side_effect=TIME_STAMPS))
    ctx = create_ctx(mocker, BTN_SEQUENCE)
    mocker.patch.object(ctx.input, "page_event", new=lambda: False)
    mocker.patch.object(ctx.input, "page_prev_event", new=lambda: False)
    ctx.input.enter_event = mocker.MagicMock(side_effect=ENTER_SEQ)
    tiny_seed = TinyScanner(ctx)
    mocker.patch.object(
        tiny_seed, "_detect_tiny_seed", new=lambda image: TINYSEED_RECTANGLE
    )
    tiny_seed._detect_and_draw_punches = mocker.MagicMock(side_effect=NUMBERS_SEQUENCE)
    words = tiny_seed.scanner(w24=True)

    assert ctx.input.wait_for_button.call_count == len(BTN_SEQUENCE)
    assert " ".join(words) == TEST_24_WORDS


def test_tinyscanner_initializes_tinyseed_with_label(multiple_devices, mocker):
    import pytest
    from krux.pages.tiny_seed import TinyScanner

    test_cases = [
        # TinyScanner grid_type param, expected exception, expected TinySeed label
        (None, None, "Tiny Seed"),
        ("Tiny Seed", None, "Tiny Seed"),
        ("OneKey KeyTag", None, "OneKey KeyTag"),
        ("Binary Grid", None, "Binary Grid"),
        ("Unsupported Format", KeyError, None),
    ]

    for i, (grid_type, expected_exception, expected_label) in enumerate(test_cases):
        print(i, (grid_type, expected_exception, expected_label))
        ctx = create_ctx(mocker, [])
        if not expected_exception:
            if grid_type:
                tiny_scanner = TinyScanner(ctx, grid_type=grid_type)
            else:
                tiny_scanner = TinyScanner(ctx)
            assert tiny_scanner.tiny_seed.label == expected_label
        else:
            with pytest.raises(expected_exception):
                tiny_scanner = TinyScanner(ctx, grid_type=grid_type)
