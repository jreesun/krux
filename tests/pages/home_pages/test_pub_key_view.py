from .. import create_ctx
from .test_home import tdata


def test_public_key(mocker, m5stickv, tdata):
    from krux.pages.home_pages.pub_key_view import PubkeyView
    from krux.wallet import Wallet
    from krux.input import BUTTON_ENTER, BUTTON_PAGE, BUTTON_PAGE_PREV
    from krux.qr import FORMAT_NONE
    from krux.key import TYPE_MULTISIG

    cases = [
        # Case parameters: [Wallet, Printer, Button Sequence, Show XPUB, Show ZPUB]
        # 0 - Singlesig - Show all text and QR codes
        (
            Wallet(tdata.SINGLESIG_12_WORD_KEY),
            None,
            [
                BUTTON_ENTER,  # Enter XPUB - Text
                BUTTON_PAGE,  # move to Back
                BUTTON_ENTER,  # Press Back
                BUTTON_PAGE,  # move to XPUB - QR Code
                BUTTON_ENTER,  # Enter XPUB - QR Code
                BUTTON_ENTER,  # Enter QR Menu
                BUTTON_PAGE_PREV,  # move to Back to Menu
                BUTTON_ENTER,  # Press Back to Menu
                BUTTON_PAGE,  # move to XPUB - QR Code
                BUTTON_PAGE,  # move to ZPUB - Text
                BUTTON_PAGE,  # move to ZPUB - QR Code
                BUTTON_ENTER,  # Enter ZPUB - QR Code
                BUTTON_ENTER,  # Enter QR Menu
                BUTTON_PAGE_PREV,  # move to Back to Menu
                BUTTON_ENTER,  # Press Back to Menu
                BUTTON_PAGE_PREV,  # Move Back
                BUTTON_ENTER,  # Press Back to leave
            ],
            True,
            True,
        ),
        # 1 - Multisig - Show all text and QR codes
        (
            Wallet(tdata.MULTISIG_12_WORD_KEY),
            None,
            [
                BUTTON_ENTER,  # Enter XPUB - Text
                BUTTON_PAGE,  # move to Back
                BUTTON_ENTER,  # Press Back
                BUTTON_PAGE,  # move to XPUB - QR Code
                BUTTON_ENTER,  # Enter XPUB - QR Code
                BUTTON_ENTER,  # Enter QR Menu
                BUTTON_PAGE_PREV,  # move to Back to Menu
                BUTTON_ENTER,  # Press Back to Menu
                BUTTON_PAGE,  # move to XPUB - QR Code
                BUTTON_PAGE,  # move to ZPUB - Text
                BUTTON_PAGE,  # move to ZPUB - QR Code
                BUTTON_ENTER,  # Enter ZPUB - QR Code
                BUTTON_ENTER,  # Enter QR Menu
                BUTTON_PAGE_PREV,  # move to Back to Menu
                BUTTON_ENTER,  # Press Back to Menu
                BUTTON_PAGE_PREV,  # Move Back
                BUTTON_ENTER,  # Press Back to leave
            ],
            True,
            True,
        ),
        # TODO: Create cases were not all text and QR codes are shown
    ]
    num = 0

    for case in cases:
        print(num)
        num += 1
        mock_seed_qr_view = mocker.patch(
            "krux.pages.qr_view.SeedQRView"
        )  # Mock SeedQRView
        ctx = create_ctx(mocker, case[2], case[0], case[1])
        pub_key_viewer = PubkeyView(ctx)

        pub_key_viewer.public_key()

        version = "Zpub" if ctx.wallet.key.policy_type == TYPE_MULTISIG else "zpub"
        qr_view_calls = []
        print_qr_calls = []

        if case[3]:  # Show XPUB
            qr_view_calls.append(
                mocker.call(
                    ctx,
                    data=ctx.wallet.key.key_expression(None),
                    title="XPUB",
                ),
            )
            print_qr_calls.append(
                mocker.call(
                    ctx.wallet.key.key_expression(None),
                    FORMAT_NONE,
                    "XPUB",
                ),
            )
        if case[4]:  # Show ZPUB
            qr_view_calls.append(
                mocker.call(
                    ctx,
                    data=ctx.wallet.key.key_expression(ctx.wallet.key.network[version]),
                    title="ZPUB",
                ),
            )
            print_qr_calls.append(
                mocker.call(
                    ctx.wallet.key.key_expression(ctx.wallet.key.network[version]),
                    FORMAT_NONE,
                    "ZPUB",
                ),
            )

        # Assert SeedQRView was initialized with the correct parameters
        mock_seed_qr_view.assert_has_calls(qr_view_calls, any_order=True)

        # TODO: Assert XPUB and ZPUB text was displayed

        assert ctx.input.wait_for_button.call_count == len(case[2])
