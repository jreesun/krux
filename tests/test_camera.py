from .shared_mocks import (
    snapshot_generator,
    MockQRPartParser,
    SNAP_SUCCESS,
    SNAP_REPEAT_QRCODE,
    # TODO: fix W0611: Unused SNAP_HISTOGRAM_FAIL imported from shared_mocks
    # this will be used in a near future or can be removed?
    # SNAP_HISTOGRAM_FAIL,
    SNAP_FIND_QRCODES_FAIL,
    IMAGE_TO_HASH,
)


# pylint: disable=unused-argument
def test_init(mocker, m5stickv):
    """
    Test camera initialization in a mocked m5stickv device

    :param mocker
    :param m5stickv
    """
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()
    camera.initialize_sensor()

    assert isinstance(camera, Camera)


# pylint: disable=unused-argument
def test_initialize_sensor(mocker, m5stickv):
    """
    Test camera sensor initialization in a mocked m5stickv device:
    - calling reset sensor
    - setup of pixformat
    - setup framesize

    :param mocker
    :param m5stickv
    """
    import krux
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()

    camera.initialize_sensor()

    krux.camera.sensor.reset.assert_called()
    krux.camera.sensor.set_pixformat.assert_called()
    assert (
        # TODO: fix W0212: Access to a protected member _extract_mock_name of a client class
        # pylint: disable=protected-access
        krux.camera.sensor.set_pixformat.call_args.args[0]._extract_mock_name()
        == "mock.RGB565"
    )
    krux.camera.sensor.set_framesize.assert_called()
    assert (
        # TODO: fix W0212: Access to a protected member _extract_mock_name of a client class
        # pylint: disable=protected-access
        krux.camera.sensor.set_framesize.call_args.args[0]._extract_mock_name()
        == "mock.QVGA"
    )


# pylint: disable=unused-argument
def test_capture_qr_code_loop(mocker, m5stickv):
    """
    Test mocked camera snapshot of a mocked qrcode:
    - capture a qrcode
    - check results

    :param mocker
    :param m5stickv
    """
    mocker.patch(
        "krux.camera.sensor.snapshot", new=snapshot_generator(outcome=SNAP_SUCCESS)
    )
    mocker.patch("krux.camera.QRPartParser", new=MockQRPartParser)
    import krux
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()

    prev_parsed_count = -1

    def progress_callback(total_count, parsed_count, is_new):
        if parsed_count == 0:
            krux.camera.sensor.run.assert_called_with(1)
        nonlocal prev_parsed_count
        assert parsed_count > prev_parsed_count
        if parsed_count > 0:
            assert is_new
            assert total_count == MockQRPartParser.TOTAL
        prev_parsed_count = parsed_count
        return False

    # TODO: fix W0622: Redefining built-in 'format'
    # pylint: disable=redefined-builtin
    result, format = camera.capture_qr_code_loop(progress_callback)
    assert result == "12345678910"
    assert format == MockQRPartParser.FORMAT
    assert prev_parsed_count == MockQRPartParser.TOTAL - 1
    krux.camera.sensor.run.assert_called_with(0)
    krux.camera.wdt.feed.assert_called()


# pylint: disable=unused-argument
def test_capture_qr_code_loop_returns_early_when_requested(mocker, m5stickv):
    """
    Test mocked camera snapshot of a mocked qrcode with o None result
    - capture a qrcode
    - check results

    :param mocker
    :param m5stickv
    """
    mocker.patch(
        "krux.camera.sensor.snapshot", new=snapshot_generator(outcome=SNAP_SUCCESS)
    )
    mocker.patch("krux.camera.QRPartParser", new=MockQRPartParser)
    import krux
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()

    prev_parsed_count = -1

    def progress_callback(total_count, parsed_count, is_new):
        if parsed_count == 0:
            krux.camera.sensor.run.assert_called_with(1)
        nonlocal prev_parsed_count
        assert parsed_count > prev_parsed_count
        if parsed_count > 0:
            assert is_new
            assert total_count == MockQRPartParser.TOTAL
        prev_parsed_count = parsed_count
        return True

    # TODO: fix W0622: Redefining built-in 'format'
    # pylint: disable=redefined-builtin
    result, format = camera.capture_qr_code_loop(progress_callback)
    assert result is None
    assert format is None
    assert prev_parsed_count < MockQRPartParser.TOTAL - 1
    krux.camera.sensor.run.assert_called_with(0)
    krux.camera.wdt.feed.assert_called()


# pylint: disable=unused-argument
def test_capture_qr_code_loop_skips_missing_qrcode(mocker, m5stickv):
    """
    Test mocked camera snapshot of a missed mocked qrcode

    :param mocker
    :param m5stickv
    """
    mocker.patch(
        "krux.camera.sensor.snapshot",
        new=snapshot_generator(outcome=SNAP_FIND_QRCODES_FAIL),
    )
    mocker.patch("krux.camera.QRPartParser", new=MockQRPartParser)
    import krux
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()

    prev_parsed_count = -1

    def progress_callback(total_count, parsed_count, is_new):
        if parsed_count == 0:
            krux.camera.sensor.run.assert_called_with(1)
        nonlocal prev_parsed_count
        if parsed_count == prev_parsed_count:
            assert not is_new
        else:
            assert parsed_count > prev_parsed_count
            if parsed_count > 0:
                assert is_new
                assert total_count == MockQRPartParser.TOTAL
        prev_parsed_count = parsed_count
        return False

    # TODO: fix W0622: Redefining built-in 'format'
    # pylint: disable=redefined-builtin
    result, format = camera.capture_qr_code_loop(progress_callback)
    assert result == "134567891011"
    assert format == MockQRPartParser.FORMAT
    assert prev_parsed_count == MockQRPartParser.TOTAL - 1
    krux.camera.sensor.run.assert_called_with(0)
    krux.camera.wdt.feed.assert_called()


# pylint: disable=unused-argument
def test_capture_qr_code_loop_skips_duplicate_qrcode(mocker, m5stickv):
    """
    Test a skiped mocked camera snapshot of a duplicated mocked qrcode

    :param mocker
    :param m5stickv
    """
    mocker.patch(
        "krux.camera.sensor.snapshot",
        new=snapshot_generator(outcome=SNAP_REPEAT_QRCODE),
    )
    mocker.patch("krux.camera.QRPartParser", new=MockQRPartParser)
    import krux
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()

    prev_parsed_count = -1

    def progress_callback(total_count, parsed_count, is_new):
        if parsed_count == 0:
            krux.camera.sensor.run.assert_called_with(1)
        nonlocal prev_parsed_count
        if parsed_count == prev_parsed_count:
            assert not is_new
        else:
            assert parsed_count > prev_parsed_count
            if parsed_count > 0:
                assert is_new
                assert total_count == MockQRPartParser.TOTAL
        prev_parsed_count = parsed_count
        return False

    # TODO: fix W0622: Redefining built-in 'format'
    # pylint: disable=redefined-builtin
    result, format = camera.capture_qr_code_loop(progress_callback)
    assert result == "134567891011"
    assert format == MockQRPartParser.FORMAT
    assert prev_parsed_count == MockQRPartParser.TOTAL - 1
    krux.camera.sensor.run.assert_called_with(0)
    krux.camera.wdt.feed.assert_called()


# pylint: disable=unused-argument
def test_capture_snapshot_entropy(mocker, m5stickv):
    """
    Test entropy of a mocked camera snapshot

    :param mocker
    :param m5stickv
    """
    mocker.patch(
        "krux.camera.sensor.snapshot", new=snapshot_generator(outcome=SNAP_SUCCESS)
    )
    import hashlib
    import krux
    from krux.camera import Camera

    # Avoid `invalid-name`:
    # C0103: Variable name "<var>" doesn't conform to snake_case naming style
    camera = Camera()

    callback_returns = [
        0,  # No button pressed
        1,  # Enter pressed
    ]
    callback = mocker.MagicMock(side_effect=callback_returns)
    entropy_bytes = camera.capture_entropy(callback)
    hasher = hashlib.sha256()
    hasher.update(IMAGE_TO_HASH)

    assert entropy_bytes == hasher.digest()
    krux.camera.sensor.run.assert_called_with(0)
    krux.camera.wdt.feed.assert_called()
