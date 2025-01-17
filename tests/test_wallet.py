import pytest
from ur.ur_decoder import URDecoder


@pytest.fixture
def tdata(mocker):
    import binascii
    from collections import namedtuple
    from ur.ur import UR
    from embit.networks import NETWORKS
    from krux.key import (
        Key,
        P2PKH,
        P2SH_P2WPKH,
        P2TR,
        TYPE_SINGLESIG,
        TYPE_MULTISIG,
        TYPE_MINISCRIPT,
    )

    TEST_MNEMONIC1 = (
        "olympic term tissue route sense program under choose bean emerge velvet absurd"
    )
    TEST_MNEMONIC2 = "brush badge sing still venue panther kitchen please help panel bundle excess sign couch stove increase human once effort candy goat top tiny major"
    TEST_MNEMONIC3 = "range fatigue into stadium endless kitchen royal present rally welcome scatter twice"

    SINGLESIG_KEY = Key(
        TEST_MNEMONIC1, TYPE_SINGLESIG, NETWORKS["main"]
    )  # default account=0, script=P2WPKH
    LEGACY1_KEY = Key(TEST_MNEMONIC1, TYPE_SINGLESIG, NETWORKS["main"], "", 1, P2PKH)
    NESTEDSW1_KEY = Key(
        TEST_MNEMONIC1, TYPE_SINGLESIG, NETWORKS["main"], "", 1, P2SH_P2WPKH
    )
    TAPROOT1_KEY = Key(TEST_MNEMONIC1, TYPE_SINGLESIG, NETWORKS["main"], "", 1, P2TR)
    MULTISIG_KEY1 = Key(TEST_MNEMONIC1, TYPE_MULTISIG, NETWORKS["main"])
    MULTISIG_KEY2 = Key(TEST_MNEMONIC2, TYPE_MULTISIG, NETWORKS["main"])
    MULTISIG_KEY3 = Key(TEST_MNEMONIC3, TYPE_MULTISIG, NETWORKS["main"])
    MINISCRIPT_KEY = Key(TEST_MNEMONIC1, TYPE_MINISCRIPT, NETWORKS["main"])
    TAP_MINISCRIPT_KEY = Key(
        TEST_MNEMONIC1, TYPE_MINISCRIPT, NETWORKS["main"], script_type=P2TR
    )

    # SINGLESIG_KEY [55f8fc5d/84h/0h/0h]xpub6DPMTPxGMqdtzMwpqT1dDQaVdyaEppEm2qYSaJ7ANsuES7HkNzrXJst1Ed8D7NAnijUdgSDUFgph1oj5LKKAD5gyxWNhNP2AuDqaKYqzphA
    # MULTISIG_KEY1 [55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy
    # MULTISIG_KEY2 [3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu
    # MULTISIG_KEY3 [d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv

    KRUX_LEGACY1_DESCRIPTOR = "pkh([55f8fc5d/44h/0h/1h]xpub6C1dUaopHgps6X75i61KaJEDm4qkFeqjhm4by1ebvpgAsKDaEhGLgNX88bvuWPm4rSVe7GsYvQLDAXXLnxNsAbd3VwRihgM3q1kEkixBAbE)"
    KRUX_LEGACY1_XPUB = "[55f8fc5d/44h/0h/1h]xpub6C1dUaopHgps6X75i61KaJEDm4qkFeqjhm4by1ebvpgAsKDaEhGLgNX88bvuWPm4rSVe7GsYvQLDAXXLnxNsAbd3VwRihgM3q1kEkixBAbE"

    KRUX_NESTEDSW1_DESCRIPTOR = "sh(wpkh([55f8fc5d/49h/0h/1h]xpub6Ca1JGnSFNZ7jjwturEn944t8B9kBgiTKtmr3maTbryEyDyYY9xycVSQaFxeUPjbHyX7MUvLUbdoDVK7XZ7Fib9We4BQRRk8bZjW2UPRjHV))"
    KRUX_NESTEDSW1_XPUB = "[55f8fc5d/49h/0h/1h]xpub6Ca1JGnSFNZ7jjwturEn944t8B9kBgiTKtmr3maTbryEyDyYY9xycVSQaFxeUPjbHyX7MUvLUbdoDVK7XZ7Fib9We4BQRRk8bZjW2UPRjHV"
    KRUX_NESTEDSW1_YPUB = "[55f8fc5d/49h/0h/1h]ypub6XQGbwTMQ46bb391kD2QM9APJ9JC8JhxF1J4qAULysM82Knmnp8YEZ6YbTvEUJPWhcdv6xWtwFzM6mvgFFXGWpq7WPsq1LZcsHo9R97uuE4"
    KRUX_NESTEDSW1_YPUB_DESCRIPTOR = "sh(wpkh(" + KRUX_NESTEDSW1_YPUB + "))"

    KRUX_NATIVESW1_DESCRIPTOR = "wpkh([55f8fc5d/84h/0h/1h]xpub6DPMTPxGMqdu43FvwYdC6eHCPJWckCkx1rLJ1HEG7259GyWQD5P17WB2oowP9SpQdC8ogrmXfwfoazvf6Te8svtxWh4UTwTqyRdG5G54FxW)"
    KRUX_NATIVESW1_XPUB = "[55f8fc5d/84h/0h/1h]xpub6DPMTPxGMqdu43FvwYdC6eHCPJWckCkx1rLJ1HEG7259GyWQD5P17WB2oowP9SpQdC8ogrmXfwfoazvf6Te8svtxWh4UTwTqyRdG5G54FxW"
    KRUX_NATIVESW1_ZPUB = "[55f8fc5d/84h/0h/1h]zpub6s3t4jJ6fCirkdeAcGCSWpUCjEoWdSjwr5Nja522s2puPB8riPi8MdVJrDrZ9G8FSUNRBoxebGNuMa9nXrUAUQGAFNTKdm6pWskYrMahu1i"
    KRUX_NATIVESW1_ZPUB_DESCRIPTOR = "wpkh(" + KRUX_NATIVESW1_ZPUB + ")"

    KRUX_TAPROOT1_DESCRIPTOR = "tr([55f8fc5d/86h/0h/1h]xpub6CNGwJbVG9sQsJjtwLiemRFAfvDafL8zRthnHWNQbRz1PwAm28T1v5hLmJhFft71oEDCbA3xHemnScW5VWheP1BxXNVnoYboyw6t4wuKu5q)"
    KRUX_TAPROOT1_XPUB = "[55f8fc5d/86h/0h/1h]xpub6CNGwJbVG9sQsJjtwLiemRFAfvDafL8zRthnHWNQbRz1PwAm28T1v5hLmJhFft71oEDCbA3xHemnScW5VWheP1BxXNVnoYboyw6t4wuKu5q"

    SPECTER_SINGLESIG_DESCRIPTOR = "wpkh([55f8fc5d/84h/0h/0h]xpub6DPMTPxGMqdtzMwpqT1dDQaVdyaEppEm2qYSaJ7ANsuES7HkNzrXJst1Ed8D7NAnijUdgSDUFgph1oj5LKKAD5gyxWNhNP2AuDqaKYqzphA/0/*)"
    SPECTER_SINGLESIG_WALLET_DATA = '{"label": "Specter Singlesig Wallet", "blockheight": 0, "descriptor": "wpkh([55f8fc5d/84h/0h/0h]xpub6DPMTPxGMqdtzMwpqT1dDQaVdyaEppEm2qYSaJ7ANsuES7HkNzrXJst1Ed8D7NAnijUdgSDUFgph1oj5LKKAD5gyxWNhNP2AuDqaKYqzphA/0/*)#9qx3vqss", "devices": [{"type": "other", "label": "Key1"}]}'

    SPECTER_MULTISIG_DESCRIPTOR = "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/0/*,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/0/*,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/0/*))"
    SPECTER_MULTISIG_WALLET_DATA = '{"label": "Specter Multisig Wallet", "blockheight": 0, "descriptor": "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/0/*,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/0/*,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/0/*))#3nfc6jdy", "devices": [{"type": "other", "label": "Key1"}, {"type": "other", "label": "Key2"}, {"type": "other", "label": "Key3"}]}'

    BLUEWALLET_SINGLESIG_DESCRIPTOR = "wpkh(zpub6s3t4jJ6fCirgxL4WAasdamVyus8i4Dks4at95tw8tezYJvCtKBeZ1CHH33P7BUdY1iFBPQbB1XnnNxCmi9BoZ4BhBmYYCf9Sfxs6jY8Ycw)"
    BLUEWALLET_SINGLESIG_WALLET_DATA = "zpub6s3t4jJ6fCirgxL4WAasdamVyus8i4Dks4at95tw8tezYJvCtKBeZ1CHH33P7BUdY1iFBPQbB1XnnNxCmi9BoZ4BhBmYYCf9Sfxs6jY8Ycw"

    BLUEWALLET_LEGACY_DESCRIPTOR = "pkh(xpub6C1dUaopHgps26SpkdwL28cS5WFH7Xyaut4HLKZq8Jgiisp5VZK8o1HJLoDRiQyAbdMpBJSpgc8eToiJay4XAnSSvxDVvMuMTnBoTAR26Gb)"
    BLUEWALLET_LEGACY_WALLET_DATA = "xpub6C1dUaopHgps26SpkdwL28cS5WFH7Xyaut4HLKZq8Jgiisp5VZK8o1HJLoDRiQyAbdMpBJSpgc8eToiJay4XAnSSvxDVvMuMTnBoTAR26Gb"

    BLUEWALLET_NESTEDSW_DESCRIPTOR = "sh(wpkh(ypub6XQGbwTMQ46bXSBeD6jADRoWSHNkL2n6kErqSK1jBY6v6Vob1bgM3PQ5reMP15WDRxer21mB1MfUVr5WeHZAmkazwyyVSJ47MVzENnCyRcP))"
    BLUEWALLET_NESTEDSW_WALLET_DATA = "ypub6XQGbwTMQ46bXSBeD6jADRoWSHNkL2n6kErqSK1jBY6v6Vob1bgM3PQ5reMP15WDRxer21mB1MfUVr5WeHZAmkazwyyVSJ47MVzENnCyRcP"

    BLUEWALLET_MULTISIG_DESCRIPTOR = "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv))"
    BLUEWALLET_MULTISIG_WALLET_DATA = """
    # BlueWallet Multisig setup file
    # this file contains only public keys and is safe to
    # distribute among cosigners
    #
    Name: BlueWallet Multisig Wallet
    Policy: 2 of 3
    Derivation: m/48'/0'/0'/2'
    Format: P2WSH

    55f8fc5d:
    xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy

    3e15470d:
    xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu

    d3a80c8b:
    xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv
    """

    BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_SCRIPT = """
    # BlueWallet Multisig setup file
    # this file contains only public keys and is safe to
    # distribute among cosigners
    #
    Name: BlueWallet Multisig Wallet
    Policy: 2 of 3
    Derivation: m/48'/0'/0'/2'
    Format: P2WPH

    55f8fc5d:
    xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy

    3e15470d:
    xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu

    d3a80c8b:
    xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv
    """

    BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_KEYS = """
    # BlueWallet Multisig setup file
    # this file contains only public keys and is safe to
    # distribute among cosigners
    #
    Name: BlueWallet Multisig Wallet
    Policy: 2 of 3
    Derivation: m/48'/0'/0'/2'
    Format: P2WSH

    55f8fc5d:
    xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy
    """

    BLUEWALLET_MULTISIG_WALLET_DATA_MISSING_KEYS = """
    # BlueWallet Multisig setup file
    # this file contains only public keys and is safe to
    # distribute among cosigners
    #
    Name: BlueWallet Multisig Wallet
    Policy: 2 of 3
    """

    # TODO: Switch to 2-of-3 from keys defined above
    UR_OUTPUT_MULTISIG_DESCRIPTOR = "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
    UR_OUTPUT_MULTISIG_WALLET_DATA = UR(
        "crypto-output",
        bytearray(
            binascii.unhexlify(
                "d90191d90196a201010282d9012fa403582103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a704582060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968906d90130a20180030007d90130a1018601f400f480f4d9012fa403582102fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea045820f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c06d90130a2018200f4021abd16bee507d90130a1018600f400f480f4"
            )
        ),
    )

    UR_BYTES_MULTISIG_DESCRIPTOR = "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/0/*,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/0/*,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/0/*))"
    UR_BYTES_MULTISIG_WALLET_DATA = UR(
        "bytes",
        bytearray(
            b"y\x01\xf3"
            + '{"label": "Unknown Multisig Wallet", "descriptor": "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/0/*,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/0/*,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/0/*))#3nfc6jdy"}'.encode()
        ),
    )

    UNAMBIGUOUS_SINGLESIG_DESCRIPTOR = "wpkh([55f8fc5d/84h/0h/0h]xpub6DPMTPxGMqdtzMwpqT1dDQaVdyaEppEm2qYSaJ7ANsuES7HkNzrXJst1Ed8D7NAnijUdgSDUFgph1oj5LKKAD5gyxWNhNP2AuDqaKYqzphA/<0;1>/*)"
    AMBIGUOUS_SINGLESIG_DESCRIPTOR = "wpkh([55f8fc5d/84h/0h/0h]xpub6DPMTPxGMqdtzMwpqT1dDQaVdyaEppEm2qYSaJ7ANsuES7HkNzrXJst1Ed8D7NAnijUdgSDUFgph1oj5LKKAD5gyxWNhNP2AuDqaKYqzphA)"

    UNAMBIGUOUS_MULTISIG_DESCRIPTOR = "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*))"
    AMBIGUOUS_MULTISIG_DESCRIPTOR = "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv))"

    UNRELATED_SINGLESIG_DESCRIPTOR = "wpkh([55f8fc5d/84h/0h/0h]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB)"
    UNRELATED_MULTISIG_DESCRIPTOR = "wsh(sortedmulti(2,[55f8fc5d/48h/0h/0h/2h]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv))"

    UNSORTED_MULTISIG_DESCRIPTOR = "wsh(multi(2,[3e15470d/48h/0h/0h/2h]xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*,[55f8fc5d/48h/0h/0h/2h]xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*,[d3a80c8b/48h/0h/0h/2h]xpub6FKYY6y3oVi7ihSCszFKRSeZj5SzrfSsUFXhKqjMV4iigrLhxwMX3mrjioNyLTZ5iD3u4wU9S3tyzpJGxhd5geaXoQ68jGz2M6dfh2zJrUv/<0;1>/*))"

    LIANA_MINISCRIPT_DESCRIPTOR = "wsh(or_d(pk([55f8fc5d/48'/0'/0'/2']xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*),and_v(v:pkh([3e15470d/48'/0'/0'/2']xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*),older(6))))#x09nw3rv"
    LIANA_TAPROOT_MINISCRIPT_DESCRIPTOR = "tr([55f8fc5d/48'/0'/0'/2']xpub6EKmKYGYc1WY6t9d3d9SksR8keSaPZbFa6tqsGiH4xVxx8d2YyxSX7WG6yXEX3CmG54dPCxaapDw1XsjwCmfoqP7tbsAeqMVfKvqSAu4ndy/<0;1>/*,and_v(v:pk([3e15470d/48'/0'/0'/2']xpub6F2P6Pz5KLPgCc6pTBd2xxCunaSYWc8CdkL28W5z15pJrN3aCYY7mCUAkCMtqrgT2wdhAGgRnJxAkCCUpGKoXKxQ57yffEGmPwtYA3DEXwu/<0;1>/*),older(6)))#qjluv5ue"

    return namedtuple(
        "TestData",
        [
            "TEST_MNEMONIC1",
            "TEST_MNEMONIC2",
            "TEST_MNEMONIC3",
            "SINGLESIG_KEY",
            "LEGACY1_KEY",
            "NESTEDSW1_KEY",
            "TAPROOT1_KEY",
            "MULTISIG_KEY1",
            "MULTISIG_KEY2",
            "MULTISIG_KEY3",
            "MINISCRIPT_KEY",
            "TAP_MINISCRIPT_KEY",
            "KRUX_LEGACY1_DESCRIPTOR",
            "KRUX_LEGACY1_XPUB",
            "KRUX_NESTEDSW1_DESCRIPTOR",
            "KRUX_NESTEDSW1_XPUB",
            "KRUX_NESTEDSW1_YPUB",
            "KRUX_NESTEDSW1_YPUB_DESCRIPTOR",
            "KRUX_NATIVESW1_DESCRIPTOR",
            "KRUX_NATIVESW1_XPUB",
            "KRUX_NATIVESW1_ZPUB",
            "KRUX_NATIVESW1_ZPUB_DESCRIPTOR",
            "KRUX_TAPROOT1_DESCRIPTOR",
            "KRUX_TAPROOT1_XPUB",
            "SPECTER_SINGLESIG_DESCRIPTOR",
            "SPECTER_SINGLESIG_WALLET_DATA",
            "SPECTER_MULTISIG_DESCRIPTOR",
            "SPECTER_MULTISIG_WALLET_DATA",
            "BLUEWALLET_SINGLESIG_DESCRIPTOR",
            "BLUEWALLET_SINGLESIG_WALLET_DATA",
            "BLUEWALLET_LEGACY_DESCRIPTOR",
            "BLUEWALLET_LEGACY_WALLET_DATA",
            "BLUEWALLET_NESTEDSW_DESCRIPTOR",
            "BLUEWALLET_NESTEDSW_WALLET_DATA",
            "BLUEWALLET_MULTISIG_DESCRIPTOR",
            "BLUEWALLET_MULTISIG_WALLET_DATA",
            "BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_SCRIPT",
            "BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_KEYS",
            "BLUEWALLET_MULTISIG_WALLET_DATA_MISSING_KEYS",
            "UR_OUTPUT_MULTISIG_DESCRIPTOR",
            "UR_OUTPUT_MULTISIG_WALLET_DATA",
            "UR_BYTES_MULTISIG_DESCRIPTOR",
            "UR_BYTES_MULTISIG_WALLET_DATA",
            "UNAMBIGUOUS_SINGLESIG_DESCRIPTOR",
            "AMBIGUOUS_SINGLESIG_DESCRIPTOR",
            "UNAMBIGUOUS_MULTISIG_DESCRIPTOR",
            "AMBIGUOUS_MULTISIG_DESCRIPTOR",
            "UNRELATED_SINGLESIG_DESCRIPTOR",
            "UNRELATED_MULTISIG_DESCRIPTOR",
            "UNSORTED_MULTISIG_DESCRIPTOR",
            "LIANA_MINISCRIPT_DESCRIPTOR",
            "LIANA_TAPROOT_MINISCRIPT_DESCRIPTOR",
        ],
    )(
        TEST_MNEMONIC1,
        TEST_MNEMONIC2,
        TEST_MNEMONIC3,
        SINGLESIG_KEY,
        LEGACY1_KEY,
        NESTEDSW1_KEY,
        TAPROOT1_KEY,
        MULTISIG_KEY1,
        MULTISIG_KEY2,
        MULTISIG_KEY3,
        MINISCRIPT_KEY,
        TAP_MINISCRIPT_KEY,
        KRUX_LEGACY1_DESCRIPTOR,
        KRUX_LEGACY1_XPUB,
        KRUX_NESTEDSW1_DESCRIPTOR,
        KRUX_NESTEDSW1_XPUB,
        KRUX_NESTEDSW1_YPUB,
        KRUX_NESTEDSW1_YPUB_DESCRIPTOR,
        KRUX_NATIVESW1_DESCRIPTOR,
        KRUX_NATIVESW1_XPUB,
        KRUX_NATIVESW1_ZPUB,
        KRUX_NATIVESW1_ZPUB_DESCRIPTOR,
        KRUX_TAPROOT1_DESCRIPTOR,
        KRUX_TAPROOT1_XPUB,
        SPECTER_SINGLESIG_DESCRIPTOR,
        SPECTER_SINGLESIG_WALLET_DATA,
        SPECTER_MULTISIG_DESCRIPTOR,
        SPECTER_MULTISIG_WALLET_DATA,
        BLUEWALLET_SINGLESIG_DESCRIPTOR,
        BLUEWALLET_SINGLESIG_WALLET_DATA,
        BLUEWALLET_LEGACY_DESCRIPTOR,
        BLUEWALLET_LEGACY_WALLET_DATA,
        BLUEWALLET_NESTEDSW_DESCRIPTOR,
        BLUEWALLET_NESTEDSW_WALLET_DATA,
        BLUEWALLET_MULTISIG_DESCRIPTOR,
        BLUEWALLET_MULTISIG_WALLET_DATA,
        BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_SCRIPT,
        BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_KEYS,
        BLUEWALLET_MULTISIG_WALLET_DATA_MISSING_KEYS,
        UR_OUTPUT_MULTISIG_DESCRIPTOR,
        UR_OUTPUT_MULTISIG_WALLET_DATA,
        UR_BYTES_MULTISIG_DESCRIPTOR,
        UR_BYTES_MULTISIG_WALLET_DATA,
        UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
        AMBIGUOUS_SINGLESIG_DESCRIPTOR,
        UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
        AMBIGUOUS_MULTISIG_DESCRIPTOR,
        UNRELATED_SINGLESIG_DESCRIPTOR,
        UNRELATED_MULTISIG_DESCRIPTOR,
        UNSORTED_MULTISIG_DESCRIPTOR,
        LIANA_MINISCRIPT_DESCRIPTOR,
        LIANA_TAPROOT_MINISCRIPT_DESCRIPTOR,
    )


def test_init_singlesig(mocker, m5stickv, tdata):
    from embit.descriptor import Descriptor
    from krux.wallet import Wallet, to_unambiguous_descriptor
    from krux.qr import FORMAT_NONE

    cases = [
        # key, descriptor, label, policy
        (None, None, None, None),
        (
            tdata.SINGLESIG_KEY,
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
            "Single-sig",
            {"type": "p2wpkh"},
        ),
        (
            tdata.LEGACY1_KEY,
            tdata.KRUX_LEGACY1_DESCRIPTOR,
            "Single-sig",
            {"type": "p2pkh"},
        ),
        (
            tdata.NESTEDSW1_KEY,
            tdata.KRUX_NESTEDSW1_DESCRIPTOR,
            "Single-sig",
            {"type": "p2sh"},
        ),
        (
            tdata.TAPROOT1_KEY,
            tdata.KRUX_TAPROOT1_DESCRIPTOR,
            "Single-sig",
            {"type": "p2tr"},
        ),
    ]

    for _case in cases:
        wallet = Wallet(_case[0])
        assert isinstance(wallet, Wallet)
        if wallet.descriptor:
            # don't fail simply because of a difference between ambiguous and unambiguous
            try:
                assert wallet.descriptor.to_string() == _case[1]
            except AssertionError:
                test_descr = to_unambiguous_descriptor(
                    Descriptor.from_string(_case[1])
                ).to_string()
                assert wallet.descriptor.to_string() == test_descr
        assert wallet.label == _case[2]
        assert wallet.policy == _case[3]


def test_init_multisig(mocker, m5stickv, tdata):
    from krux.wallet import Wallet

    wallet = Wallet(tdata.MULTISIG_KEY1)
    assert isinstance(wallet, Wallet)
    assert wallet.descriptor is None
    assert wallet.label is None
    assert wallet.policy is None

    wallet = Wallet(None)
    assert isinstance(wallet, Wallet)
    assert wallet.descriptor is None
    assert wallet.label is None
    assert wallet.policy is None


def test_init_miniscript(mocker, m5stickv, tdata):
    from krux.wallet import Wallet

    wallet = Wallet(tdata.MINISCRIPT_KEY)
    assert isinstance(wallet, Wallet)
    assert wallet.descriptor is None
    assert wallet.label is None
    assert wallet.policy is None


def test_is_multisig(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE

    # Non multisig keys
    wallet = Wallet(tdata.SINGLESIG_KEY)
    assert not wallet.is_multisig()

    wallet = Wallet(tdata.TAPROOT1_KEY)
    assert not wallet.is_multisig()

    wallet = Wallet(tdata.MINISCRIPT_KEY)
    assert not wallet.is_multisig()

    # Multisig key
    wallet = Wallet(tdata.MULTISIG_KEY1)
    assert wallet.is_multisig()

    # Multisig key with loaded descriptor
    wallet.load(tdata.SPECTER_MULTISIG_DESCRIPTOR, FORMAT_NONE)
    assert wallet.is_multisig()

    # No key, no descriptor
    wallet = Wallet(None)
    assert not wallet.is_multisig()

    # Sans key: Descriptor only, no key loaded
    # Multisig descriptor
    wallet.load(tdata.SPECTER_MULTISIG_DESCRIPTOR, FORMAT_NONE)
    assert wallet.is_multisig()

    # Single-sig descriptor
    wallet = Wallet(None)
    wallet.load(tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_multisig()

    # Taproot single-sig descriptor
    wallet = Wallet(None)
    wallet.load(tdata.KRUX_TAPROOT1_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_multisig()

    # Miniscript descriptor
    wallet = Wallet(None)
    wallet.load(tdata.LIANA_MINISCRIPT_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_multisig()

    # Taproot miniscript descriptor
    wallet = Wallet(None)
    wallet.load(tdata.LIANA_TAPROOT_MINISCRIPT_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_multisig()


def test_is_miniscript(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE

    # Non multisig keys
    wallet = Wallet(tdata.SINGLESIG_KEY)
    assert not wallet.is_miniscript()

    wallet = Wallet(tdata.TAPROOT1_KEY)
    assert not wallet.is_miniscript()

    wallet = Wallet(tdata.MULTISIG_KEY1)
    assert not wallet.is_miniscript()

    # Miniscript key
    wallet = Wallet(tdata.MINISCRIPT_KEY)
    assert wallet.is_miniscript()

    # Miniscript key with loaded descriptor
    wallet.load(tdata.LIANA_MINISCRIPT_DESCRIPTOR, FORMAT_NONE)
    assert wallet.is_miniscript()

    # Taproot miniscript key with loaded descriptor
    wallet = Wallet(tdata.TAP_MINISCRIPT_KEY)
    wallet.load(tdata.LIANA_TAPROOT_MINISCRIPT_DESCRIPTOR, FORMAT_NONE)
    assert wallet.is_miniscript()

    # No key and no descriptor
    wallet = Wallet(None)
    assert not wallet.is_miniscript()

    # Non miniscript descriptors
    wallet.load(tdata.SPECTER_MULTISIG_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_miniscript()

    wallet = Wallet(None)
    wallet.load(tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_miniscript()

    wallet = Wallet(None)
    wallet.load(tdata.KRUX_TAPROOT1_DESCRIPTOR, FORMAT_NONE)
    assert not wallet.is_miniscript()

    # Miniscript descriptor
    wallet = Wallet(None)
    wallet.load(tdata.LIANA_MINISCRIPT_DESCRIPTOR, FORMAT_NONE)
    assert wallet.is_miniscript()


def test_is_loaded(mocker, m5stickv, tdata):
    from krux.wallet import Wallet

    wallet = Wallet(tdata.SINGLESIG_KEY)
    assert not wallet.is_loaded()

    wallet = Wallet(tdata.MULTISIG_KEY1)
    assert not wallet.is_loaded()

    wallet.wallet_data = tdata.UR_OUTPUT_MULTISIG_WALLET_DATA
    assert wallet.is_loaded()

    wallet = Wallet(None)
    assert not wallet.is_loaded()


def test_wallet_qr(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_UR

    for wallet in (Wallet(tdata.MULTISIG_KEY1), Wallet(None)):
        wallet.wallet_data = tdata.UR_OUTPUT_MULTISIG_WALLET_DATA
        wallet.wallet_qr_format = FORMAT_UR

        wallet_data, wallet_qr_format = wallet.wallet_qr()

        assert wallet_data == tdata.UR_OUTPUT_MULTISIG_WALLET_DATA
        assert wallet_qr_format == FORMAT_UR


def test_receive_addresses(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_PMOFN
    from krux.key import TYPE_SINGLESIG

    cases = [
        (  # Native Segwit
            tdata.SINGLESIG_KEY,
            tdata.SPECTER_SINGLESIG_WALLET_DATA,
            FORMAT_PMOFN,
            [
                "bc1qrhjqrz2d9tdym3p2r9m2vwzn2sn2yl6k5m357y",
                "bc1q6hpnrwgy7a26newf5ewgl6a3f6cqz2xtmmhghx",
                "bc1qjfygdgjvw6euxtzs3fxx5d7fxvs8ypykzu8cjs",
                "bc1qjl4kpu95s2z9lws3pmwlww5260n66ccnc5uc8t",
                "bc1qzdwh9ctwj7wg5ul2pskc6rvzmmpn2l5j4lkprc",
                "bc1qdx4z958lcu0xfe9jkjm3v5354k0tq9pqwtv6th",
                "bc1q7s8u2g260f6qs97vmhc34kvpuque87uk3aw47h",
                "bc1qdm8yaere7fnu02tstwrxkhfgrfpteumjsl7l4r",
                "bc1qfz3rfm0da9m7lca8rfkzgs2uhk5cxnms5dxmxu",
                "bc1q6mlxs236fmyeteummv9x5pmxteh86lkln4emag",
            ],
        ),
        (  # Legacy Single-sig
            tdata.LEGACY1_KEY,
            tdata.KRUX_LEGACY1_DESCRIPTOR,
            FORMAT_PMOFN,
            [
                "1GsaC1sVGGnN7KpYCHUMR4Z8c9F3BzfUAL",
                "1CSSWcbgAPNsB5twS2TfACtCqC6PfahgnM",
                "1E9U3icgCLbDqEhS4xqtopvXYtRU4UmSoU",
                "17mTKjHWb1LNKjEdUUmVXsDFUcEmqWzSw6",
                "16Sg1PLRfEoGr2YsH93v3xAfXSTf42vcHi",
                "13rNEribNgeARh7p58FXKJxSRYcVg3i5VJ",
                "1Ler4fyDfDq23dMbJ1WXRoYr9EcL6QX8KN",
                "15dihUfEHdC21UaJhneQFUfPywonD9ZuJe",
                "1MSN9AjP8GourmFEmtqTjukqV9Jp2vzgVS",
                "1CoSqz4K5xEysnBoPPLukp4gmh2dnx11Wj",
            ],
        ),
        (  # Nested Segwit Single-sig
            tdata.NESTEDSW1_KEY,
            tdata.KRUX_NESTEDSW1_DESCRIPTOR,
            FORMAT_PMOFN,
            [
                "3HN5XxXfK5kNNu83GSVc1tAu3CVpBjghcS",
                "395RjbYLhWFWC2LarYkDk41BxxiBiJSWEb",
                "3EuvWJNACMVswiczged3bHnWjywKA3n3WQ",
                "3EZtai8s84WG8MvcUw3xnTHnWKiQUJBLr7",
                "36eFaNxjFBTZUHFWHRcKacppmdFy4X1MKR",
                "38p4zYbK1KC4KEkid1tVkHr2ruARTCKBJK",
                "3P8PcnaFeHn8FCoFwoxPKFGCTzmxXnLJEx",
                "33aw8rJwuxtexN8nZ6YiYvJSoNUAeaY8FM",
                "35V6by4xd9owyHaZiBhueKCGMUecV9K4d8",
                "33eCmbdSneaxYarxtX9mdJpvyoG1NWaKPj",
            ],
        ),
        (  # Taproot Single-sig
            tdata.TAPROOT1_KEY,
            tdata.KRUX_TAPROOT1_DESCRIPTOR,
            FORMAT_PMOFN,
            [
                "bc1pkusdqe839xltdn5jk62rv0cx6c4nrrw3hr8rmf3478tnn88qs2ls4g77cl",
                "bc1pzlnrsqze6lwcl9w9z5n9x8dfejf47mrdhv5t8pp4gjehe535xftqkwp635",
                "bc1pxz7j9cakl53a72hg08g0ug8gtsy9cf86fmh5mtjucyp707jm7mjsx8lagh",
                "bc1p2aqrr4wctz0mhcnn4tpcrg0r89pnn7yqqnv8xpeqr3sckkp3s3fqnnpkgh",
                "bc1p3tdqgfjk2zn88jshtj698vfphzn8t3lr4l6qhpf38yyvcpevkfeql3p2fs",
                "bc1paa4rtwsdf7z9p22wassvhj6zk5zs94xp0rpcrq2452xwzmgejxpquat7gs",
                "bc1p93pdqw9v2237pn2xzyks0dd3mnpnf0kagx0hl44u2msz23425w0s68s658",
                "bc1pmejm3jyp6d287dn4lx68j966y0783rvwfujus8s3h9dmedfdm98s7xglv7",
                "bc1p9dvlkmfzl8qmax47lg22rfluztc0ev7lvs3rl838y0s96p65mwusz08lhv",
                "bc1p8fue49l0amhqvsau72gmk3dau2w5ktxkh2njck95rej0v538wj4q40gksu",
            ],
        ),
        (  # Multisig WSH
            tdata.MULTISIG_KEY1,
            tdata.SPECTER_MULTISIG_WALLET_DATA,
            FORMAT_PMOFN,
            [
                "bc1q6y95p2qkcmsr7kp5zpnt04qx5l2slq73d9um62ka3s5nr83mlcfsywsn65",
                "bc1qv72e35u2qjtzm60qznzzc63aq6mjlxg6y8xnctw9vq5q9mp43lasj69v67",
                "bc1qymmm8s0g38hhjfxn0kdm2r9xsvch3gzxc07th2athuq7r9rje3xskwvk0q",
                "bc1qaerrqmm0ce4qsrlsvswvm6mmcw462cydwzawh4wy7eed8fcjkvtsdkccnl",
                "bc1qacxshm6p84zj4x6vevat65uqu6k8379x55vzp0gz5y6m0eyrgayqpuamez",
                "bc1q0xvq09ep68jp57v3f2et2pmm6vtdu9f5le9c5qr75rmlge4et25qlt2lkz",
                "bc1qnqq4qfa7c5vg9nh0ddvnwf9fxucms2c992h4qht9hzs96qc8fggsegfurq",
                "bc1qnds506sq72glz8x7pq3dkywhktg7scaua3d4mdzjpluwvtzxdwcsxlmj89",
                "bc1qss8w8dygehsqusat6hzxlrtzykqxjsmjsccdf9qlsx7yhjcze9xqekznh5",
                "bc1qgzqffn9f4fal2ld04wdafakvgrl5gexp744gm8eg58j7a633lf9slzcjup",
            ],
        ),
        (  # Miniscript WSH
            tdata.MINISCRIPT_KEY,
            tdata.LIANA_MINISCRIPT_DESCRIPTOR,
            FORMAT_PMOFN,
            [
                "bc1q3qp2kgjxkmh6dptyppvptjyg8wlvvddyec0cfgpwftn4nyjs8jpslyaynm",
                "bc1qt2j45nvg7rup8h73t5syuaxuvzqr4wk3lqdpjw3ew2afdc7ggzlqspnqwj",
                "bc1qvs22y63jdy0fdmgesht3yn3d7ruvuahf73yqmuhhx5w6trj6fy6syugd43",
                "bc1qckd42m2mttn3gmz2my7c3flj9uujq0ekpkuxqjj2m2lnwgkrzwuqq8ke23",
                "bc1qq4lhujwh4rhxmu82svy3cz97h7ays9j2wjmtw2ju8sqynx88pxys2fud4h",
                "bc1q8jm9g8t96g8m75ce6uvq2lhp5snfnzmumdq3qh04v8jt5w7dlmvqfjs8f2",
                "bc1qa8tc0pwljncccdauv37vka3kxfus9pssn62dwvvjjhye3h0egsjsj2eu27",
                "bc1q5rehtcjd7xw9pfv72lnpv7rrtr4pjh93afr0y60hrluauzn2y83qc8p4fe",
                "bc1qmz9v9z0acnd7qehmvqje2m7qmr9ytus87xyk8nprzkypg8gy4zksem4dfz",
                "bc1qncuaqah98hypkxnpp465mqw7srjgm67s70gkzcs693kv9zp3dv8qa5w8fj",
            ],
        ),
        (  # Miniscript TR
            tdata.TAP_MINISCRIPT_KEY,
            tdata.LIANA_TAPROOT_MINISCRIPT_DESCRIPTOR,
            FORMAT_PMOFN,
            [
                "bc1pq87pvf85eu3stcxgemm2gppt5w99uxgm75fv3l62lnmjaewuaw0qjpeda6",
                "bc1purr3u8x4j0ean426yf09ap2xu5xvehyrlh9s3uqxsf3e2w9pxkjsaf9pum",
                "bc1pw83dp6vq7tn7965jxxavkd5fa04y8vpz9njtg7ms8ng9l3u0d0uqnqssfa",
                "bc1pef8a3pmsdee6vlup2g3mg5903zxq5lykvpwm4v5f4z0swefdrswsle9sy8",
                "bc1pfxmm35spmp9s9jstmvwd0vjksura79ez5f68q6c5gewh6q77jwqs7geafk",
                "bc1pwwntw7cplgueq5kulek7mqqqr5s6uatd6psgnclp2a8c3rukxgzqmhszr7",
                "bc1pc0m0kvav5sddu5a05chzqk9de9z324teh7cdtem9kly6snw8fz4qpp5uwu",
                "bc1pedvnetmy08ekk9j3qyw3zussmxy0lc3tlzmvs9qmnxm9yqq827dqhzjv69",
                "bc1p40d9u4g7wgnggrykeghztla4l78k38nkc3ekrghsp6evp2awj72slfa8qc",
                "bc1pvpwmch3gjcrer395wzswawnfuer4crz7x6vt9g845jqklvgvydkq0hm8gj",
            ],
        ),
    ]

    for case in cases:
        wallet = Wallet(case[0])
        # Check addresses before descriptor is loadaded in case it is single-sig
        if wallet.key.policy_type == TYPE_SINGLESIG:
            assert [addr for addr in wallet.obtain_addresses(0, limit=10)] == case[3]
        else:
            # Ensure an error is raised as the descriptor is not loaded
            with pytest.raises(ValueError):
                [addr for addr in wallet.obtain_addresses(0, limit=10)]

        # Check addresses after descriptor is loaded
        wallet.load(case[1], case[2])
        assert [addr for addr in wallet.obtain_addresses(0, limit=10)] == case[3]

        wallet = Wallet(None)
        wallet.load(case[1], case[2])
        assert [addr for addr in wallet.obtain_addresses(0, limit=10)] == case[3]


def test_load_multisig(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE, FORMAT_PMOFN, FORMAT_UR

    cases = [
        (
            tdata.SPECTER_MULTISIG_WALLET_DATA,
            FORMAT_PMOFN,
            tdata.SPECTER_MULTISIG_DESCRIPTOR,
            "Specter Multisig Wallet",
            {
                "type": "p2wsh",
                "m": 2,
                "n": 3,
                "cosigners": [
                    tdata.MULTISIG_KEY1.xpub(),
                    tdata.MULTISIG_KEY2.xpub(),
                    tdata.MULTISIG_KEY3.xpub(),
                ],
            },
        ),
        (
            tdata.BLUEWALLET_MULTISIG_WALLET_DATA,
            FORMAT_NONE,
            tdata.UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
            "BlueWallet Multisig Wallet",
            {
                "type": "p2wsh",
                "m": 2,
                "n": 3,
                "cosigners": [
                    tdata.MULTISIG_KEY1.xpub(),
                    tdata.MULTISIG_KEY2.xpub(),
                    tdata.MULTISIG_KEY3.xpub(),
                ],
            },
        ),
        # TODO: Fix AssertionError (see previous "TODO: Switch to 2-of-3 from keys defined above")
        # (
        #    tdata.UR_OUTPUT_MULTISIG_WALLET_DATA,
        #    FORMAT_UR,
        #    tdata.UR_OUTPUT_MULTISIG_DESCRIPTOR,
        #    '2 of 3',
        #    {
        #        'type': 'p2wsh',
        #        'm': 2,
        #        'n': 3,
        #        'cosigners': [
        #            tdata.MULTISIG_KEY1.xpub(),
        #            tdata.MULTISIG_KEY2.xpub(),
        #            tdata.MULTISIG_KEY3.xpub()
        #        ],
        #    },
        # ),
        (
            tdata.UR_BYTES_MULTISIG_WALLET_DATA,
            FORMAT_UR,
            tdata.UR_BYTES_MULTISIG_DESCRIPTOR,
            "Unknown Multisig Wallet",
            {
                "type": "p2wsh",
                "m": 2,
                "n": 3,
                "cosigners": [
                    tdata.MULTISIG_KEY1.xpub(),
                    tdata.MULTISIG_KEY2.xpub(),
                    tdata.MULTISIG_KEY3.xpub(),
                ],
            },
        ),
        (
            tdata.UNSORTED_MULTISIG_DESCRIPTOR,
            FORMAT_NONE,
            tdata.UNSORTED_MULTISIG_DESCRIPTOR,
            "2 of 3 multisig",
            {
                "type": "p2wsh",
                "m": 2,
                "n": 3,
                "cosigners": [
                    tdata.MULTISIG_KEY2.xpub(),
                    tdata.MULTISIG_KEY1.xpub(),
                    tdata.MULTISIG_KEY3.xpub(),
                ],
            },
        ),
    ]
    for wallet in (Wallet(None), Wallet(tdata.MULTISIG_KEY1)):
        for case in cases:
            wallet.load(case[0], case[1])
            assert wallet.wallet_data == case[0]
            assert wallet.wallet_qr_format == case[1]
            assert wallet.descriptor.to_string() == case[2]
            assert wallet.label == case[3]
            assert wallet.policy == case[4]


def test_load_singlesig(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE, FORMAT_PMOFN

    cases = [
        (
            tdata.SPECTER_SINGLESIG_WALLET_DATA,
            FORMAT_PMOFN,
            tdata.SPECTER_SINGLESIG_DESCRIPTOR,
            "Specter Singlesig Wallet",
            {"type": "p2wpkh"},
        ),
        (
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
            FORMAT_NONE,
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
            "Single-sig",
            {"type": "p2wpkh"},
        ),
    ]
    for wallet in (Wallet(None), Wallet(tdata.SINGLESIG_KEY)):
        for case in cases:
            wallet.load(case[0], case[1])
            assert wallet.wallet_data == case[0]
            assert wallet.wallet_qr_format == case[1]
            assert wallet.descriptor.to_string() == case[2]
            assert wallet.label == case[3]
            assert wallet.policy == case[4]


def test_load_singlesig_fails_with_multisig_descriptor(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE, FORMAT_PMOFN, FORMAT_UR

    wallet = Wallet(tdata.SINGLESIG_KEY)

    cases = [
        (tdata.SPECTER_MULTISIG_WALLET_DATA, FORMAT_PMOFN),
        (tdata.BLUEWALLET_MULTISIG_WALLET_DATA, FORMAT_NONE),
        (tdata.UR_OUTPUT_MULTISIG_WALLET_DATA, FORMAT_UR),
        (tdata.UR_BYTES_MULTISIG_WALLET_DATA, FORMAT_UR),
    ]
    for case in cases:
        with pytest.raises(ValueError):
            wallet.load(case[0], case[1])


def test_load_multisig_fails_with_singlesig_descriptor(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE, FORMAT_PMOFN

    wallet = Wallet(tdata.MULTISIG_KEY1)

    cases = [
        (tdata.SPECTER_SINGLESIG_WALLET_DATA, FORMAT_PMOFN),
        (tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR, FORMAT_NONE),
    ]
    for case in cases:
        with pytest.raises(ValueError):
            wallet.load(case[0], case[1])


def test_load_singlesig_fails_when_key_not_in_descriptor(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE

    wallet = Wallet(tdata.SINGLESIG_KEY)

    with pytest.raises(ValueError):
        wallet.load(tdata.UNRELATED_SINGLESIG_DESCRIPTOR, FORMAT_NONE)


def test_load_multisig_fails_when_key_not_in_descriptor(mocker, m5stickv, tdata):
    from krux.wallet import Wallet
    from krux.qr import FORMAT_NONE

    wallet = Wallet(tdata.MULTISIG_KEY1)

    with pytest.raises(ValueError):
        wallet.load(tdata.UNRELATED_MULTISIG_DESCRIPTOR, FORMAT_NONE)


def test_parse_wallet(mocker, m5stickv, tdata):
    from krux.wallet import parse_wallet, AssumptionWarning

    cases = [
        (
            tdata.KRUX_LEGACY1_XPUB,
            tdata.KRUX_LEGACY1_DESCRIPTOR,
            None,
        ),
        (
            tdata.KRUX_NESTEDSW1_XPUB,
            tdata.KRUX_NESTEDSW1_DESCRIPTOR,
            None,
        ),
        (
            tdata.KRUX_NESTEDSW1_YPUB,
            tdata.KRUX_NESTEDSW1_YPUB_DESCRIPTOR,
            None,
        ),
        (
            tdata.KRUX_NATIVESW1_XPUB,
            tdata.KRUX_NATIVESW1_DESCRIPTOR,
            None,
        ),
        (
            tdata.KRUX_NATIVESW1_ZPUB,
            tdata.KRUX_NATIVESW1_ZPUB_DESCRIPTOR,
            None,
        ),
        (
            tdata.KRUX_TAPROOT1_XPUB,
            tdata.KRUX_TAPROOT1_DESCRIPTOR,
            None,
        ),
        (
            tdata.SPECTER_SINGLESIG_WALLET_DATA,
            tdata.SPECTER_SINGLESIG_DESCRIPTOR,
            "Specter Singlesig Wallet",
        ),
        (
            tdata.SPECTER_MULTISIG_WALLET_DATA,
            tdata.SPECTER_MULTISIG_DESCRIPTOR,
            "Specter Multisig Wallet",
        ),
        (
            tdata.BLUEWALLET_SINGLESIG_WALLET_DATA,
            tdata.BLUEWALLET_SINGLESIG_DESCRIPTOR,
            None,
        ),
        # ( BlueWallet legacy bip44 xpub w/o key-origin is not supported, will default to bip84
        #    tdata.BLUEWALLET_LEGACY_WALLET_DATA,
        #    tdata.BLUEWALLET_LEGACY_DESCRIPTOR,
        #    None,
        # ),
        (
            tdata.BLUEWALLET_NESTEDSW_WALLET_DATA,
            tdata.BLUEWALLET_NESTEDSW_DESCRIPTOR,
            None,
        ),
        (
            tdata.BLUEWALLET_MULTISIG_WALLET_DATA,
            tdata.BLUEWALLET_MULTISIG_DESCRIPTOR,
            "BlueWallet Multisig Wallet",
        ),
        (
            tdata.UR_OUTPUT_MULTISIG_WALLET_DATA,
            tdata.UR_OUTPUT_MULTISIG_DESCRIPTOR,
            None,
        ),
        (
            tdata.UR_BYTES_MULTISIG_WALLET_DATA,
            tdata.UR_BYTES_MULTISIG_DESCRIPTOR,
            "Unknown Multisig Wallet",
        ),
        (
            tdata.AMBIGUOUS_MULTISIG_DESCRIPTOR,
            tdata.AMBIGUOUS_MULTISIG_DESCRIPTOR,
            None,
        ),
        (
            tdata.UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
            tdata.UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
            None,
        ),
        (
            tdata.AMBIGUOUS_SINGLESIG_DESCRIPTOR,
            tdata.AMBIGUOUS_SINGLESIG_DESCRIPTOR,
            None,
        ),
        (
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
            None,
        ),
    ]

    case_n = 1
    for case in cases:
        print(case_n)
        case_n += 1
        try:
            descriptor, label = parse_wallet(case[0])
        except AssumptionWarning as e:
            descriptor, label = parse_wallet(case[0], allow_assumption=e.args[1])
        assert descriptor.to_string() == case[1]
        assert label == case[2]


def test_parse_wallet_raises_errors(mocker, m5stickv, tdata):
    from krux.wallet import parse_wallet
    from ur.ur import UR

    cases = [
        tdata.BLUEWALLET_MULTISIG_WALLET_DATA_MISSING_KEYS,
        tdata.BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_KEYS,
        tdata.BLUEWALLET_MULTISIG_WALLET_DATA_INVALID_SCRIPT,
        UR("unknown-type", bytearray("invalid wallet format".encode())),
        "invalid wallet format",
        '{"invalid": "json", "wallet": "format"}',
    ]
    for case in cases:
        with pytest.raises(ValueError):
            parse_wallet(case)


def test_parse_address(mocker, m5stickv, tdata):
    from krux.wallet import parse_address

    cases = [
        # m/44
        ("14ihRbmxbgZ6JN9HdDDo6u6nGradHDy4GJ", "14ihRbmxbgZ6JN9HdDDo6u6nGradHDy4GJ"),
        # m/48/0/0/2
        ("1BRwWQ3GHabCV5DP6MfnCpr6dF6GBAwQ7k", "1BRwWQ3GHabCV5DP6MfnCpr6dF6GBAwQ7k"),
        # m/84
        (
            "bc1qx2zuday8d6j4ufh4df6e9ttd06lnfmn2cuz0vn",
            "bc1qx2zuday8d6j4ufh4df6e9ttd06lnfmn2cuz0vn",
        ),
        # m/49
        ("32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg", "32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg"),
        # m/0
        ("3KLoUhwLihgC5aPQPFHakWUtJ4QoBkT7Aw", "3KLoUhwLihgC5aPQPFHakWUtJ4QoBkT7Aw"),
        (
            "bitcoin:14ihRbmxbgZ6JN9HdDDo6u6nGradHDy4GJ",
            "14ihRbmxbgZ6JN9HdDDo6u6nGradHDy4GJ",
        ),
        (
            "bitcoin:1BRwWQ3GHabCV5DP6MfnCpr6dF6GBAwQ7k",
            "1BRwWQ3GHabCV5DP6MfnCpr6dF6GBAwQ7k",
        ),
        (
            "bitcoin:bc1qx2zuday8d6j4ufh4df6e9ttd06lnfmn2cuz0vn",
            "bc1qx2zuday8d6j4ufh4df6e9ttd06lnfmn2cuz0vn",
        ),
        (
            "bitcoin:32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg",
            "32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg",
        ),
        (
            "bitcoin:3KLoUhwLihgC5aPQPFHakWUtJ4QoBkT7Aw",
            "3KLoUhwLihgC5aPQPFHakWUtJ4QoBkT7Aw",
        ),
        (
            "bitcoin:14ihRbmxbgZ6JN9HdDDo6u6nGradHDy4GJ?message=test",
            "14ihRbmxbgZ6JN9HdDDo6u6nGradHDy4GJ",
        ),
        (
            "bitcoin:1BRwWQ3GHabCV5DP6MfnCpr6dF6GBAwQ7k?message=test",
            "1BRwWQ3GHabCV5DP6MfnCpr6dF6GBAwQ7k",
        ),
        (
            "bitcoin:bc1qx2zuday8d6j4ufh4df6e9ttd06lnfmn2cuz0vn?message=test",
            "bc1qx2zuday8d6j4ufh4df6e9ttd06lnfmn2cuz0vn",
        ),
        (
            "bitcoin:32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg?message=test",
            "32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg",
        ),
        (
            "bitcoin:3KLoUhwLihgC5aPQPFHakWUtJ4QoBkT7Aw?message=test",
            "3KLoUhwLihgC5aPQPFHakWUtJ4QoBkT7Aw",
        ),
    ]

    for case in cases:
        assert parse_address(case[0]) == case[1]


def test_parse_address_raises_errors(mocker, m5stickv, tdata):
    from krux.wallet import parse_address

    cases = [
        "invalidaddress",
        "32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg$",
        "bitcorn:32iCX1pY1iztdgM5qzurGLPMu5xhNfAUtg",
    ]
    for case in cases:
        with pytest.raises(ValueError):
            parse_address(case)


def test_to_unambiguous_descriptor(mocker, m5stickv, tdata):
    from embit.descriptor import Descriptor
    from krux.wallet import to_unambiguous_descriptor

    cases = [
        (
            tdata.AMBIGUOUS_SINGLESIG_DESCRIPTOR,
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
        ),
        (
            tdata.AMBIGUOUS_MULTISIG_DESCRIPTOR,
            tdata.UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
        ),
        (
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
            tdata.UNAMBIGUOUS_SINGLESIG_DESCRIPTOR,
        ),
        (
            tdata.UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
            tdata.UNAMBIGUOUS_MULTISIG_DESCRIPTOR,
        ),
        (
            tdata.UR_OUTPUT_MULTISIG_DESCRIPTOR,
            tdata.UR_OUTPUT_MULTISIG_DESCRIPTOR,
        ),
        (tdata.SPECTER_MULTISIG_DESCRIPTOR, tdata.SPECTER_MULTISIG_DESCRIPTOR),
    ]

    for case in cases:
        unambiguous_descriptor = to_unambiguous_descriptor(
            Descriptor.from_string(case[0])
        )
        assert unambiguous_descriptor.to_string() == case[1]


def test_version_to_network_versiontype():
    from embit.networks import NETWORKS
    from krux.wallet import version_to_network_versiontype

    for network_name, version_dict in [
        (k, v) for k, v in NETWORKS.items() if k in ("main", "test")
    ]:
        for versiontype, version in version_dict.items():
            assert version_to_network_versiontype(version) == (
                network_name,
                versiontype,
            )


def test_xpub_data_to_derivation():
    from krux.wallet import xpub_data_to_derivation, AssumptionWarning

    # purpose
    LEGACY = 44 + 2**31
    NATSW = 84 + 2**31
    NESSW = 49 + 2**31
    TAPROOT = 86 + 2**31
    MULTISIG = 48 + 2**31

    # network
    MAIN = 0 + 2**31
    TEST = 1 + 2**31

    # account
    ACCT0 = 0 + 2**31
    ACCT1 = 1 + 2**31

    # multisig script type
    MULTINESSW = 1 + 2**31
    MULTINATSW = 2 + 2**31

    cases = [
        # versiontype, network, child, depth, allow_assumption, expected_return
        ("xpub", "main", ACCT0, 3, None, AssumptionWarning),  # don't assume
        ("xpub", "main", ACCT0, 3, [NATSW, MAIN, ACCT0], [NATSW, MAIN, ACCT0]),
        ("xpub", "test", ACCT0, 3, [NATSW, TEST, ACCT0], [NATSW, TEST, ACCT0]),
        ("xpub", "main", ACCT1, 3, [NATSW, MAIN, ACCT1], [NATSW, MAIN, ACCT1]),
        ("xpub", "main", ACCT0, 4, [NATSW, MAIN, ACCT0], None),  # wrong depth
        ("ypub", "main", ACCT0, 3, None, [NESSW, MAIN, ACCT0]),
        ("ypub", "test", ACCT0, 3, None, [NESSW, TEST, ACCT0]),
        ("ypub", "main", ACCT1, 3, None, [NESSW, MAIN, ACCT1]),
        ("ypub", "test", ACCT1, 3, None, [NESSW, TEST, ACCT1]),
        ("ypub", "main", ACCT0, 4, None, None),  # wrong depth
        ("zpub", "main", ACCT0, 3, None, [NATSW, MAIN, ACCT0]),
        ("zpub", "test", ACCT0, 3, None, [NATSW, TEST, ACCT0]),
        ("zpub", "main", ACCT1, 3, None, [NATSW, MAIN, ACCT1]),
        ("zpub", "test", ACCT1, 3, None, [NATSW, TEST, ACCT1]),
        ("zpub", "main", ACCT0, 4, None, None),  # wrong depth
        ("Ypub", "main", MULTINESSW, 4, None, AssumptionWarning),  # don't assume
        ("Ypub", "test", MULTINESSW, 4, None, AssumptionWarning),
        (
            "Ypub",
            "main",
            MULTINESSW,
            4,
            [MULTISIG, MAIN, ACCT0, MULTINESSW],
            [MULTISIG, MAIN, ACCT0, MULTINESSW],
        ),
        (
            "Ypub",
            "test",
            MULTINESSW,
            4,
            [MULTISIG, TEST, ACCT0, MULTINESSW],
            [MULTISIG, TEST, ACCT0, MULTINESSW],
        ),
        ("Ypub", "main", MULTINESSW, 3, None, None),  # wrong depth
        ("Zpub", "main", MULTINATSW, 4, None, AssumptionWarning),  # don't assume
        ("Zpub", "test", MULTINATSW, 4, None, AssumptionWarning),
        (
            "Zpub",
            "main",
            MULTINATSW,
            4,
            [MULTISIG, MAIN, ACCT0, MULTINATSW],
            [MULTISIG, MAIN, ACCT0, MULTINATSW],
        ),
        (
            "Zpub",
            "test",
            MULTINATSW,
            4,
            [MULTISIG, TEST, ACCT0, MULTINATSW],
            [MULTISIG, TEST, ACCT0, MULTINATSW],
        ),
        ("Zpub", "main", MULTINATSW, 3, None, None),  # wrong depth
    ]

    for _case in cases:
        if type(_case[5]) == type and issubclass(_case[5], Exception):
            with pytest.raises(_case[5]):
                xpub_data_to_derivation(*_case[:5])
        else:
            assert xpub_data_to_derivation(*_case[:5]) == _case[5]


def test_derivation_to_script_wrapper():
    from krux.wallet import derivation_to_script_wrapper

    # purpose
    LEGACY = 44 + 2**31
    NATSW = 84 + 2**31
    NESSW = 49 + 2**31
    TAPROOT = 86 + 2**31

    # network
    MAIN = 0 + 2**31
    TEST = 1 + 2**31

    # account
    HARD = 0 + 2**31

    NOTHARD = 2**31 - 1

    cases = [
        # derivation list as the only function param and expected return
        ([HARD, MAIN], None),
        ([HARD, TEST], None),
        ([HARD, MAIN, HARD], None),
        ([NOTHARD, MAIN, HARD], None),
        ([LEGACY, MAIN, HARD], "pkh({})"),
        ([LEGACY, TEST, HARD], "pkh({})"),
        ([LEGACY, MAIN, NOTHARD], None),
        ([LEGACY, NOTHARD, HARD], None),
        ([NESSW, MAIN, HARD], "sh(wpkh({}))"),
        ([NESSW, TEST, HARD], "sh(wpkh({}))"),
        ([NESSW, MAIN, NOTHARD], None),
        ([NESSW, NOTHARD, HARD], None),
        ([NATSW, MAIN, HARD], "wpkh({})"),
        ([NATSW, TEST, HARD], "wpkh({})"),
        ([NATSW, MAIN, NOTHARD], None),
        ([NATSW, NOTHARD, HARD], None),
        ([TAPROOT, MAIN, HARD], "tr({})"),
        ([TAPROOT, TEST, HARD], "tr({})"),
        ([TAPROOT, MAIN, NOTHARD], None),
        ([TAPROOT, NOTHARD, HARD], None),
    ]

    for _case in cases:
        assert derivation_to_script_wrapper(_case[0]) == _case[1]


def test_parse_wallet_via_ur_output(mocker, m5stickv):
    from krux.wallet import parse_wallet

    # sparrow uses this ur format
    QRDATA = [
        # testnet legacy p2pkh
        "UR:CRYPTO-OUTPUT/TAADMUTAADDLOSAOWKAXHDCLAXJPDPECBNTOVEKOVOADIHWDDIBKHTHYAECWBSWPDEYTMSLEDRBSPMAMDEVAURWFDWAAHDCXKKSGMELBWMKOFRDMOEDAUEMUQDVDVANEBGVOMYGLKOVSFDSKDEJYKOGDGTINETTOAHTAADEHOEADAEAOADAMTAADDYOTADLNCSDWYKADYKAEYKAOCYTBFSSSOSAXAXAYCYLBZMISPFASIMGUIHIHIEGUINIOJTIHJPMEZMDWFY",
        # testnet nested segwit
        "UR:CRYPTO-OUTPUT/TAADMHTAADMWTAADDLOSAOWKAXHDCLAXPKGWJSLTINFRRELGGHECCMJLLKADKSHDRLDNDARLBZBACHSNAHHGNLDLLBGSTICFAAHDCXRPEETDCMQDWKBDPSBYJETBLGKTDNDRMSHHRFDIBEDREOLEKTBGMTBBOTKPFPWFWNAHTAADEHOEADAEAOADAMTAADDYOTADLNCSEHYKADYKAEYKAOCYTBFSSSOSAXAXAYCYINOTTORLASIEGRJPKPKSRYCEWNPF",
        # testnet native segwit
        "UR:CRYPTO-OUTPUT/TAADMWTAADDLOSAOWKAXHDCLAXRFBBVARYHNRLIMTLFEASUEOSGSRYOLBTCTSAHTIHKIDAMNPKLKFZTBHHMKKGKKGUAAHDCXHKMEMSKTVLNLSWDLUOGRDYBSFYIYIEJLCYVSJLNLMDLPJPNNGSSFMEIHHYCHLGENAHTAADEHOEADAEAOADAMTAADDYOTADLNCSGHYKADYKAEYKAOCYTBFSSSOSAXAXAYCYIDWEJPPKASIHFWGAGDEOESYKNYPEOT",
        # testnet taproot
        "UR:CRYPTO-OUTPUT/TAADNLTAADDLOSAOWKAXHDCLAOUYWTLNPRWYDIBNZCWEMHVWSTJYLGCNISEOPSEETEDMZTBSYTATJLAEZMNYDEEHCAAAHDCXHTRLUYDIRDNLDSYAZEKESWDYMTWNGSVAKTVWFGFEGUCSDNPDDTFRZMRTUTNSBSGTAHTAADEHOEADAEAOADAMTAADDYOTADLNCSHFYKADYKADYKAOCYTBFSSSOSAXAXAYCYOEWNPFHKASIMGUIHIHIEGUINIOJTIHJPDKZSVSIS",
    ]
    DESCRIPTORS = [
        "pkh([d63dc4a7/44h/1h/0h]tpubDCxxwY2QwiUCq8ievg9BurvmxfSa8LStd6XLh6meDBjK2BWynxq8M7d99P9yNBaCxSkUcxZrvnwgUsXbqP8SyJZY21C7Cm1R7M36xxSeiS6)",
        "sh(wpkh([d63dc4a7/49h/1h/0h]tpubDCoS7zq26q1CC75oB7zcNRvbXbQwAUf9gnhaS5vDYEZA2F8Maz7taNiKGbEWGY1fxEyWQgvCCQRGNBz87qej9XuyMXpTCtDbbKP6fXGtio1))",
        "wpkh([d63dc4a7/84h/1h/0h]tpubDCka9mfAaAN3cit16QqK2RCRVBpA2B7b8RFWUCLdyKR8eA48pjX7kZ5RAM6bSdwD9ivwh33KES7Q4DcqzNwkNUyyadZTTLf36Xp955vUBdf)",
        "tr([d63dc4a7/86h/1h/1h]tpubDDDs2UVFbhXBRTW4EJEH74qDcdVetqn5pF2AMcpMCfwvU561GJiY4BZoLPSpw4d6cb7wVHyu1JNa3dVjhKgmTKZ6m8M4L6wv763gHjhYAfd)",
    ]

    for i, QRDATUM in enumerate(QRDATA):
        wallet_data = URDecoder().decode(QRDATUM)
        descriptor, label = parse_wallet(wallet_data)
        assert str(descriptor) == DESCRIPTORS[i]
        print(DESCRIPTORS[i])


def test_parse_wallet_via_ur_account(mocker, m5stickv):
    from krux.wallet import parse_wallet

    # seedsigner uses this ur format when exporting for sparrow
    QRDATA = [
        # mainnet legacy p2pkh
        "UR:CRYPTO-ACCOUNT/OEADCYTBFSSSOSAOLYTAADMUTAADDLOXAXHDCLAODNLFAHCFGUJOYLESGDYNVANSDRGYTISWRTMWTTIAGUADAMPLONLAAEKPZOLGHSPMAAHDCXOLEOFRMSGELTHFPRJNVEECBBHDGOONEHMHBBTDVDAMCXVDMDROBZCWUYLDRERNHSAMTAADDYOTADLNCSDWYKAEYKAEYKAOCYTBFSSSOSAXAXAYCYBTWMBGPTAXUOCEVY",
        # mainnet nested segwit
        "UR:CRYPTO-ACCOUNT/OEADCYTBFSSSOSAOLYTAADMHTAADMWTAADDLOXAXHDCLAOFNVAJKFZAXCPCMJSAYYNYLCHEYESNLWDISVTVODAVTFZVEWLAMWYLDBNNTBEKECTAAHDCXSPYLEYCFMSHKJLGOMTTTEHCMNEPYSEIADTKPNBPMPKONIEWYAHPRADWDONYNGMSKAMTAADDYOTADLNCSEHYKAEYKAEYKAOCYTBFSSSOSAXAXAYCYVEZSGMCXTKYTCMKN",
        # mainnet native segwit
        "UR:CRYPTO-ACCOUNT/OEADCYTBFSSSOSAOLYTAADMWTAADDLOXAXHDCLAXZOCTGEIDHKEHSBHSDEZTJZWZJLFLMYAARSRFBWCLIDNELEVDDTWEDAMYURAECKSAAAHDCXGOSKCMDTKPFZJZSRJZHFHDQZJYLTIAZTQZMTZOCAIOCEECUESKAYECWFKPJZGOSPAMTAADDYOTADLNCSGHYKAEYKAEYKAOCYTBFSSSOSAXAXAYCYTBTEAXAODTCFGMBK",
        # mainnet taproot
        "UR:CRYPTO-ACCOUNT/OEADCYTBFSSSOSAOLYTAADNLTAADDLOXAXHDCLAXLKOENLDTDIFXOYDYUYHGOLFXSESOQZOXWSRTMHINPMSGKPNSHYIEBZVYVYRODKCEAAHDCXFTIDJNMSDWWPFDZSBNLSAORSKGGHTPGYFERSQDSFVSFWFYCYAOINCLWFLKSPMHFYAMTAADDYOTADLNCSHFYKAEYKAEYKAOCYTBFSSSOSAXAXAYCYKIWKJKVDYKTDJNUY",
    ]
    DESCRIPTORS = [
        "pkh([d63dc4a7/44h/0h/0h]xpub6Bkhh15pTDsqX2kEBaqLL9YTNwMBNkn8eL4vPEzPkKPG3dU1CtgNEfz6qMRH7ek8gonFWUe73Jg6Z2zVpYZMMgoXKsAnsuyFF6B3kZX81ed)",
        "sh(wpkh([d63dc4a7/49h/0h/0h]xpub6DLPFknTv1YuRkTAmXXkrdcMVtsWjwMG1WkCKgQqP2LbEfhbn4EyYGo8gxgqF6jozRfQEVafJRnt57Ua2gXXBqyPvKPzuQRQpfYbyEUh8Z1))",
        "wpkh([d63dc4a7/84h/0h/0h]xpub6DEMJ2Yce8xR9qAD4ZNfV4HuhhYCgNYbjDoZnuJprRQBtZCE7fgTLfLYdao26s3Pva1PBySwnSx9AtRtpSC3AsJ6LYuhKy1brMoc3Qe16t7)",
        "tr([d63dc4a7/86h/0h/0h]xpub6CaTuhnAha3kjK1bZQxYbmyw8PcM6UypdK9MTdJY41Xxyg2dVws9LwuB5bL1fFPqJiAkBAoSwpcfEjEwwJ2byNeM4xxXKSa45TcHxLhQKPh)",
    ]

    for i, QRDATUM in enumerate(QRDATA):
        wallet_data = URDecoder().decode(QRDATUM)
        descriptor, label = parse_wallet(wallet_data)
        assert str(descriptor) == DESCRIPTORS[i]
        print(DESCRIPTORS[i])
