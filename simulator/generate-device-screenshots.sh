# The MIT License (MIT)

# Copyright (c) 2021-2022 Krux contributors

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

#!/bin/bash

device=$1
locale=$2

rm -rf screenshots && mkdir -p screenshots
rm -rf sd && mkdir -p sd && rm -f sd/settings.json
echo "{\"settings\": {\"i18n\": {\"locale\": \"$locale\"}}}" > sd/settings.json

poetry run python simulator.py --sequence sequences/about.txt --sd --device $device
poetry run python simulator.py --sequence sequences/logging-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/extended-public-key-wpkh.txt --sd --device $device
poetry run python simulator.py --sequence sequences/extended-public-key-wsh.txt --sd --device $device
poetry run python simulator.py --sequence sequences/home-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/load-mnemonic-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/load-mnemonic-via-bits.txt --sd --device $device
poetry run python simulator.py --sequence sequences/load-mnemonic-via-numbers.txt --sd --device $device
poetry run python simulator.py --sequence sequences/load-mnemonic-via-qr.txt --sd --device $device
poetry run python simulator.py --sequence sequences/load-mnemonic-via-text.txt --sd --device $device
poetry run python simulator.py --sequence sequences/language-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/login-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/logo.txt --sd --device $device
poetry run python simulator.py --sequence sequences/mnemonic-12-word.txt --sd --device $device
poetry run python simulator.py --sequence sequences/mnemonic-24-word.txt --sd --device $device
poetry run python simulator.py --sequence sequences/bitcoin-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/new-mnemonic-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/new-mnemonic-via-d6.txt --sd --device $device
poetry run python simulator.py --sequence sequences/new-mnemonic-via-d20.txt --sd --device $device
poetry run python simulator.py --sequence sequences/print-qr.txt --sd --printer --device $device
poetry run python simulator.py --sequence sequences/printer-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/thermal-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/scan-address.txt --sd --device $device
poetry run python simulator.py --sequence sequences/settings-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/shutdown.txt --sd --device $device
poetry run python simulator.py --sequence sequences/sign-message.txt --sd --device $device
poetry run python simulator.py --sequence sequences/sign-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/sign-psbt.txt --sd --device $device
poetry run python simulator.py --sequence sequences/wallet-type-options.txt --sd --device $device
poetry run python simulator.py --sequence sequences/wallet-wpkh.txt --sd --device $device
poetry run python simulator.py --sequence sequences/wallet-wsh.txt --sd --device $device
