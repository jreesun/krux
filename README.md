[![downloads](https://img.shields.io/github/downloads/selfcustody/krux/total)](https://github.com/selfcustody/krux/releases)
[![codecov](https://codecov.io/gh/selfcustody/krux/branch/main/graph/badge.svg?token=XU80PT6Q9V)](https://codecov.io/gh/selfcustody/krux)
[![calver](https://img.shields.io/badge/calver-YY.0M.MICRO-22bfda.svg)](https://calver.org)

<p align="center">
<img src="https://selfcustody.github.io/krux/img/maixpy_m5stickv/logo-125.png">
<img src="https://selfcustody.github.io/krux/img/maixpy_amigo_tft/logo-125.png">
</p>

Krux is open-source firmware that enables anyone to build their own Bitcoin signing device via off-the-shelf parts. It runs on Kendryte K210 devices such as the [M5StickV](https://docs.m5stack.com/en/core/m5stickv) and [Maix Amigo](https://www.seeedstudio.com/Sipeed-Maix-Amigo-p-4689.html), converting them into airgapped devices that can sign transactions for multisignature and single-key wallets.

---
## Disclaimer
**WARNING**: *This software has not yet been audited by a third party. Use at your own risk!*

---

# Getting Started
Instructions for building and running Krux can now be found on our GitHub Pages site:

https://selfcustody.github.io/krux/

The instructions below are intended for developers who wish to contribute to the project.

# Development
## Fetch the code
Run the following:
```bash
git clone --recurse-submodules https://github.com/selfcustody/krux
```
This will pull down the Krux source code as well as the code for all its dependencies and put them inside a new `krux` folder.

Note: When you wish to pull down updates to this repo, you should run the following:
```bash
git pull origin main && git submodule update --init --recursive
```
This will make sure that all submodules (and their submodules, etc.) are pulled down and updated.

## Krux (script)
The [krux](krux) bash script contains commands for common development tasks. It assumes a Linux host, but may work on other systems. For this reason, we suggest you use [Vagrant](https://www.vagrantup.com/) since all dependencies for development will be included. If running outside of Vagrant, you will need to have [Docker](https://www.docker.com/), `openssl`, and `wget` installed at a minimum for the commands to work as expected.

For building and flashing Krux from within Vagrant, please follow the [Installing from source](https://selfcustody.github.io/krux/getting-started/installing-from-source) guide on the website.

Otherwise, to run the commands on bare metal, remove the `vagrant ssh -c 'cd /vagrant; <command>'` wrapper from all commands like so:

```bash
# build firmware for MaixDock
# vagrant ssh -c 'cd /vagrant; ./krux build maixpy_dock'
./krux build maixpy_dock

# flash the firmware to a MaixDock
# vagrant ssh -c 'cd /vagrant; ./krux flash maixpy_dock'
./krux flash maixpy_dock
```

## Install krux and dev tools
The krux code is a Python package that should be installed with [Poetry](https://python-poetry.org/).
```bash
pip install poetry
poetry install
```

This will also install all development tools so that you can run tests, run pylint, format code with [black](https://github.com/psf/black), etc.

Note that you can run `poetry install` after making a change to the krux code if you wish to test a change in the [interpreter](#use-the-python-interpreter-repl).

## Format code
```bash
poetry run black ./src
poetry run black ./tests
```

## Run pylint
```bash
poetry run pylint ./src
```

## Run tests
```bash
poetry run pytest --cache-clear --cov src/krux --cov-report html ./tests
```
This will run all tests and generate a coverage report you can browse to locally in your browser at `file:///path/to/krux/htmlcov/index.html`.

For more verbose test output (e.g., to see the output of print statements), run:

```bash
poetry run pytest --cache-clear --cov src/krux --cov-report html --show-capture all --capture tee-sys -r A ./tests
```

## Use the Python interpreter (REPL)
This can be useful for testing a change to the krux code without having to run a full build and flash:
```bash
poetry run python
```
```
Python 3.9.1
Type "help", "copyright", "credits" or "license" for more information.
>>> from krux.key import Key
>>> Key("olympic term tissue route sense program under choose bean emerge velvet absurd", False).xpub()
'tpubDCDuqu5HtBX2aD7wxvnHcj1DgFN1UVgzLkA1Ms4Va4P7TpJ3jDknkPLwWT2SqrKXNNAtJBCPcbJ8Tcpm6nLxgFapCZyhKgqwcEGv1BVpD7s'
>>>
```

## Run the simulator
This can be useful for testing a change to the krux code without having to run a full build and flash, visual regression testing,
generating screenshots, or even just trying out Krux before purchasing a device.

Before executing the simulator, make sure you have installed the poetry extras:
```bash
poetry install --extras simulator
```

Run the simulator:
```bash
# Enter simulator folder
cd simulator

# Run simulator with the touch device amigo, then use mouse to navigate
poetry run python simulator.py --device maixpy_amigo_tft

# Run simulator with the small button-only m5stick, then use keyboard to navigate
poetry run python simulator.py --device maixpy_m5stickv
```

Simulator error troubleshooting:
```bash
# ImportError: Unable to find zbar shared library
sudo apt install python3-zbar

# ImportError: libGL.so.1: cannot open shared object file: No such file or directory
sudo apt install libgl1

# `pygame.error: No available video device`
# You are trying to run the simulator on an OS without a GUI (some kind of terminal only or WSL). Try one with GUI!
```

Simulator sequences (automatic testing):
```bash
# Enter simulator folder:
cd simulator

# Run all sequences of commands on all devices and in all locales (languages)
./generate-all-screenshots.sh

# Run a specific sequence for a specific device (need to have the screenshots and the sd folder with the file settings.json inside)
poetry run python simulator.py --sequence sequences/about.txt --sd --device maixpy_m5stickv
```

## Live debug a device
If you've made a fresh build and flashed it to your device, you can connect to the device over serial connection with:
```bash
screen /dev/tty.usbserial-device-name 115200
```

If you see a `Resource is busy` message, make sure to shut down the Vagrant box and try again:
```bash
vagrant halt
```

If successful, the device should restart and you should see:
```bash
K210 bootloader by LoBo v.1.4.1

* Find applications in MAIN parameters
0: '       firmware', @ 0x00080000, size=XXX, app_size=XXX, App ok, ACTIVE
* Loading app from flash at 0x00080000 (XXX B)
* Starting at 0x80000000 ...


[MAIXPY] Pll0:freq:XXX
[MAIXPY] Pll1:freq:XXX
[MAIXPY] Pll2:freq:XXX
[MAIXPY] cpu:freq:XXX
[MAIXPY] kpu:freq:XXX
[MAIXPY] Flash:0xef:0x17
[MaixPy] gc heap=0x8029f430-0x8036f430(851968)
init i2c:2 freq:XXX
[MAIXPY]: find ov7740
[MAIXPY]: find ov sensor
```

Krux makes use of MaixPy's [WDT watchdog module](https://wiki.sipeed.com/soft/maixpy/en/api_reference/machine/wdt.html), you can see it [here](src/krux/wdt.py). This will reset the device if not fed for some time. To stop the watchdog, when connected through the terminal, run the following:
```python
# This will read the board config file, add the config to disable watchdog, save the new config file and reset the device (in order to make krux read the new file!)

import json, machine

CONF_FILENAME="/flash/config.json"
CONF_NAME="WATCHDOG_DISABLE"

conf_dict = {}
try:
  with open(CONF_FILENAME, "rb") as f:
    conf_dict = json.loads(f.read())
except:
    pass

conf_dict[CONF_NAME] = 1

with open(CONF_FILENAME, "w") as f:
    f.write(json.dumps(conf_dict))
    
machine.reset()
```

Now, with watchdog disabled, you can use the device normally. So no more automatic resets, and if you added any print statements to the code, they should appear whenever your code is reached.

You can also drop into a live Python REPL at any point by issuing an interrupt with Ctrl-C:

```bash
Traceback (most recent call last):
  File "boot.py", line 38, in <module>
  File "krux/pages/__init__.py", line 192, in run
  File "krux/pages/__init__.py", line 207, in run_loop
  File "krux/input.py", line 27, in wait_for_button
KeyboardInterrupt:
MicroPython; Sipeed_M1 with kendryte-k210
Type "help()" for more information.
>>>
>>>
```

Customizations made to the firmware removed the support to MaixPy IDE (due to size constraints), but you still can use it's terminal (MaixPy IDE menu bar > Tools > Open Terminal).

## Create new translations - i18n

The project has lots of translations [here](i18n/translations), if you add new english messages in code using `t()` function, you will need to:

```bash
# Enter i18n folder:
cd i18n

# Make sure all files have this new translated message:
python3 i18n.py validate

# Format translation files properly:
python3 i18n.py prettify

# Create the compiled table for krux translations.py
python3 i18n.py bake
```

## Run mkdocs
```bash
poetry run mkdocs serve
```

# Inspired by these similar projects
- https://github.com/SeedSigner/seedsigner for Raspberry Pi (Zero)
- https://github.com/diybitcoinhardware/f469-disco for the F469-Discovery board

# Powered by
- [embit](https://embit.rocks/), a Bitcoin library for Python 3 and Micropython
- [MaixPy](https://github.com/sipeed/MaixPy), MicroPython for K210 RISC-V
- [MicroPython](https://github.com/micropython/micropython), a lean and efficient Python implementation for microcontrollers and constrained systems
- [Kboot](https://github.com/loboris/Kboot) and [ktool](https://github.com/loboris/ktool)

# Contributing
Issues and pull requests welcome! Let's make this as good as it can be.

Before opening a pull request for a new feature, please first start a [new discussion](https://github.com/selfcustody/krux/discussions) if the feature is large, is a proposal, or is in need of fleshing out before it can be turned into issue(s) for work. If the pull request you're opening already has an associated issue, please reference it when making your pull request and briefly explain how your PR resolves it. Ideally, each PR should be focused on resolving one issue (exceptions can be made if the work is related or tightly coupled).

**Please note**: When adding a new feature, please checkout and branch off of the `develop` branch. When making a PR, please also make sure to explicitly target `develop`; `main` is the default branch on GitHub because we want it to be easy for users (who aren't necessarily devs) to download and install Krux from source.

# Support
For technical support installing or using Krux, you can join our [#krux:matrix.org](https://matrix.to/#/#krux:matrix.org) server or [Telegram chat](https://t.me/SC_Krux). Make sure to also check out the [DIYbitcoin chat](https://t.me/diybitcoin) on Telegram, a broader community of tinkerers, builders, hackers, etc.

We do not use GitHub issues for support requests, only for bug reports and feature requests. 

You can also post a question in our [Discussions](https://github.com/selfcustody/krux/discussions) forum here on GitHub.
