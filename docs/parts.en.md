# Part List

## M5StickV
Available from many distributors, including:

- [M5Stack](https://shop.m5stack.com/products/stickv)
- [Adafruit](https://www.adafruit.com/product/4321)
- [Mouser](https://www.mouser.com/ProductDetail/Adafruit/4321)
- [Digi-Key](https://www.digikey.com/en/products/detail/m5stack-technology-co-ltd/K027/10492135)
- [Lee's Electronic](https://leeselectronic.com/en/product/169940-m5stick-ai-camera-kendryte-k210-risc-v-core-no-wifi.html)
- [Cytron](https://www.cytron.io/c-development-tools/c-fpga/p-m5stickv-k210-ai-camera-without-wifi)
- [Pimoroni](https://shop.pimoroni.com/products/m5stick-v-k210-ai-camera-without-wifi)
- [OKDO](https://www.okdo.com/p/m5stickv-k210-ai-camera-without-wifi/)

You can expect to pay around $50 for one depending on which distributor you choose.

## Maix Amigo
Available from many distributors, including:

- [Seeed Studio](https://www.seeedstudio.com/Sipeed-Maix-Amigo-p-4689.html)
- [Mouser](https://www.mouser.com/ProductDetail/Seeed-Studio/102110463)
- [Digi-Key](https://www.digikey.com/en/products/detail/seeed-technology-co-ltd/102110463/13168813)

You can expect to pay around $70 for one depending on which distributor you choose.

## Maix Dock and Maix Bit
For the DIYers, the Maix Dock and Bit are also supported but will require sourcing the parts individually and building the device yourself.

Below are example implementations created by [odudex](https://twitter.com/odudex) with instructions on how to recreate them:

- [https://github.com/selfcustody/DockEncoderCase](https://github.com/selfcustody/DockEncoderCase)
- [https://github.com/selfcustody/MaixBitCase](https://github.com/selfcustody/MaixBitCase)

## USB-C Charge Cable
This will be included with the M5StickV and Maix Amigo that you purchase from one of the distributors above. It will be necessary to power and charge the device and to initially flash the firmware.

## (Optional) MicroSD Card
Not all microSD cards will work with the devices. Make sure to use one that has been [tested and shown to work](https://github.com/m5stack/m5-docs/blob/master/docs/en/core/m5stickv.md#tf-cardmicrosd-test) with the devices already. The size of the SD card isn't important; anything over a few megabytes will be plenty.

## (Optional) Thermal Printer
Krux has the ability to print all QR codes it generates, including mnemonic, xpub, wallet backup, and signed PSBT, via a locally-connected [thermal printer from Adafruit](https://www.adafruit.com/?q=thermal+printer) over its serial port.

Any of their thermal printers will work, but the [starter pack](https://www.adafruit.com/product/600) would be the easiest way to get started since it includes all the parts (except the one below) you will need to begin printing.

## (Optional) Conversion Cable for Thermal Printer
To connect the printer to the device, you will need a [conversion cable](https://store-usa.arduino.cc/products/grove-4-pin-male-to-grove-4-pin-cable-5-pcs) with a 4-pin female Grove connector on one end (to connect to the device) and 4-pin male jumpers on the other end (to connect to the printer). You can find them at one of the distributors above or from Amazon.
