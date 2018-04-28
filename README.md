1. Use microchip ACES to init the ATECC508A chip.
2. Execute GenKey Command with mode 0x04 .
3. Use sha256sum on linux to get a checksum for some random data. the result is a hex string with length of 64 bytes.
4. Execute Nonce command with mode 0x03 to load the sha256 result.
5. Execute Sign command with mode 0x80.
6. Get the sign result to this program and verify the result.
7. Read the Datasheet of ATECC508A.
8. http://ww1.microchip.com/downloads/en/DeviceDoc/20005927A.pdf