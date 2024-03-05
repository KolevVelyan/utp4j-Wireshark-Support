# utp4j-Wireshark-Support
 A lua script for Wireshark to be able to parse [utp4j](https://github.com/iiljkic/utp4j) protocol packets (EXPERIMENTAL).

## How to use
1. Install Wireshark
2. Copy the `utp4j.lua` file to the Wireshark's plugins folder
3. In the last line of the `utp4j.lua` file, change `12345` to the port number you want to filter on.
4. Open Wireshark and start capturing packets (might need to press `Ctrl+Shift+L` to apply the filter)

## Protocol Specification
This script is based on the [uTP implementation in Java by iiljkic](https://github.com/iiljkic/utp4j).

## Notice
This is an experimental script and provides very basic parsing of the utp4j protocol. It is not guaranteed to work in all cases and might not be able to parse all packets. It is recommended to use this script for testing and debugging purposes only. Feel free to improve it.
