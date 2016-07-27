# WebSocket_cURL
cURL like command for WebSocket

WebSocket_cURL is a command line tool like cURL command for WebSocket 
which enables you to send a stirng or binary file as WebSocket data. 
Also you can replay array data from Wireshark capture.

This script is not only sending data but also there is a cool feature, FrameCrafter, that 
enables you to modify WebSocket frame, then send it or save to a file.

# Supported Features

* General WebSocket_cURL features
Send data in one-liner command like cURL command

Sending a string data. This is --string (-s) option. 
  
$ python WebSocket_cURL HOST PORT URL --string "DEAD BEEF"

Sending a binary file. This is --binary (-b) option.

$ python WebSocket_cURL HOST PORT URL --binary myfile.bin

Sending an array file. This is --array (-a) option.
You can copy/paste array data from Wireshark or you can generate via FrameCrafter feature, --editor option.

$ cat myarray.txt (copied from Wireshark)

0x81, 0x9c, 0x39, 0x5d, 0xcf, 0x95, 0x6b, 0x32,
0xac, 0xfe, 0x19, 0x34, 0xbb, 0xb5, 0x4e, 0x34,
0xbb, 0xfd, 0x19, 0x15, 0x9b, 0xd8, 0x75, 0x68,
0xef, 0xc2, 0x5c, 0x3f, 0x9c, 0xfa, 0x5a, 0x36,
0xaa, 0xe1

$ python WebSocket_cURL HOST PORT URL --array myarray.txt


* FrameCrafter

Use --editor (-e) option at the end of the command to enter FrameCrafter menu where you can
flip/overwrite WebSocket frame fields. You can create crafted/malformed frame.
Save the modified data to a file so that you can read/send via -a option.

$ python WebSocket_cURL.py 192.168.0.10 9090 /ws -s "DEAD BEEF" -e                 
-------------------------------------
* Frame Header bits                 *
-------------------------------------
  1000000110001001 0100001001000101
  0100010101000110 0000011000000000
  0000010000000010
-------------------------------------
* Frame Header Analizer             *
-------------------------------------
FIN        [0th bit]: 1
RSV     [1-3th bits]: 000
opcode  [4-7th bits]: 0001
MASK       [8th bit]: 1
Length [9-15th bits]: 9 byte
-----------------------------
* Frame Crafter Menu        *
-----------------------------
Flip FIN bit: F
Flip RSV1 bit: R1
Flip RSV2 bit: R2
Flip RSV3 bit: R3
Overwrite Opcode: O
Flip MASK bit: M
Change Length: L
Write to file: W

Send frame as it is: S

Input: 



# Command Syntax 

$ python WebSocket_cURL.py --help

Usage: WebSocket_cURL.py [OPTIONS] HOST PORT URL

Options:

  -s, --string TEXT      Give a string to send

  -b, --binary FILENAME  Give a path of a binary data

  -a, --array FILENAME   Give a path of frame hex data

  -e, --editor           This enters FrameCrafter menu

  -H, --header TEXT      Add HTTP headers

  --help                 Show this message and exit.
