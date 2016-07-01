# WebSocket_cURL
cURL like command for WebSocket

WebSocket_cURL is a command line tool like cURL command for WebSocket 
which enables you to send a stirng or binary file as WebSocket data. 
Also you can replay array data from Wireshark capture.

This script is not only sending data but also there is a cool feature, FrameCrafter, that 
enables you to modify WebSocket frame, then send it or save to a file.

Supported Features
------------------
General WebSocket_cURL features
* Sending a string data. This is -s option. 
* Sending a binary file. This is -b option.
* Reading an array file and send it. This is -a option.

FrameCrafter
Use -x option at the end of the command to enter FrameCrafter menu where you can
* flip/overwrite WebSocket frame fields. You can create crafted/malformed frame.
* Save the modified data to a file so that you can read/send via -a option.

Command Syntax 
--------------
$ python WebSocket_cURL.py <IP ADDRESS> <PORT> [-s|-b|-a] ["string"|binary file|array file] -x (optional)

How to use
-----------
Send a small string data

$ python WebSocket_cURL.py 192.168.0.101 80 -s "DEAD BEEF"

Send a large string data, with bash script

$ str=; tmp=a; for i in {1..65535}; do str=$str$tmp; done; python WebSocket_cURL.py 192.168.0.101 80 -s "$str"

Send a binary file

$ python WebSocket_cURL.py 192.168.0.101 80 -b 50byte.bin

Send an array file 

$ cat array

0x81, 0x9c, 0x39, 0x5d, 0xcf, 0x95, 0x6b, 0x32,
0xac, 0xfe, 0x19, 0x34, 0xbb, 0xb5, 0x4e, 0x34,
0xbb, 0xfd, 0x19, 0x15, 0x9b, 0xd8, 0x75, 0x68,
0xef, 0xc2, 0x5c, 0x3f, 0x9c, 0xfa, 0x5a, 0x36,
0xaa, 0xe1

$ python WebSocket_cURL.py 192.168.0.101 80 -a array
 
FrameCrafter

$ python WebSocket_cURL.py 192.168.0.101 80 -s "DEAD BEEF" -x
