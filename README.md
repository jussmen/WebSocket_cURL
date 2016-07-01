# WebSocket_cURL
cURL like command for WebSocket

WebSocket_cURL is a command line tool like cURL command for WebSocket 
which enables you to send a stirng or binary file as WebSocket data. 
Also you can replay array data from Wireshark capture.

This script is not only sending data but also there is a cool feature, FrameCrafter, that 
enables you to modify WebSocket frame, then send it or save to a file.

# Supported Features

General WebSocket_cURL features
* Sending a string data. This is -s option. 
* Sending a binary file. This is -b option.
* Reading an array file and send it. This is -a option.

FrameCrafter
Use -x option at the end of the command to enter FrameCrafter menu where you can
* flip/overwrite WebSocket frame fields. You can create crafted/malformed frame.
* Save the modified data to a file so that you can read/send via -a option.

# Command Syntax 
$ python WebSocket_cURL.py <IP ADDRESS> <PORT> [-s|-b|-a] ["string"|binary file|array file] -x (optional)

Please have a look at HOWTO.txt for actual syntax examples.
