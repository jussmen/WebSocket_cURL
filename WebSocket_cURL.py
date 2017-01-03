# --- coding: UTF-8 ---

'''
WebSocket_cURL.py

Copyright (c) 2016 Kimihito Tanaka

This software is released under the MIT License.
http://opensource.org/licenses/mit-license.php

'''

# Version: Ver1.0

from __future__ import print_function
import sys
import socket
from contextlib import closing
from array import array
import click
import re

class SyntaxHandler():
    u''' This class handles command arguments '''
    
    def __init__(self, arg):
        for i in range(len(sys.argv)):
            if sys.argv[i] == '-h' or sys.argv[i] == '--help':
                print ('')
                print ('Syntax: python xxxx.py <HOST> <PORT> <OPCODE> <[FILE|STRING]>')
                print ('')
                print ('HOST   : hostname or ip address of the WebSocket server')
                print ('PORT   : TCP port number of the WebSocket server')
                print ('Option :')
                print ('  -a  Array option. Supply array file path')
                print ('  -s  String option. Supply strings with double quote')
                print ('  -b  Binary file option. Supply binary file path')
                print ('-x for 5th argument : WebSocket Frame Crafte Menu')
                sys.exit()
    
    def opcodeCheck(self, arg):
        u''' This checks sys.argv[3] and if it does not match none of the supported options, then spits an error. '''
        if sys.argv[3] != '-a' and sys.argv[3] != '-s' and sys.argv[3] != '-b':
            print ('\nWrong opcode. See help')
            sys.exit()

class WebSocket_cURL():
    u''' Open socket and establish WebSocket '''
    
    def __init__(self, host, port, url, opcode, data_to_send, custom_header):
        # Constructing socket
        self.host = host
        self.port = int(port)
        self.bufsize = 4096
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Constructing header
        self.header = 'GET /' + url + ' HTTP/1.1\n'
        self.header += 'Host: ' + host + '\n'
        self.header += 'Connection: Upgrade\n'
        self.header += 'Upgrade: websocket\n'
        self.header += 'Sec-WebSocket-Version: 13\n'
        self.header += 'Sec-WebSocket-Key: n5twxG/tNPf8h3po+pNrPA==\n'
        self.header += 'User-Agent: WebSocket_cURL\n'
        for h in custom_header:
            self.header += h + '\n'
        self.header += '\n'
        # Constructing data
        self.data_to_send = data_to_send
        #print ('')
        #print ('Data to send : ', end='')
        #print (data_to_send)
        #print ('')
        # Constructing close frame
        self.arr_close_frame = array('B', [])
        # 136 = FIN 1, RSV 0, OP Connection Close  
        # 128 = Mask True, Len 0 
        # 66,69,69,70 = 'BEEF'
        self.close_frame = [136, 128, 66, 69, 69, 70] 
        for i in self.close_frame:
            self.arr_close_frame.append(i)
        
    def run(self):
        with closing(self.sock):
            self.sock.connect((self.host, self.port))
            print (self.header)
            self.sock.send(self.header)
            print(self.sock.recv(self.bufsize))
            
            #print('sending WebScoket frame')
            self.sock.send(self.data_to_send)
            #self.sock.recv(self.bufsize)
            self.sock.send(self.arr_close_frame)
            self.sock.recv(self.bufsize)
        return 

class DataHandler():
    
    def __init__(self, op, data):
        self.arrdata = array('B', [])  # This is the final data to send
        self.generated_frame_list = [] # This is used by string mode and binary mode
        self.payload_list = [] # This is used to pass maskPayload(). Both string and binary data need to be put in this.
        self.payloadLen = 0
        if op == '-a':
            self.readArray(data)
            self.genArrayFromHex()
        elif op == '-s':
            self.string = data
            self.payloadLen = len(data)
            self.genTextFrame(self.string)
        elif op == '-b':
            self.readBinaryFile(data)
            self.payloadLen = len(self.binary_hexlist)
            self.genBinaryFrame()
            
    def genBinaryFrame(self):
        if self.payloadLen <= 125:
            # Generating FIN, RSV, Masking-key, length
            # print ('binary length is <= 125')
            self.generated_frame_list.append(130) # 0b10000010, FIN=1, RSV=0, OP=2
            self.generated_frame_list.append(128 + self.payloadLen)
            self.generated_frame_list.append(66) # Masking-key, 'BEEF'
            self.generated_frame_list.append(69) 
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(70)
            # From here, binary payload
            for i in self.binary_hexlist:
                self.payload_list.append(i)
            #print ('this is self.payload_lsit in Binary mode')
            #print (self.payload_list)
            self.maskBinaryPayload()
            self.genArrayFromHexBin()
        elif self.payloadLen >= 126 and self.payloadLen <= 65535: # maximum payload length can be 65535
            self.generated_frame_list.append(130) # FIN=1, RSV=0, OP=2
            self.generated_frame_list.append(254) # Mask=True(128), Len=126
            # Extended length 16bit
            self.generated_frame_list.append((self.payloadLen & 65280) >> 8) # Getting MSB
            self.generated_frame_list.append(self.payloadLen & 255) # Getting LSB
            self.generated_frame_list.append(66) # Mask is 'BEEF'
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(70)
            #print (self.generated_frame_list)
            # Header fields are 8 bytes. Further bytes are payload
            for i in range(self.payloadLen):  # Generating payload_list
                self.payload_list.append(self.binary_hexlist[i])
            self.maskBinaryPayload()
            self.genArrayFromHexBin()
        elif self.payloadLen >= 65536:
            self.generated_frame_list.append(130) # FIN=1, RSV=0, OP=2
            self.generated_frame_list.append(255) # Mask=True(128), Len=127
            # Extended length 64bit
            self.generated_frame_list.append((self.payloadLen & 18374686479671623680) >> 56) # MSB
            self.generated_frame_list.append((self.payloadLen & 71776119061217280) >> 48) # Next 8bits, and so on
            self.generated_frame_list.append((self.payloadLen & 280375465082880) >> 40)
            self.generated_frame_list.append((self.payloadLen & 1095216660480) >> 32)
            self.generated_frame_list.append((self.payloadLen & 4278190080) >> 24)
            self.generated_frame_list.append((self.payloadLen & 16711680) >> 16)
            self.generated_frame_list.append((self.payloadLen & 65280) >> 8)
            self.generated_frame_list.append(self.payloadLen & 255) # LSB
            self.generated_frame_list.append(66) # Mask is 'BEEF'
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(70)
            #print (self.generated_frame_list)
            # Header fields are 14 bytes. Further bytes are payload
            for i in range(self.payloadLen):
                self.payload_list.append(self.binary_hexlist[i])
            self.maskBinaryPayload()
            self.genArrayFromHexBin()
        
    def genTextFrame(self, payload):
        #print (self.payloadLen)
        if self.payloadLen <= 125:
            #print ('String length 125')
            # Generating FIN, RSV, Making-key, length 
            self.generated_frame_list = []
            self.generated_frame_list.append(129) # 0b10000001, FIN=1, RSV=0, OP=1
            self.generated_frame_list.append(128 + self.payloadLen)
            self.generated_frame_list.append(66) # Masking-key, 'BEEF'
            self.generated_frame_list.append(69) 
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(70)
            # From here, doing payload
            self.payload_list = list(payload)
            #print (self.payload_list)
            self.maskPayload() # Comment out this to DISABLE payload masking. Usefull to test
            for char in self.payload_list:
                self.generated_frame_list.append(ord(char)) # conver string to ASCII code
            # Use this to check generated frame
            #for i in self.generated_frame_list:
            #    print (i, end='')
            #    print ('  ' + hex(i))
            
            self.genArrayFromInt()
        elif self.payloadLen  >= 126 and self.payloadLen <= 65535:
            #print ('string length 126')
            self.generated_frame_list.append(129) # FIN=1, RSV=0, OP=1
            self.generated_frame_list.append(254) # Mask=True(128), Len=126
            # Extended length 16bit
            self.generated_frame_list.append((self.payloadLen & 65280) >> 8) # Getting MSB
            self.generated_frame_list.append(self.payloadLen & 255) # Getting LSB
            self.generated_frame_list.append(66) # Mask is 'BEEF'
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(70)
            self.payload_list = list(payload)
            self.maskPayload()
            for char in self.payload_list:
                self.generated_frame_list.append(ord(char))
            self.genArrayFromInt()
        elif self.payloadLen >= 65536:
            #print ('string length 127')
            self.generated_frame_list.append(129) # FIN=1, RSV=0, OP=2
            self.generated_frame_list.append(255) # Mask=True(128), Len=127
            # Extended length 64bit
            self.generated_frame_list.append((self.payloadLen & 18374686479671623680) >> 56) # MSB
            self.generated_frame_list.append((self.payloadLen & 71776119061217280) >> 48) # Next 8bits, and so on
            self.generated_frame_list.append((self.payloadLen & 280375465082880) >> 40)
            self.generated_frame_list.append((self.payloadLen & 1095216660480) >> 32)
            self.generated_frame_list.append((self.payloadLen & 4278190080) >> 24)
            self.generated_frame_list.append((self.payloadLen & 16711680) >> 16)
            self.generated_frame_list.append((self.payloadLen & 65280) >> 8)
            self.generated_frame_list.append(self.payloadLen & 255) # LSB
            self.generated_frame_list.append(66) # Mask is 'BEEF'
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(69)
            self.generated_frame_list.append(70)
            self.payload_list = list(payload)
            self.maskPayload()
            for char in self.payload_list:
                self.generated_frame_list.append(ord(char))
            self.genArrayFromInt()
         
    def readArray(self, file):
        self.f = file
        self.hexlist = self.f.read()
        self.hexlist = self.hexlist.replace(' ', '')
        self.hexlist = self.hexlist.replace('\n', '')
        self.hexlist = self.hexlist.split(',')
         
    def readBinaryFile(self, file):
        self.f = open(file, 'rb')
        self.binary_hexlist = []
        for b in self.f.read():
            self.binary_hexlist.append(hex(ord(b)))
        
    def genArrayFromHex(self): # -a
        for hex in self.hexlist:
            self.arrdata.append(int(hex, 16))
         
    def genArrayFromHexBin(self): # -b
        for i in self.generated_frame_list:
            self.arrdata.append(i)
        #for hex in self.binary_hexlist:
        for i in self.payload_list:
            self.arrdata.append(i)
        
    def genArrayFromInt(self): # -s
        for i in self.generated_frame_list:
            self.arrdata.append(i)

    def getArray(self):
        #print (self.arrdata)
        return self.arrdata
        
    def maskPayload(self):
        if (self.generated_frame_list[1] & 127) == 127:
            for i in range(len(self.payload_list)):
                self.masking_octet = i % 4
                # Original payload octet
                #print ('Original payload octet')
                #print (bin(ord(self.payload_list[i]))) 
                # Masking octet
                #print ('Masking octet')
                #print (bin(self.generated_frame_list[self.masking_octet + 10]))
                # XOR result
                #print ('XOR result')
                #print (bin(ord(self.payload_list[i]) ^ self.generated_frame_list[self.masking_octet + 10]))
                # convert to ASCII and calc. Then, convert back to character
                self.payload_list[i] = chr(ord(self.payload_list[i]) ^ self.generated_frame_list[self.masking_octet + 10])
                #print ('')
        elif (self.generated_frame_list[1] & 127) == 126:
            for i in range(len(self.payload_list)):
                self.masking_octet = i % 4
                # Original payload octet
                #print ('Original payload octet')
                #print (bin(ord(self.payload_list[i]))) 
                # Masking octet
                #print ('Masking octet')
                #print (bin(self.generated_frame_list[self.masking_octet + 4]))
                # XOR result
                #print ('XOR result')
                #print (bin(ord(self.payload_list[i]) ^ self.generated_frame_list[self.masking_octet + 4]))
                # convert to ASCII and calc. Then, convert back to character
                self.payload_list[i] = chr(ord(self.payload_list[i]) ^ self.generated_frame_list[self.masking_octet + 4])
                #print ('')
        else:
            # Masked payload octet[i] = original payload octet[i] ^ Mask[i % 4] 
            for i in range(len(self.payload_list)):
                self.masking_octet = i % 4
                # Original payload octet
                #print ('Original payload octet')
                #print (bin(ord(self.payload_list[i]))) 
                # Masking octet
                #print ('Masking octet')
                #print (bin(self.generated_frame_list[self.masking_octet + 2]))
                # XOR result
                #print ('XOR result')
                #print (bin(ord(self.payload_list[i]) ^ self.generated_frame_list[self.masking_octet + 2]))
                # convert to ASCII and calc. Then, convert back to character
                self.payload_list[i] = chr(ord(self.payload_list[i]) ^ self.generated_frame_list[self.masking_octet + 2])
        
    def maskBinaryPayload(self):
        # Length is 127, then mask octets are 10th~ bytes, thus +9
        if (self.generated_frame_list[1] & 127) == 127:
            for i in range(len(self.payload_list)):
                self.masking_octet = i % 4
                self.payload_list[i] = int(self.payload_list[i], 16) ^ self.generated_frame_list[self.masking_octet + 9]
        # Length is 126, then mask octets are 5th~ bytes, thus +4
        elif (self.generated_frame_list[1] & 127) == 126:
            for i in range(len(self.payload_list)):
                self.masking_octet = i % 4
                # Masking octet
                #print (self.generated_frame_list[self.masking_octet + 4])
                self.payload_list[i] = int(self.payload_list[i], 16) ^ self.generated_frame_list[self.masking_octet + 4]
        # Length < 126, then mask octets are 3th~ bytes, thus +2
        else:
            # Masked payload octet[i] = original payload octet[i] ^ Mask[i % 4] 
            for i in range(len(self.payload_list)):
                self.masking_octet = i % 4
                # Original payload octet
                #print ('Original Payload octet')
                #print (int(self.payload_list[i], 16))
                # Masking octet
                #print ('Masking octet')
                #print (self.generated_frame_list[self.masking_octet + 2])
                # XOR result
                #print ('XOR result')
                #print (int(self.payload_list[i], 16) ^ self.generated_frame_list[self.masking_octet + 2])
                # convert to ASCII and calc. Then, convert back to character
                #print (int(self.payload_list[i], 16))
                self.payload_list[i] = int(self.payload_list[i], 16) ^ self.generated_frame_list[self.masking_octet + 2]

class FrameCrafter():
    u''' Modify headers '''
    
    def __init__(self, array):
        self.arrdata = array
        self.non_payload_byte_list = [] 
        self.payload_byte_list = [] 
        self.cur_payload_len = 0
        self.original_payload_len = 0
        self.length_field = 0
        self.length_modified = 0
        self.ever_large_flg = 0
        self.ever_middle_flg = 0
        self.fileName = ''

    def frameAnalyzer(self):
        #self.frameParser()
        while True:
            self.frameParser()
            self.framePrinter()
            self.input = raw_input('Input: ')
            print ('')
            if self.input == 'S' or self.input == 's':
                return self.arrdata
            elif self.input == 'F' or self.input == 'f':
                self.frameFlipFin()
            elif self.input == 'R1' or self.input == 'r1':
                self.frameFlipR1()
            elif self.input == 'R2' or self.input == 'r2':
                self.frameFlipR2()
            elif self.input == 'R3' or self.input == 'r3':
                self.frameFlipR3()
            elif self.input == 'O' or self.input == 'o':
                self.frameOp()
            elif self.input == 'M' or self.input == 'm':
                self.frameMask()
            elif self.input == 'L' or self.input == 'l':
                self.length_modified = 1
                self.frameLen()
            elif self.input == 'W' or self.input == 'w':
                self.writeToFile()
                sys.exit()

    def frameParser(self):
        # If MASK is 1, need to consider Masking-key
        self.mask_present = int(self.arrdata[1]) >> 7 # Checking 8th bit
        self.length_field = int(self.arrdata[1]) & 0b01111111 # Checking 5th ~ 7th bit
        if self.mask_present == 1:
            if self.length_field <= 125:
                self.cur_payload_len = self.length_field
                if self.length_modified == 0: # Save the original length value
                    self.original_payload_len = self.cur_payload_len
                for i in range(6): # Then, headers are 6 bytes
                    self.non_payload_byte_list.append(self.arrdata[i])
                for i in range(6, len(self.arrdata)):
                    self.payload_byte_list.append(self.arrdata[i])
            elif self.length_field == 126:
                self.ever_middle_flg = 1
                # Getting 16 bit extended length value
                self.cur_payload_len = int(self.arrdata[2]) << 8 | int(self.arrdata[3])
                if self.length_modified == 0:
                    self.original_payload_len = self.cur_payload_len
                for i in range(8): # Then, headers are 8 bytes
                    self.non_payload_byte_list.append(self.arrdata[i])
                for i in range(8, len(self.arrdata)):
                    self.payload_byte_list.append(self.arrdata[i])
            elif self.length_field == 127:
                self.ever_large_flg = 1
                # Getting 64 bit extended length value
                self.cur_payload_len = int(self.arrdata[2]) << 56 | \
                        int(self.arrdata[3]) << 48 | int(self.arrdata[4]) << 40 | \
                        int(self.arrdata[5]) << 32 | int(self.arrdata[6]) << 24 | \
                        int(self.arrdata[7]) << 16 | int(self.arrdata[8]) << 8 | \
                        int(self.arrdata[9]) 
                if self.length_modified == 0:
                    self.original_payload_len = self.cur_payload_len
                for i in range(14): # Then, headers are 14 bytes
                    self.non_payload_byte_list.append(self.arrdata[i])
                for i in range(14, len(self.arrdata)):
                    self.payload_byte_list.append(self.arrdata[i])

    def frameFlipFin(self):
        self.arrdata[0] = self.arrdata[0] ^ 128
    def frameFlipR1(self):
        self.arrdata[0] = self.arrdata[0] ^ 64
    def frameFlipR2(self):
        self.arrdata[0] = self.arrdata[0] ^ 32
    def frameFlipR3(self):
        self.arrdata[0] = self.arrdata[0] ^ 16
    def frameOp(self):
        self.op_input = raw_input('Input opcode(0-15): ')
        self.arrdata[0] = self.arrdata[0] & 240
        self.arrdata[0] = self.arrdata[0] | int(self.op_input)
    def frameMask(self):
        #print (bin(self.arrdata[1]))
        self.arrdata[1] = self.arrdata[1] ^ 128
    def frameLen(self):
        if int(self.length_field) == 127:
            self.change_std_len = raw_input('Change standard length field ? [Y/N]: ') 
            if self.change_std_len == 'Y' or self.change_std_len == 'y':
                while True:
                    self.std_len_input = raw_input('Input value for the standard length field(0-127): ')
                    # if input is 127, no change needed.
                    if int(self.std_len_input) == 126: 
                        print ('By setting 126, the next 16 bits (extended length field) represents payload length')
                        self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                        self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                        self.cur_payload_len = int(self.arrdata[2]) << 8 | int(self.arrdata[3])
                    elif int(self.std_len_input) < 126:
                        self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                        self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                        self.cur_payload_len = self.arrdata[1] ^ 128
                    break
            elif self.change_std_len == 'N' or self.change_std_len == 'n':
                while True:
                    self.ext_len_input = raw_input('Input value for the exteded length field(65535-18446744073709551615): ')
                    if int(self.ext_len_input) <= 18446744073709551615:
                        self.arrdata[2] = int(format(int(self.ext_len_input) & 18374686479671623680, '064b'), 2) >> 56
                        self.arrdata[3] = int(format(int(self.ext_len_input) & 71776119061217280, '064b'), 2) >> 48
                        self.arrdata[4] = int(format(int(self.ext_len_input) & 280375465082880, '064b'), 2) >> 40
                        self.arrdata[5] = int(format(int(self.ext_len_input) & 1095216660480, '064b'), 2) >> 32
                        self.arrdata[6] = int(format(int(self.ext_len_input) & 4278190080, '064b'), 2) >> 24
                        self.arrdata[7] = int(format(int(self.ext_len_input) & 16711680, '064b'), 2) >> 16
                        self.arrdata[8] = int(format(int(self.ext_len_input) & 65280, '064b'), 2) >> 8
                        self.arrdata[9] = int(format(int(self.ext_len_input) & 255, '064b'), 2)
                    break  
        elif int(self.length_field) == 126:
            self.change_std_len = raw_input('Change standard length field ? [Y/N]: ') 
            if self.change_std_len == 'Y' or self.change_std_len == 'y':    
                while True:
                    self.std_len_input = raw_input('Input value for the standard length field(0-127): ')
                    if int(self.std_len_input) == 127:
                        print ('By setting 127, the next 64 bits (extended length field) represents payload length')
                        print ('Increasing length value may cause an error')
                        self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                        self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                        self.cur_payload_len = int(self.arrdata[2]) << 56 | \
                            int(self.arrdata[3]) << 48 | int(self.arrdata[4]) << 40 | \
                            int(self.arrdata[5]) << 32 | int(self.arrdata[6]) << 24 | \
                            int(self.arrdata[7]) << 16 | int(self.arrdata[8]) << 8 | \
                            int(self.arrdata[9])                        
                    elif int(self.std_len_input) < 126:
                        #print ('not implemented yet')
                        #sys.exit()
                        self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                        self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                        self.cur_payload_len = self.arrdata[1] ^ 128
                    break
            elif self.change_std_len == 'N' or self.change_std_len == 'n':
                while True:
                    self.ext_len_input = raw_input('Input value for the extended length field(0-65535): ')
                    if int(self.ext_len_input) <= 65535:
                        self.arrdata[2] = int(format(int(self.ext_len_input) & 65280, '016b'), 2) >> 8
                        self.arrdata[3] = int(format(int(self.ext_len_input) & 255, '016b'), 2)
                    break
        elif int(self.length_field) < 126:
            while True:
                self.std_len_input = raw_input('Input value for the standard length field(0-127): ')
                if int(self.std_len_input) == 127:
                    print ('By setting 127, the next 64 bits (extended length field) represents payload length')
                    self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                    self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                    self.cur_payload_len = self.arrdata[1] ^ 128
                    if self.ever_large_flg == 0: # Need 64 bits padding
                        for i in range(2, 10):
                            self.arrdata.insert(i, 0)
                        self.ever_large_flg = 1
                elif int(self.std_len_input) == 126:
                    print ('By setting 126, the next 16 bits (extended length field) represents payload length')
                    self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                    self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                    self.cur_payload_len = self.arrdata[1] ^ 128
                    if self.ever_middle_flg == 0: # Need 16 bits padding.
                        for i in range(2, 4):
                            self.arrdata.insert(i, 0) 
                        self.ever_middle_flg = 1
                elif int(self.std_len_input) < 126:
                    self.arrdata[1] = self.arrdata[1] & 128 # clearing length bits
                    self.arrdata[1] = self.arrdata[1] | int(self.std_len_input) # updating length bits
                    self.cur_payload_len = self.arrdata[1] ^ 128
                break
    
    def writeToFile(self):
        self.fileName = raw_input('File Name: ')
        f = open(self.fileName, 'w')
        for i, h in enumerate(self.arrdata):
            f.write(hex(h))
            if i == len(self.arrdata) - 1:
                f.close()
                break
            f.write(', ')
        
    def framePrinter(self):
        print ('-------------------------------------')
        print ('* Frame Header bits                 *')
        print ('-------------------------------------')
        print ('  ', end='')
        print (format(int(self.arrdata[0]), '08b'), end='')
        print (format(int(self.arrdata[1]), '08b'), end='')
        print (' ', end='')
        print (format(int(self.arrdata[2]), '08b'), end='')
        print (format(int(self.arrdata[3]), '08b'))
        print ('  ', end='')
        print (format(int(self.arrdata[4]), '08b'), end='')
        print (format(int(self.arrdata[5]), '08b'), end='')
        print (' ', end='')
        if len(self.arrdata) > 6:
            print (format(int(self.arrdata[6]), '08b'), end='')
        if len(self.arrdata) > 7:
            print (format(int(self.arrdata[7]), '08b')) 
            print ('  ', end='')
        if len(self.arrdata) > 8:
            print (format(int(self.arrdata[8]), '08b'), end='')
        if len(self.arrdata) > 9:
            print (format(int(self.arrdata[9]), '08b'), end='')
        print ('')
        print ('-------------------------------------')
        print ('* Frame Header Analizer             *')
        print ('-------------------------------------')
        print ('FIN        [0th bit]: ', end='')
        print (int(self.arrdata[0]) >> 7)
        print ('RSV     [1-3th bits]: ', end='')
        print (format(int(self.arrdata[0]) >> 4 & 0b0111, '03b'))
        print ('opcode  [4-7th bits]: ', end='')
        print (format(int(self.arrdata[0]) & 0b00001111, '04b')) 
        print ('MASK       [8th bit]: ', end='')
        print (int(self.arrdata[1]) >> 7)
        print ('Length [9-15th bits]: ', end='')
        if self.length_field == 127:
            print (str(self.length_field) + ' (64 bits ext length field used)')
            print ('                    : ' + str(self.cur_payload_len) + ' byte', end='')
        elif self.length_field == 126:
            print (str(self.length_field) + ' (16 bits ext length field used)')
            print ('                    : ' + str(self.cur_payload_len) + ' byte', end='')
        elif self.length_field < 126:
            print (str(self.cur_payload_len) + ' byte', end='')
        if self.length_modified == 1:
            print (' / original length was ' + str(self.original_payload_len) + ' byte')
        else:
            print ('')
        print ('-----------------------------')
        print ('* Frame Crafter Menu        *')
        print ('-----------------------------')
        print ('Flip FIN bit: F')
        print ('Flip RSV1 bit: R1')
        print ('Flip RSV2 bit: R2')
        print ('Flip RSV3 bit: R3')
        print ('Overwrite Opcode: O')
        print ('Flip MASK bit: M')
        print ('Change Length: L')
        print ('Write to file: W')
        print ('')
        print ('Send frame as it is: S')
        #print ('Save current data to a file : W')
        print ('')


@click.command()
@click.argument('HOST')
@click.argument('PORT')
@click.argument('URL')
@click.option('-s', '--string', help='Give a string to send')
@click.option('-b', '--binary', type=click.File('r'), help='Give a path of a binary data')
@click.option('-a', '--array', type=click.File('r'), help='Give a path of frame hex data')
@click.option('-e', '--editor', is_flag=True, help='This enters FrameCrafter menu')
@click.option('-H', '--header', multiple=True, help='Add HTTP headers')
def syntax_parser(host, port, url, string, binary, array, editor, header):
    url = re.sub(r'^/', '', url)
    custom_header = []
    if string:
        opcode = '-s'
        data = string
        data_handler = DataHandler(opcode, data)
    elif binary:
        opcode = '-b'
        data = binary
        data_handler = DataHandler(opcode, data)
    elif array:
        opcode = '-a'
        data = array
        data_handler = DataHandler(opcode, data)
    if header:
        for h in header:
            custom_header.append(h) 
    if editor: 
        frame_crafter = FrameCrafter(data_handler.getArray()) 
        data_to_send = frame_crafter.frameAnalyzer()
    else:
        data_to_send = data_handler.getArray()
    client = WebSocket_cURL(host, port, url, opcode, data_to_send, custom_header).run()

if __name__ == '__main__':
    syntax_parser()
