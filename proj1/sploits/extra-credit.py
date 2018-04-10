#!/usr/bin/python2
import sys
import socket
import traceback
import struct

####

## This function takes your exploit code, adds a carriage-return and newline
## and sends it to the server. The server will always respond, but if the
## exploit crashed the server it will close the connection. Therefore, we try
## to write another query to the server, recv on the socket and see if we get
## an exception
##
## True means the exploit made the server close the connection (i.e. it crashed)
## False means the socket is still operational.
def try_exploit(exploit, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send("%s\n" % exploit)
    b = 0
    while b < (len(exploit) + 1):
        mylen = len(sock.recv(4098))
        b += mylen
        if mylen == 0:
            return True
    sock.send("\n")
    try:
        return len(sock.recv(5)) == 0
    except:
        return True

def exploit(host, port, shellcode):
    # Build your exploit here
    # One useful function might be
    #   struct.pack("<I", x)
    # which returns the 4-byte binary encoding of the 32-bit integer x
    while True:
        if try_exploit("hello world", host, port):
            # Connection closed by server
            continue
        else:
            # Connection still up
            break

####

if len(sys.argv) != 3:
    print("Usage: " + sys.argv[0] + " host port")
    exit()

try:
    shellfile = open("shellcode.bin", "r")
    shellcode = shellfile.read()
    exploit(sys.argv[1], int(sys.argv[2]), shellcode)

except:
    print("Exception:")
    print(traceback.format_exc())

