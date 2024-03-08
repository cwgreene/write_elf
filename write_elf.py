import argparse

MAGIC = b"\x7fELF"
ENTRY = 4096*40

def header_offset():
    return 0x40

def program_header_bytes(text) -> bytes:
    res = b""
    res += bsi(0x1,4)           # type
    res += bsi(0x1|0x4, 4)  # RWX
    res += bsi(0x0, 8)    # offset 
    res += bsi(ENTRY, 8)        # virtual address
    res += bsi(ENTRY, 8)            # physical address
    res += bsi(222, 8)        # size in bytes of section
    res += bsi(222, 8)        # size in memory
    res += bsi(0x4, 8)              # alignment
    return res

def section_header_bytes() -> bytes:
    return b"\x00"*0x40 

def bsi(n:int, k=1) -> bytes:
    return n.to_bytes(length=k, byteorder="little") 

def write_elf_header(file, text):
    file.write(MAGIC)
    file.write(b"\x02") # 64 bit
    file.write(b"\x01") # little endian
    file.write(b"\x01") # version
    file.write(b"\x03") # linux ABI
    file.write(b"\x00") # abi version
    file.write(b"\x00"*7) # pad
    file.write(b"\x02\x00") # file type, exec
    file.write(b"\x3e\x00") # amd 64
    file.write(b"\x01\x00\x00\x00") # version
    file.write(bsi(ENTRY+0xb8, 8)) #entrypoint
    file.write(bsi(header_offset(),8)) # program header offset
    section_header_offset = header_offset() + len(program_header_bytes(text))
    file.write(bsi(section_header_offset, 8)) #section header offset
    file.write(b"\x00"*4) # flags. no idea
    file.write(bsi(header_offset(), 2)) # elf header size
    file.write(bsi(0x38, 2)) # program entry header size
    file.write(bsi(1,2)) # number of entries in program header table
    file.write(bsi(0x40, 2)) # section header size
    file.write(bsi(1,2)) # number of sections
    file.write(bsi(0,2)) # index of the section header that contains section names

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--assembly", required=True)
    options = parser.parse_args()
    
    text = open(options.assembly, "rb").read()
    with open(options.file,"wb") as output:
        write_elf_header(output, text)
        output.write(program_header_bytes(text))
        output.write(section_header_bytes())
        output.write(text)

main()
