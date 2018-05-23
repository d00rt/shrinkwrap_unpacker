import sys
import struct
import pefile
import StringIO
import array

def mod_string(s, i, v):
    l = list(s)
    l[i] = v
    return ''.join(l)

def rva_to_offset(pe, rva):
    offset = -1
    for section in pe.sections:
        if rva >= section.VirtualAddress and rva <= (section.VirtualAddress + section.Misc_VirtualSize):
            offset = rva - section.VirtualAddress + section.PointerToRawData
            return offset


    return offset


def neg(value):
    return (-value % (1 << 32))


def get_offsets(data):
    f = StringIO.StringIO(data)
    oep_o = neg(struct.unpack("=L", f.read(4))[0]) ^ 0x1111
    import_directory = neg(struct.unpack("=L", f.read(4))[0]) ^ 0x1111
    base_address = struct.unpack("=L", f.read(4))[0]
    code_rva = neg(struct.unpack("=L", f.read(4))[0])
    data_size = neg(struct.unpack("=L", f.read(4))[0])
    code_end_rva = neg(struct.unpack("=L", f.read(4))[0])
    add_sub = neg(struct.unpack("=L", f.read(4))[0])
    xor_key = neg(struct.unpack("B", f.read(1))[0]) & 0xFF

    return (oep_o, import_directory, base_address, code_rva, data_size, code_end_rva, add_sub, xor_key)


def decrypt_data(data, key):
    res = ''
    for c in data:
        if ord(c) != 0x00 and ord(c) != key:
            res += chr(ord(c) ^ key)

        else:
            res += c
    return res


def main(filename):
    with open(filename, "rb") as f:
        buff = f.read()

    pe = pefile.PE(filename)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    ep_offset = rva_to_offset(pe, ep)
    
    oep_o, import_directory, base_address, code_rva, data_size, code_end_rva, add_sub, xor_key = get_offsets(buff[ep_offset + 5: ep_offset + 5 + 0x1D])
    print hex(oep_o)
    print hex(import_directory)
    print '0x0C - CODE INI RVA: ' + hex(code_rva)
    print '0x10 - DATA SIZE: ' + hex(data_size)
    print '0x14 - CODE END RVA: ' + hex(code_end_rva)
    print '0x18 - ADD SUB: ' + hex(add_sub)
## 
    # print 'RVA ADD: ' + hex(code_end_rva + add_sub)
    # print 'RVA SUB: ' + hex(data_size - (code_end_rva - code_rva) - add_sub)

    # data = pe.get_data(code_rva, code_end_rva - code_rva)


    block_size = code_end_rva - code_rva

    i = 0
    patched_bytes = 0
    code_offset = rva_to_offset(pe, code_rva)
    code_end_offset = rva_to_offset(pe, code_end_rva)

    pe.close()
    while patched_bytes < data_size:
        if code_offset + i == code_end_offset:
            i = 0
            code_offset = code_end_offset + add_sub 
            data_size = data_size - add_sub

        try:
            buff = mod_string(buff, code_offset + i, decrypt_data(buff[code_offset + i], xor_key))
        except Exception as e:
            import pdb; pdb.set_trace()

        i += 1
        patched_bytes += 1


    with open(filename + "_unpacked.exe", "wb") as f:
        f.write(buff) 


    pe = pefile.PE(filename + "_unpacked.exe")

    import_directory_rva = import_directory - base_address
    ope_rva = oep_o - base_address
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = ope_rva

    for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        if directory.name == 'IMAGE_DIRECTORY_ENTRY_IMPORT':
            directory.VirtualAddress = import_directory_rva
            directory.Size = 0

    buff = pe.write()
    pe.close()
    with open(filename + "_unpacked.exe", "wb") as f:
        f.write(buff) 
    

if __name__ == '__main__':
    main(sys.argv[1])
