from flag_format import flag_prefix, flag_full
from PIL import Image
import sys, os, magic, re, subprocess
import binwalk
import math
import numpy as np
from binwalk.core.common import bytes2str

# os.environ['PWNLIB_NOTERM']='true'
import pwn


def cyan(s): return f'\033[36m{s}\033[0m'


def red(s): return f'\033[31m{s}\033[0m'


def cyan_bg(s): return f'\033[97;46m{s}\033[0m'


def expand(pattern, content: bytes, context = 10, format = cyan, codec = 'latin1'):
    for sub in re.finditer(pattern, content):
        expend_start = slice(max(sub.start(0) - context, 0), sub.start(0))
        expend_end = slice(sub.end(0) + 1, min(sub.end(0) + context, len(content)))
        print(content[expend_start].decode(codec) + format(sub.group(0).decode(codec)) + content[expend_end].decode(
            codec))


def int_to_bytes(n):
    return int.to_bytes(n, math.ceil(math.log2(n)), 'big')


def extract_lsb(content: bytes):
    bits = []
    not_bits = []
    for b in content:
        bits.append(b % 2)
        not_bits.append(1 - b % 2)
    bs = ''.join(map(str, bits))
    not_bs = ''.join(map(str, not_bits))
    return int_to_bytes(int(bs, 2)), int_to_bytes(int(not_bs, 2)), int_to_bytes(int(bs[::-1], 2)), int_to_bytes(
        int(not_bs[::-1], 2))


def extract_msb(content: bytes):
    bits = []
    not_bits = []
    for b in content:
        bits.append(b >> 7)
        not_bits.append(1 - b % 2)
    bs = ''.join(map(str, bits))
    not_bs = ''.join(map(str, not_bits))
    return int_to_bytes(int(bs, 2)), int_to_bytes(int(not_bs, 2)), int_to_bytes(int(bs[::-1], 2)), int_to_bytes(
        int(not_bs[::-1], 2))


def analyze_elf(elf):
    print(red('-' * 20))
    print(red(f"Checksec".center(20)))
    print(red('-' * 20))

    print(elf.checksec())

    if len(elf.symbols) < 20:
        for symb in elf.symbols.keys():
            print(symb)

    elif len(elf.symbols) < 100:
        print(red('-' * 20))
        print(red(f"Interesting Symbols".center(20)))
        print(red('-' * 20))

        for symb in elf.symbols.keys():
            if not symb.startswith('_') and not symb.startswith('got') and not symb.startswith(
                    'plt') and 'clone' not in symb.lower():
                print(symb)

        print(red('-' * 20))
        print(red(f"GOT".center(20)))
        print(red('-' * 20))

        for symb in elf.got.keys():
            if not symb.startswith('_'):
                print(symb)

        print(red('-' * 20))
        print(red(f"PLT".center(20)))
        print(red('-' * 20))

        for symb in elf.plt.keys():
            if not symb.startswith('_'):
                print(symb)


def analyze_img(img):
    arr = np.asarray(img)
    possible_bytes = []
    for i in range(arr.shape[2]):
        channel = arr[:, :, i]
        lsb = channel % 2
        msb = channel >> 7
        possible_bytes.append(np.packbits(lsb.flatten('C')).tobytes())
        possible_bytes.append(np.packbits(lsb.flatten('C')).tobytes())
        possible_bytes.append(np.packbits(msb.flatten('F')).tobytes())
        possible_bytes.append(np.packbits(msb.flatten('F')).tobytes())
    lsb = arr % 2
    msb = arr >> 7
    possible_bytes.append(np.packbits(lsb.flatten('C')).tobytes())
    possible_bytes.append(np.packbits(lsb.flatten('C')).tobytes())
    possible_bytes.append(np.packbits(msb.flatten('F')).tobytes())
    possible_bytes.append(np.packbits(msb.flatten('F')).tobytes())
    return possible_bytes


def bin_pattern(content):
    expand(flag_full, content, format = cyan_bg)
    expand(flag_prefix, content, format = cyan_bg)


def check(path):
    if not os.path.exists(path):
        print(f"File {path} not exist")
        return
    print(cyan('-' * 50))
    print(cyan(f"File {path}".center(50)))
    print(cyan('-' * 50))

    io = open(path, 'rb')
    content = io.read()
    io.seek(0)
    mime = magic.check_buf(content, magic.MIME_TYPE)
    print('MIME:', mime)

    file = magic.check_buf(content, magic.CONTINUE)
    print(file)
    print(cyan('-' * 50))
    print(cyan(f"Pattern match".center(50)))
    print(cyan('-' * 50))
    bin_pattern(content)

    print(cyan('-' * 50))
    print(cyan(f"Signatures".center(50)))
    print(cyan('-' * 50))
    binwalk.scan(path, signature = True)

    try:
        elf = pwn.ELF(path, False)
    except:
        pass
    else:
        print(cyan('-' * 50))
        print(cyan(f"ELF".center(50)))
        print(cyan('-' * 50))
        analyze_elf(elf)

        p = subprocess.run(['ldd', path], executable = 'ldd', stdout = subprocess.PIPE, stderr = subprocess.PIPE)

        print(red('-' * 20))
        print(red(f"Linked libraries".center(20)))
        print(red('-' * 20))
        for entry in pwn.parse_ldd_output(p.stdout.decode('utf8')):
            print(entry)


    if mime.startswith('image'):
        print(cyan('-' * 50))
        print(cyan(f"Image Metadata".center(50)))
        print(cyan('-' * 50))
        subprocess.run(['exiftool', path], executable = 'exiftool/exiftool')
        io.seek(0)
        img = Image.open(io)
        print(cyan('-' * 50))
        print(cyan(f"Image Bits Extraction".center(50)))
        print(cyan('-' * 50))
        for b in analyze_img(img):
            bin_pattern(b)

    print(cyan('-' * 50))
    print(cyan(f"Least Significant Bits".center(50)))
    print(cyan('-' * 50))
    for b in extract_msb(content):
        bin_pattern(b)

    print(cyan('-' * 50))
    print(cyan(f"Most Significant Bits".center(50)))
    print(cyan('-' * 50))

    print(cyan('-' * 50))
    print(cyan(f"End file {path}".center(50)))
    print(cyan('-' * 50))
    io.close()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print('Usage: python3 local.py file1 file2 ...')
        exit(1)
    for fp in sys.argv[1:]:
        check(fp)
