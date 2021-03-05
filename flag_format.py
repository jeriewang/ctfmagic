import re

flag_full = re.compile(b'(?:flag|ctf){.+?}',re.I|re.S|re.M)
flag_prefix = re.compile(b'flag|ctf',re.I)
