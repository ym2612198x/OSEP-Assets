import sys
import re

def shift_hex(match):
    val = int(match.group(1), 16)
    shifted = (val + 5) & 0xFF  # keep in byte range
    return f'0x{shifted:02x}'


data = sys.stdin.read()

# match all 0xHH patterns
result = re.sub(r'0x([0-9a-fA-F]{2})', shift_hex, data)
print(result)
