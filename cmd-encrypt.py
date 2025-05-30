import argparse
import base64

arg_parser = argparse.ArgumentParser(description='Encrypt command for powershell -e')
arg_parser.add_argument('-c', '--command', required=True, help='Command to encrypt')

args = arg_parser.parse_args()
cmd = args.command

print(f"[*] Command:\t{cmd}")
encoded = base64.b64encode(cmd.encode('utf-16le')).decode('utf-8')
print(f"powershell -e {encoded}")

