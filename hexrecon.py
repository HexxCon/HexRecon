import os
import subprocess
import argparse

def get_args():
    parser = argparse.ArgumentParser(
        description='hexrecon')
    parser.add_argument(
        '-u', '--url', type=str, help='Domain URL', required=False, default=False)
    parser.add_argument(
        '--install', help='Install HexRecon', nargs='?', default=False)

    return parser.parse_args()

def logo():
    print("""
 _   _          ______                         
| | | |         | ___ \                        
| |_| | _____  _| |_/ /_____  _____ ___  _ __  
|  _  |/ _ \ \/ /    // _ \ \/ / __/ _ \| '_ \ 
| | | |  __/>  <| |\ \  __/>  < (_| (_) | | | |
\_| |_/\___/_/\_\_| \_\___/_/\_\___\___/|_| |_|

============ Made by hexcon - v0.1 ===========
""")

def makedirs():
    bpath = "$HOME/hexrecon/targets"

    if not os.path.exists(bpath):
        os.makedirs(bpath)
    else:
        os.system("rm -r $HOME/hexrecon")
        os.makedirs(bpath)

    if not os.path.exists(url):
        os.makedirs(url)
    else:
        print("Could not create directory.")

if __name__ == "__main__":
    logo()
    args = get_args()
    makedirs()
    
    url = args.url
    install = args.install

