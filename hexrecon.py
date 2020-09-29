import os
import subprocess
import argparse

def get_args():
        parser = argparse.ArgumentParser(description='HexRecon - Please use one of the following options:')
        parser.add_argument('-u', '--url', type=str, help='supply URL for subdomain enumeration', default=False)
        parser.add_argument('--install', help='install required 3rd party programs', nargs='?', default=False)

        return parser.parse_args()

def logo():
    print("""
 _   _          ______                     
| | | |         | ___ \                    
| |_| | _____  _| |_/ /___  ___ ___  _ __  
|  _  |/ _ \ \/ /    // _ \/ __/ _ \| '_ \ 
| | | |  __/>  <| |\ \  __/ (_| (_) | | | |
\_| |_/\___/_/\_\_| \_\___|\___\___/|_| |_|
                                          
========== Made by hexcon - v0.1 ==========
""")

def makedir(): # make directories in pwd
        path = "output"

        if not os.path.exists(path):
                os.makedirs(path)

        if not os.path.exists(path + "/" + url):
                os.makedirs(path + "/" + url)
                print(url + " directory created.")
        else:
                print("Domain supplied is not valid or the folder already exists.\n")

def install_tools():
        print("Checking for system updates...\n")
        os.system("sudo apt-get update -y")
        print("Upgrading the system...\n")
        os.system("sudo apt-get upgrade -y")
        print("Installing go...\n")
        os.system("snap install go --classic")
        print("Installing python-pip3...\n")
        os.system("sudo apt-get install -y python3-pip")   

if __name__ == "__main__":
        logo()
        args = get_args()
        url = args.url
        install = args.install
        if url is not False:
                makedir()
        else:
                print("Please select an option. Use -h for help.\n")
        if install is not False:
                install_tools()

