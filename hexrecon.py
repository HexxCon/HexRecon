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

        if not os.path.exists("/root/tools/"):
                os.makedirs("/root/tools/")
        print("\033[1;31mChecking for system updates ...\n\033[1;37m")
        sysupdate = ("sudo apt-get update -y")
        os.system(sysupdate)
        print("\n\033[1;31mUpgrading the system ...\n\033[1;37m")
        sysupgrade = ("sudo apt-get upgrade -y")
        os.system(sysupgrade)
        print("\n\033[1;31mInstalling go ...\n\033[1;37m")
        goinstall = ("snap install go --classic")
        os.system(goinstall)
        print("\n\033[1;31mInstalling python-pip3 ...\n\033[1;37m")
        pip3install = ("sudo apt-get install -y python3-pip")
        os.system(pip3install)
        print("\n\033[1;31mInstalling sublert ...\n\033[1;37m")
        sublertinstall = ("cd /root/tools/; git clone https://github.com/yassineaboukir/sublert.git; cd sublert; pip3 install -r requirements.txt; chmod +x $HOME/tools/sublert/sublert.py")
        os.system(sublertinstall)
        print("\n\033[1;31mInstalling subfinder ...\n\033[1;37m")
        subfinderinstall = ("cd /root/tools/; git clone https://github.com/projectdiscovery/subfinder.git; cd subfinder/v2/cmd/subfinder; go build .; cp subfinder /usr/local/bin/")
        os.system(subfinderinstall)
        print("\n\033[1;31mInstalling assetfinder ...\n\033[1;37m")
        assetfinderinstall = ("go get -u -v github.com/tomnomnom/assetfinder; cp $HOME/go/bin/assetfinder /usr/local/bin/")
        os.system(assetfinderinstall)
        print("\n\033[1;31mInstalling amass ...\n\033[1;37m")
        amassinstall = ("GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...; cp $HOME/go/bin/amass /usr/local/bin/")
        os.system(amassinstall)
        print("\n\033[1;31mInstalling findomain ...\n\033[1;37m")
        findomaininstall = ("wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O $HOME/tools/findomain; chmod +x $HOME/tools/findomain; sudo cp $HOME/tools/findomain /usr/local/bin")
        os.system(findomaininstall)
        print("\n\033[1;31mInstalling Sublist3r ...\n\033[1;37m")
        sublist3rinstall = ("cd $HOME/tools/; git clone https://github.com/aboul3la/Sublist3r.git; cd Sublist3r; pip3 install -r requirements.txt")
        os.system(sublist3rinstall)
        print("\n\033[1;31mInstalling crobat ...\n\033[1;37m")
        crobatinstall = ("go get -u -v github.com/cgboal/sonarsearch/crobat; cp $HOME/go/bin/crobat /usr/local/bin/")
        os.system(crobatinstall)
        print("\n\033[1;31mInstalling massdns ...\n\033[1;37m")
        massdnsinstall = ("cd $HOME/tools/; git clone https://github.com/blechschmidt/massdns.git; cd $HOME/tools/massdns; make -j; sudo cp $HOME/tools/massdns/bin/massdns /usr/local/bin/")
        os.system(massdnsinstall)
        print("\n\033[1;31mInstalling shuffledns ...\n\033[1;37m")
        shufflednsinstall = ("GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns; cp $HOME/go/bin/shuffledns /usr/local/bin/")
        os.system(shufflednsinstall)
        print("\n\033[1;31mInstalling httprobe ...\n\033[1;37m")
        httprobeinstall = ("go get -u -v github.com/tomnomnom/httprobe; cp $HOME/go/bin/httprobe /usr/local/bin/")
        os.system(httprobeinstall)
        print("\n\033[1;31mInstalling dnsprobe ...\n\033[1;37m")
        dnsprobeinstall = ("GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsprobe; cp $HOME/go/bin/dnsprobe /usr/local/bin")
        os.system(dnsprobeinstall)


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
