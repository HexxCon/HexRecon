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
                os.makedirs(path + "/" + url + "/resolvers")
                os.makedirs(path + "/" + url + "/subdomains")
                os.makedirs(path + "/" + url + "/results")
                print(url + " directory created.")
        else:
                print("Domain supplied is not valid or the folder already exists.\n")

def start_enum():
        print("\n\033[1;31Enumerating Subdomains ...\n\033[1;37m")
        print("\n\033[1;31mFetching Resolver IP's ...\n\033[1;37m")
        runipresolve = ("wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O /root/HexRecon/output/"+url+"/resolvers/resolvers.txt; wc -l /root/HexRecon/output/"+url+"/resolvers/resolvers.txt")
        os.system(runipresolve)
        print("\n\033[1;31mStarting sublert ...\n\033[1;37m")
        runsublert = ("cd /root/tools/sublert; yes 2>/dev/null | python3 sublert.py -u "+url+"; cp /root/tools/sublert/output/"+url+".txt /root/HexRecon/output/"+url+"/subdomains/sublert.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/sublert.txt")
        os.system(runsublert)
        print("\n\033[1;31msublert Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting subfinder ...\n\033[1;37m")
        runsubfinder = ("subfinder -d "+url+" -all -o /root/HexRecon/output/"+url+"/subdomains/subfinder.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/subfinder.txt")
        os.system(runsubfinder)
        print("\n\033[1;31msubfinder Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting assetfinder ...\n\033[1;37m")
        runassetfinder = ("assetfinder --subs-only "+url+" > /root/HexRecon/output/"+url+"/subdomains/assetfinder.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/assetfinder.txt")
        os.system(runassetfinder)
        print("\n\033[1;31massetfinder Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting amass ...\n\033[1;37m")
        runamass = ("amass enum -passive -d "+url+" -o /root/HexRecon/output/"+url+"/subdomains/amass.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/amass.txt")
        os.system(runamass)
        print("\n\033[1;31mamass Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting findomain ...\n\033[1;37m")
        runfindomain = ("findomain -t "+url+" -u /root/HexRecon/output/"+url+"/subdomains/findomain.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/findomain.txt")
        os.system(runfindomain)
        print("\n\033[1;31mfindomain Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting Sublist3r ...\n\033[1;37m")
        runsublist3r = ("cd /root/tools/Sublist3r; python3 sublist3r.py -d "+url+" -o /root/HexRecon/output/"+url+"/subdomains/Sublist3r.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/Sublist3r.txt")
        os.system(runsublist3r)
        print("\n\033[1;31mSublist3r Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting crobat ...\n\033[1;37m")
        runcrobat = ("crobat -s "+url+" | sort -u | tee /root/HexRecon/output/"+url+"/subdomains/rapiddns.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/rapiddns.txt")
        os.system(runcrobat)
        print("\n\033[1;31mcrobat Finished.\n\033[1;37m")
        print("\n\033[1;31mSorting Results ...\n\033[1;37m")
        runsortsubs = ("cat /root/HexRecon/output/"+url+"/subdomains/*.txt | sort -u > /root/HexRecon/output/"+url+"/subdomains/subdomains.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/subdomains.txt")
        os.system(runsortsubs)
        print("\n\033[1;31mSorting Finished.\n\033[1;37m")
        print("\n\033[1;31mResolving Subdomains ...\n\033[1;37m")
        runresolvesubs = ("cat /root/HexRecon/output/"+url+"/subdomains/subdomains.txt | sort -u | shuffledns -silent -d "+url+" -r /root/HexRecon/output/"+url+"/resolvers/resolvers.txt > /root/HexRecon/output/"+url+"/subdomains/alive_subdomains.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/alive_subdomains.txt")
        os.system(runresolvesubs)
        print("\n\033[1;31mResolving Subdomains Finished.\n\033[1;37m")
        print("\n\033[1;31mFinding Alive Hosts ...\n\033[1;37m")
        runalivehosts = ("cat /root/HexRecon/output/"+url+"/subdomains/alive_subdomains.txt | httprobe -prefer-https | tee /root/HexRecon/output/"+url+"/subdomains/hosts.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/hosts.txt")
        os.system(runalivehosts)
        print("\n\033[1;31mFinding Alive Hosts Finished.\n\033[1;37m")
        print("\n\033[1;31mGetting CNAME's ...\n\033[1;37m")
        rungetcname = ("cat /root/HexRecon/output/"+url+"/subdomains/subdomains.txt | dnsprobe -r CNAME -o /root/HexRecon/output/"+url+"/subdomains/subdomains_cname.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/subdomains_cname.txt")
        os.system(rungetcname)
        print("\n\033[1;31mGetting CNAME's Finished.\n\033[1;37m")
        print("\n\033[1;31mGetting IP's ...\n\033[1;37m")
        rungetip = ("cat /root/HexRecon/output/"+url+"/subdomains/subdomains.txt | dnsprobe -silent -f ip | sort -u | tee /root/HexRecon/output/"+url+"/subdomains/ips.txt; wc -l /root/HexRecon/output/"+url+"/subdomains/ips.txt")
        os.system(rungetip)
        print("\n\033[1;31mGetting IP's Finished.\n\033[1;37m")
        print("\n\033[1;31mChecking Subdomain Takeovers ...\n\033[1;37m")
        print("\n\033[1;31mStarting subjack ...\n\033[1;37m")
        runsubjack = ("subjack -w /root/HexRecon/output/"+url+"/subdomains/hosts.txt -a -ssl -t 50 -v -c /root/go/src/github.com/haccer/subjack/fingerprints.json -o all_takeovers.txt -ssl; grep -v "+print("Not Vulnerable")+" < /root/HexRecon/output/"+url+"/subdomains/all_takeovers.txt > /root/HexRecon/output/"+url+"/subdomains/subjack_takeovers.txt; rm /root/HexRecon/output/"+url+"/subdomains/all_takeovers.txt")
        os.system(runsubjack)
        print("\n\033[1;31msubjack Finished.\n\033[1;37m")
        print("\n\033[1;31mStarting nuclei ...\n\033[1;37m")
        runnucleitakeover = ("cat /root/HexRecon/output/"+url+"/subdomains/hosts.txt | nuclei -t /root/tools/nuclei-templates/subdomain-takeover/ -c 50 -o /root/HexRecon/output/"+url+"/subdomains/nuclei_takeovers.txt")
        os.system(runnucleitakeover)
        print("\n\033[1;31mnuclei Finished.\n\033[1;37m")
        print("\n\033[1;31mSaving Results ...\n\033[1;37m")  
        runcopyresults = ("cp /root/HexRecon/output/"+url+"/subdomains/subdomains.txt /root/HexRecon/output/"+url+"/results/subdomains.txt; cp /root/HexRecon/output/"+url+"/subdomains/subdomains_cname.txt /root/HexRecon/output/"+url+"/results/subdomains_cname.txt; cp /root/HexRecon/output/"+url+"/subdomains/ips.txt /root/HexRecon/output/"+url+"/results/ips.txt; cp /root/HexRecon/output/"+url+"/subdomains/hosts.txt /root/HexRecon/output/"+url+"/results/hosts.txt")
        os.system(runcopyresults)
        print("\n\033[1;31mResults saved in /root/HexRecon/output/"+url+"/results/\n\033[1;37m")
        print("\n\033[1;31mFinished.\n\033[1;37m") 

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
        print("\n\033[1;31mInstallation Finished.\n\033[1;37m")
        print("\n\033[1;31mInstalling subjack ...\n\033[1;37m")
        installsubjack = ("go get -u -v github.com/haccer/subjack; cp $HOME/go/bin/subjack /usr/local/bin/")
        os.system(installsubjack)
        print("\n\033[1;31mInstalling nuclei ...\n\033[1;37m")
        installnuclei = ("cd $HOME/tools/;  git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; cp nuclei /usr/local/bin/")
        installnucleitemp = ("cd $HOME/tools/; git clone https://github.com/projectdiscovery/nuclei-templates.git")
        os.system(installnuclei)
        os.system(installnucleitemp)



if __name__ == "__main__":
        logo()
        args = get_args()
        url = args.url
        install = args.install
        if url is not False:
                makedir()
                start_enum()
        else:
                print("Please select an option. Use -h for help.\n")
        if install is not False:
                install_tools()
