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
                os.makedirs(path + "/" + url + "/endpoints")
                os.makedirs(path + "/" + url + "/nuclei")
                os.makedirs(path + "/" + url + "/results")
                print(url + " directory created.")
        else:
                print("Domain supplied is not valid or the folder already exists.\n")

def sub_enum():
        print("\n\033[1;31Enumerating Subdomains ...\n\033[1;37m")
        print("\n\033[1;31mFetching Resolver IP's ...\n\033[1;37m")
        runipresolve = ("wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "+resolvedir+"resolvers.txt; wc -l "+resolvedir+"resolvers.txt")
        os.system(runipresolve)

        print("\n\033[1;31mStarting sublert ...\n\033[1;37m")
        runsublert = ("cd "+toolsdir+"sublert; yes 2>/dev/null | python3 sublert.py -u "+url+"; cp "+toolsdir+"sublert/output/"+url+".txt "+subdir+"sublert.txt; wc -l "+subdir+"sublert.txt")
        os.system(runsublert)

        print("\n\033[1;31mStarting subfinder ...\n\033[1;37m")
        runsubfinder = ("subfinder -d "+url+" -all -o "+subdir+"subfinder.txt; wc -l "+subdir+"subfinder.txt")
        os.system(runsubfinder)

        print("\n\033[1;31mStarting assetfinder ...\n\033[1;37m")
        runassetfinder = ("assetfinder --subs-only "+url+" > "+subdir+"assetfinder.txt; wc -l "+subdir+"assetfinder.txt")
        os.system(runassetfinder)

        print("\n\033[1;31mStarting amass ...\n\033[1;37m")
        runamass = ("amass enum -passive -d "+url+" -o "+subdir+"amass.txt; wc -l "+subdir+"amass.txt")
        os.system(runamass)

        print("\n\033[1;31mStarting findomain ...\n\033[1;37m")
        runfindomain = ("findomain -t "+url+" -u "+subdir+"findomain.txt; wc -l "+subdir+"findomain.txt")
        os.system(runfindomain)

        print("\n\033[1;31mStarting Sublist3r ...\n\033[1;37m")
        runsublist3r = ("cd "+toolsdir+"Sublist3r; python3 sublist3r.py -d "+url+" -o "+subdir+"Sublist3r.txt; wc -l "+subdir+"Sublist3r.txt")
        os.system(runsublist3r)

        print("\n\033[1;31mStarting crobat ...\n\033[1;37m")
        runcrobat = ("crobat -s "+url+" | sort -u | tee "+subdir+"rapiddns.txt; wc -l "+subdir+"rapiddns.txt")
        os.system(runcrobat)

        print("\n\033[1;31mSorting Results ...\n\033[1;37m")
        runsortsubs = ("cat "+subdir+"*.txt | sort -u > "+subdir+"subdomains.txt; wc -l "+subdir+"subdomains.txt")
        os.system(runsortsubs)

        print("\n\033[1;3mEnumeration Finished.\n\033[1;37m")

def sub_resolve():
        print("\n\033[1;31mResolving Subdomains ...\n\033[1;37m")
        runresolvesubs = ("cat "+subdir+"subdomains.txt | sort -u | shuffledns -silent -d "+url+" -r "+resolvedir+"resolvers.txt > "+subdir+"alive_subdomains.txt; wc -l "+subdir+"alive_subdomains.txt")
        os.system(runresolvesubs)

        print("\n\033[1;31mFinding Alive Hosts ...\n\033[1;37m")
        runalivehosts = ("cat "+subdir+"alive_subdomains.txt | httprobe -prefer-https | tee "+subdir+"hosts.txt; wc -l "+subdir+"hosts.txt")
        os.system(runalivehosts)

        print("\n\033[1;31mGetting CNAME's ...\n\033[1;37m")
        rungetcname = ("cat "+subdir+"subdomains.txt | dnsprobe -r CNAME -o "+subdir+"subdomains_cname.txt; wc -l "+subdir+"subdomains_cname.txt")
        os.system(rungetcname)

        print("\n\033[1;31mGetting IP's ...\n\033[1;37m")
        rungetip = ("cat "+subdir+"subdomains.txt | dnsprobe -silent -f ip | sort -u | tee "+subdir+"ips.txt; wc -l "+subdir+"ips.txt")
        os.system(rungetip)

        print("\n\033[1;31mResolving Subdomains Finished.\n\033[1;37m")

def sub_takeovers():
        print("\n\033[1;31mChecking Subdomain Takeovers ...\n\033[1;37m")
        print("\n\033[1;31mStarting subjack ...\n\033[1;37m")
        runsubjack = ("subjack -w "+subdir+"hosts.txt -a -ssl -t 50 -v -c "+godir+"/src/github.com/haccer/subjack/fingerprints.json -o "+subdir+"subjack_takeovers.txt -ssl")
        os.system(runsubjack)

        print("\n\033[1;31mStarting nuclei ...\n\033[1;37m")
        runnucleitakeover = ("cat "+subdir+"hosts.txt | nuclei -t "+toolsdir+"nuclei-templates/subdomain-takeover/ -c 50 -o "+subdir+"nuclei_takeovers.txt")
        os.system(runnucleitakeover)

        print("\n\033[1;31mSubdomain Takeovers Finished.\n\033[1;37m")

def get_endpoints():
        print("\n\033[1;31mScraping Endpoints ...\n\033[1;37m")
        runscrape = ("cat "+subdir+"hosts.txt | sed 's/https\\?:\\/\\///' | gau > "+endpointsdir+"getallurls.txt; cat "+endpointsdir+"getallurls.txt  | sort -u | unfurl --unique keys > "+endpointsdir+"paramlist.txt")
        os.system(runscrape)

        runscrape1 = ("cat "+endpointsdir+"getallurls.txt | sort -u | grep -P '\\w+\\.js(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"jsurls.txt; cat "+endpointsdir+"getallurls.txt | sort -u | grep -P '\\w+\\.php(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"phpurls.txt; cat "+endpointsdir+"getallurls.txt | sort -u | grep -P '\\w+\\.aspx(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"aspxurls.txt; cat "+endpointsdir+"getallurls.txt  | sort -u | grep -P '\\w+\\.jsp(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"jspurls.txt")
        os.system(runscrape1)

        #runscrape2 = ("cat "+subdir+"hosts.txt | httpx -path //server-status?full=true -status-code -content-length | awk '{print $1}' | sort -u > "+endpointsdir+"server-status.txt; cat "+subdir+"hosts.txt | httpx -ports 80,443,8009,8080,8081,8090,8180,8443 -path /web-console/ -status-code -content-length | awk '{print $1}' | sort -u > "+endpointsdir+"web-consoles.txt; cat "+subdir+"hosts.txt | httpx -path /phpinfo.php -status-code -content-length -title | awk '{print $1}' | sort -u > "+endpointsdir+"phpinfo.txt")
        #os.system(runscrape2)

        print("\n\033[1;31mStarting LinkFinder ...\n\033[1;37m")
        runlinkfinder = ("cat "+endpointsdir+"jsurls.txt | xargs -I{} python3 "+toolsdir+"/LinkFinder/linkfinder.py -i {} -o cli | sort -u | tee "+endpointsdir+"linkfinderjs.txt")       
        os.system(runlinkfinder)

        print("\n\033[1;31mStarting SecretFinder ...\n\033[1;37m")
        runsecretfinder = ("cat "+endpointsdir+"jsurls.txt | xargs -I{} python3 "+toolsdir+"/secretfinder/SecretFinder.py -i {} -o cli | sort -u | tee "+endpointsdir+"secretfinderjs.txt")       
        os.system(runsecretfinder)

        print("\n\033[1;31mScraping Endpoints Finished.\n\033[1;37m")

def run_meg():
        print("\n\033[1;31mStarting meg ...\n\033[1;37m")
        runmeg = ("cd "+subdir+"; meg -d 1000 -v /; mv out meg")       
        os.system(runmeg)

def nuclei_scan():
        print("\n\033[1;31mStarting nuclei ...\n\033[1;37m")
        runnuclei = ("nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/generic-detections/ -c 50 -o "+nucleidir+"generic-detections.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/cves/ -c 50 -o "+nucleidir+"cve.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/default-credentials/ -c 50 -o "+nucleidir+"default-creds.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/dns/ -c 50 -o "+nucleidir+"dns.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/files/ -c 50 -o "+nucleidir+"files.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/panels/ -c 50 -o "+nucleidir+"panels.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/security-misconfiguration/ -c 50 -o "+nucleidir+"security-misconfiguration.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/technologies/ -c 50 -o "+nucleidir+"technologies.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/tokens/ -c 50 -o "+nucleidir+"tokens.txt; nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/vulnerabilities/ -c 50 -o "+nucleidir+"vulnerabilties.txt")       
        os.system(runnuclei)

def screen_shots():
        print("\n\033[1;31mStarting Eyewitness ...\n\033[1;37m")
        runeyewitness = ("python3 "+toolsdir+"EyeWitness/Python/EyeWitness.py -f "+subdir+"/hosts.txt --no-prompt -d "+resultsdir+"")
        os.system(runeyewitness)

def port_scan():
        print("\n\033[1;31mStarting nmap port scan ...\n\033[1;37m")
        runportscan = ("cat "+subdir+"ips.txt | naabu -silent | bash "+toolsdir+"naabu2nmap.sh | tee "+resultsdir+"scan.nmap")
        os.system(runportscan)
        
def save_results():
        print("\n\033[1;31mSaving Results ...\n\033[1;37m")  
        runcopyresults = ("cp "+subdir+"subdomains.txt "+resultsdir+"subdomains.txt; cp "+subdir+"subdomains_cname.txt "+resultsdir+"subdomains_cname.txt; cp "+subdir+"ips.txt "+resultsdir+"ips.txt; cp "+subdir+"hosts.txt "+resultsdir+"hosts.txt")
        os.system(runcopyresults)
        print("\n\033[1;31mResults saved in "+resultsdir+"\n\033[1;37m")
        print("\n\033[1;31mFinished.\n\033[1;37m") 

def install_tools():
        if not os.path.exists(toolsdir):
                os.makedirs(toolsdir)

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
        sublertinstall = ("cd "+toolsdir+"; git clone https://github.com/yassineaboukir/sublert.git; cd sublert; pip3 install -r requirements.txt; chmod +x "+toolsdir+"sublert/sublert.py")
        os.system(sublertinstall)

        print("\n\033[1;31mInstalling subfinder ...\n\033[1;37m")
        subfinderinstall = ("cd "+toolsdir+"; git clone https://github.com/projectdiscovery/subfinder.git; cd subfinder/v2/cmd/subfinder; go build .; cp subfinder /usr/local/bin/")
        os.system(subfinderinstall)

        print("\n\033[1;31mInstalling assetfinder ...\n\033[1;37m")
        assetfinderinstall = ("go get -u -v github.com/tomnomnom/assetfinder; cp "+godir+"bin/assetfinder /usr/local/bin/")
        os.system(assetfinderinstall)

        print("\n\033[1;31mInstalling amass ...\n\033[1;37m")
        amassinstall = ("GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...; cp "+godir+"bin/amass /usr/local/bin/")
        os.system(amassinstall)

        print("\n\033[1;31mInstalling findomain ...\n\033[1;37m")
        findomaininstall = ("wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O "+toolsdir+"findomain; chmod +x "+toolsdir+"findomain; sudo cp "+toolsdir+"findomain /usr/local/bin")
        os.system(findomaininstall)

        print("\n\033[1;31mInstalling Sublist3r ...\n\033[1;37m")
        sublist3rinstall = ("cd "+toolsdir+"; git clone https://github.com/aboul3la/Sublist3r.git; cd Sublist3r; pip3 install -r requirements.txt")
        os.system(sublist3rinstall)

        print("\n\033[1;31mInstalling crobat ...\n\033[1;37m")
        crobatinstall = ("go get -u -v github.com/cgboal/sonarsearch/crobat; cp "+godir+"bin/crobat /usr/local/bin/")
        os.system(crobatinstall)

        print("\n\033[1;31mInstalling massdns ...\n\033[1;37m")
        massdnsinstall = ("cd "+toolsdir+"; git clone https://github.com/blechschmidt/massdns.git; cd "+toolsdir+"massdns; make -j; sudo cp "+toolsdir+"massdns/bin/massdns /usr/local/bin/")
        os.system(massdnsinstall)

        print("\n\033[1;31mInstalling shuffledns ...\n\033[1;37m")
        shufflednsinstall = ("GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns; cp "+godir+"bin/shuffledns /usr/local/bin/")
        os.system(shufflednsinstall)

        print("\n\033[1;31mInstalling httprobe ...\n\033[1;37m")
        httprobeinstall = ("go get -u -v github.com/tomnomnom/httprobe; cp "+godir+"bin/httprobe /usr/local/bin/")
        os.system(httprobeinstall)

        print("\n\033[1;31mInstalling dnsprobe ...\n\033[1;37m")
        dnsprobeinstall = ("GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsprobe; cp "+godir+"bin/dnsprobe /usr/local/bin")
        os.system(dnsprobeinstall)

        print("\n\033[1;31mInstalling subjack ...\n\033[1;37m")
        installsubjack = ("go get -u -v github.com/haccer/subjack; cp "+godir+"bin/subjack /usr/local/bin/")
        os.system(installsubjack)

        print("\n\033[1;31mInstalling nuclei ...\n\033[1;37m")
        installnuclei = ("cd "+toolsdir+";  git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; cp nuclei /usr/local/bin/; cd "+toolsdir+"; git clone https://github.com/projectdiscovery/nuclei-templates.git")
        os.system(installnuclei)

        print("\n\033[1;31mInstalling nmap ...\n\033[1;37m")
        installnmap = ("apt install nmap -y")
        os.system(installnmap)

        print("\n\033[1;31mInstalling naabu ...\n\033[1;37m")
        installnaabu = ("GO111MODULE=on go get -u -v github.com/projectdiscovery/naabu/cmd/naabu ; cp "+godir+"bin/naabu /usr/local/bin")
        os.system(installnaabu)

        print("\n\033[1;31mInstalling naabu2nmap ...\n\033[1;37m")
        installnaabu2nmap = ("wget https://raw.githubusercontent.com/maverickNerd/naabu/master/scripts/naabu2nmap.sh -O "+toolsdir+"naabu2nmap.sh; chmod +x "+toolsdir+"naabu2nmap.sh")
        os.system(installnaabu2nmap)

        print("\n\033[1;31mInstalling Eyewitness ...\n\033[1;37m")
        installeyewitness = ("cd "+toolsdir+"; git clone https://github.com/FortyNorthSecurity/EyeWitness.git; bash "+toolsdir+"EyeWitness/Python/setup/setup.sh")
        os.system(installeyewitness)

        print("\n\033[1;31mInstalling gau ...\n\033[1;37m")
        installgau = ("go get -u -v github.com/lc/gau; cp "+godir+"bin/gau /usr/local/bin")
        os.system(installgau)

        print("\n\033[1;31mInstalling unfurl ...\n\033[1;37m")
        installunfurl = ("go get -u -v github.com/tomnomnom/unfurl; cp "+godir+"bin/unfurl /usr/local/bin")
        os.system(installunfurl)

        print("\n\033[1;31mInstalling httpx ...\n\033[1;37m")
        installhttpx = ("GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx; cp "+godir+"bin/httpx /usr/local/bin")
        os.system(installhttpx)

        print("\n\033[1;31mInstalling linkfinder ...\n\033[1;37m")
        installlinkfinder = ("cd "+toolsdir+"; git clone https://github.com/GerbenJavado/LinkFinder.git; cd LinkFinder; python3 setup.py install; pip3 install -r requirements.txt")
        os.system(installlinkfinder)

        print("\n\033[1;31mInstalling secretfinder ...\n\033[1;37m")
        installsecretfinder = ("cd "+toolsdir+"; git clone https://github.com/m4ll0k/SecretFinder.git secretfinder; cd secretfinder; pip install -r requirements.txt")
        os.system(installsecretfinder)

        print("\n\033[1;31mInstalling meg ...\n\033[1;37m")
        installmeg = ("go get -u -v github.com/tomnomnom/meg; cp "+godir+"bin/meg /usr/local/bin")
        os.system(installmeg)

        print("\n\033[1;31mInstalling gf ...\n\033[1;37m")
        installgf = ("go get -u github.com/tomnomnom/gf; cp "+godir+"bin/gf /usr/local/bin; cd "+toolsdir+"; git clone https://github.com/1ndianl33t/Gf-Patterns; cp "+toolsdir+"Gf-Patterns/*.json ~/.gf")
        os.system(installgf)

if __name__ == "__main__":    
        logo()
        args = get_args()
        url = args.url
        install = args.install
        toolsdir = "/root/tools/"
        godir = "/root/go/"      
        if url is not False:
                subdir = "/root/HexRecon/output/"+url+"/subdomains/"
                resolvedir = "/root/HexRecon/output/"+url+"/resolvers/"
                resultsdir = "/root/HexRecon/output/"+url+"/results/"  
                endpointsdir = "/root/HexRecon/output/"+url+"/endpoints/"
                nucleidir = "/root/HexRecon/output/"+url+"/nuclei/"
                makedir()
                sub_enum()
                sub_resolve()
                sub_takeovers()
                get_endpoints()
                run_meg()
                nuclei_scan()
                screen_shots()
                port_scan()
                save_results()
        else:
                print("Please select an option. Use -h for help.\n")
        if install is not False:
                install_tools()
