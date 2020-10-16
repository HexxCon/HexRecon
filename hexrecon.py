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
                                          
========== Made by hexcon - v0.2 ==========
""")

def make_dir(): # make directories in pwd
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
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Enumerating Subdomains ...\n\033[1;37m")

        enum = {"resolves":"wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "+resolvedir+"resolvers.txt; wc -l "+resolvedir+"resolvers.txt",
                "sublert":"cd "+toolsdir+"sublert; yes 2>/dev/null | python3 sublert.py -u "+url+"; cp "+toolsdir+"sublert/output/"+url+".txt "+subdir+"sublert.txt; wc -l "+subdir+"sublert.txt",
                "subfinder":"subfinder -d "+url+" -all -o "+subdir+"subfinder.txt; wc -l "+subdir+"subfinder.txt",
                "assetfinder":"assetfinder --subs-only "+url+" > "+subdir+"assetfinder.txt; wc -l "+subdir+"assetfinder.txt",
                "amass":"amass enum -passive -d "+url+" -o "+subdir+"amass.txt; wc -l "+subdir+"amass.txt",
                "findomain":"findomain -t "+url+" -u "+subdir+"findomain.txt; wc -l "+subdir+"findomain.txt",
                "Sublist3r":"cd "+toolsdir+"Sublist3r; python3 sublist3r.py -d "+url+" -o "+subdir+"Sublist3r.txt; wc -l "+subdir+"Sublist3r.txt",
                "crobat":"crobat -s "+url+" | sort -u | tee "+subdir+"rapiddns.txt; wc -l "+subdir+"rapiddns.txt",
                "sort":"cat "+subdir+"*.txt | sort -u > "+subdir+"subdomains.txt; wc -l "+subdir+"subdomains.txt"}

        for enum_msg, enum_tool in enum.items():
            print("\n[\033[0;32m+\033[0;0m]\033[1;34m Running "+ enum_msg +" ...\n\033[1;37m")
            os.system(enum_tool)

def sub_resolve():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Resolving Subdomains ...\n\033[1;37m")

        resolve = {"resolve-subdomains":"cat "+subdir+"subdomains.txt | sort -u | shuffledns -silent -d "+url+" -r "+resolvedir+"resolvers.txt > "+subdir+"alive_subdomains.txt; wc -l "+subdir+"alive_subdomains.txt",
                   "find-alive-hosts":"cat "+subdir+"alive_subdomains.txt | httprobe -prefer-https | tee "+subdir+"hosts.txt; wc -l "+subdir+"hosts.txt",
                   "get-cname":"cat "+subdir+"subdomains.txt | dnsprobe -r CNAME -o "+subdir+"subdomains_cname.txt; wc -l "+subdir+"subdomains_cname.txt",
                   "get-ip":"cat "+subdir+"subdomains.txt | dnsprobe -silent -f ip | sort -u | tee "+subdir+"ips.txt; wc -l "+subdir+"ips.txt"}

        for resolve_msg, resolve_tool in resolve.items():
            print("\n[\033[0;32m+\033[0;0m]\033[1;34m Running "+ resolve_msg +" ...\n\033[1;37m")
            os.system(resolve_tool)

def sub_takeovers():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Checking Subdomain Takeovers ...\n\033[1;37m")

        takeovers = {"subjack":"subjack -w "+subdir+"hosts.txt -a -ssl -t 50 -v -c "+godir+"/src/github.com/haccer/subjack/fingerprints.json -o "+subdir+"subjack_takeovers.txt -ssl",
                     "nuclei":"cat "+subdir+"hosts.txt | nuclei -t "+toolsdir+"nuclei-templates/subdomain-takeover/ -o "+subdir+"nuclei_takeovers.txt"}

        for takeovers_msg, takeovers_tool in takeovers.items():
            print("\n[\033[0;32m+\033[0;0m]\033[1;34m Running "+ takeovers_msg +" ...\n\033[1;37m")
            os.system(takeovers_tool)                     

def get_endpoints():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Scraping Endpoints ...\n\033[1;37m")

        endpoints = {"getallurls":"cat "+subdir+"hosts.txt | sed 's/https\\?:\\/\\///' | gau > "+endpointsdir+"getallurls.txt; cat "+endpointsdir+"getallurls.txt  | sort -u | unfurl --unique keys > "+endpointsdir+"paramlist.txt",
                     "scrape-js":"cat "+endpointsdir+"getallurls.txt | sort -u | grep -P '\\w+\\.js(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"jsurls.txt",
                     "scrape-php":"cat "+endpointsdir+"getallurls.txt | sort -u | grep -P '\\w+\\.php(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"phpurls.txt",
                     "scrape-aspx":"cat "+endpointsdir+"getallurls.txt | sort -u | grep -P '\\w+\\.aspx(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"aspxurls.txt",
                     "scrape-jsp":"cat "+endpointsdir+"getallurls.txt  | sort -u | grep -P '\\w+\\.jsp(\\?|$)' | httpx -silent -status-code | awk '{print $1}' | sort -u > "+endpointsdir+"jspurls.txt",
                     "linkfinder":"cat "+endpointsdir+"jsurls.txt | xargs -I{} python3 "+toolsdir+"/LinkFinder/linkfinder.py -i {} -o cli | sort -u | tee "+endpointsdir+"linkfinderjs.txt",
                     "secretfinder":"cat "+endpointsdir+"jsurls.txt | xargs -I{} python3 "+toolsdir+"/secretfinder/SecretFinder.py -i {} -o cli | sort -u | tee "+endpointsdir+"secretfinderjs.txt"}

        for endpoints_msg, endpoints_tool in endpoints.items():
            print("\n[\033[0;32m+\033[0;0m]\033[1;34m Stage "+ endpoints_msg +" ...\n\033[1;37m")
            os.system(endpoints_tool)  

def sub_xss():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m XSS Check...\n\033[1;37m")
        runcheckxss = ("cat "+subdir+"alive_subdomains.txt | httprobe -p http:81 -p http:8080 -p https:8443 | waybackurls | kxss | tee "+endpointsdir+"xss.txt; wc -l "+endpointsdir+"xss.txt")
        os.system(runcheckxss)   

def run_meg():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Running meg ...\n\033[1;37m")
        runmeg = ("cd "+subdir+"; meg -d 1000 -v / hosts.txt; mv out meg")       
        os.system(runmeg)

def nuclei_scan():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Running nuclei Scanner ...\n\033[1;37m")

        nuclei = {"nuclei-detections":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/generic-detections/ -o "+nucleidir+"generic-detections.txt",
                  "nuclei-cves":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/cves/ -o "+nucleidir+"cve.txt",
                  "nuclei-defaults":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/default-credentials/ -o "+nucleidir+"default-creds.txt",
                  "nuclei-dns":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/dns/ -o "+nucleidir+"dns.txt",
                  "nuclei-files":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/files/ -o "+nucleidir+"files.txt",
                  "nuclei-panels":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/panels/ -o "+nucleidir+"panels.txt",
                  "nuclei-tokens":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/tokens/ -o "+nucleidir+"tokens.txt",
                  "nuclei-vulns":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/vulnerabilities/ -o "+nucleidir+"vulnerabilties.txt",
                  "nuclei-techs":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/technologies/ -o "+nucleidir+"technologies.txt",
                  "nuclei-misconfigs":"nuclei -l "+subdir+"hosts.txt -t "+toolsdir+"nuclei-templates/security-misconfiguration/ -o "+nucleidir+"security-misconfiguration.txt"}

        for nuclei_msg, nuclei_tool in nuclei.items():
            print("\n[\033[0;32m+\033[0;0m]\033[1;34m Stage "+ nuclei_msg +" ...\n\033[1;37m")
            os.system(nuclei_tool)

def screen_shots():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Starting Eyewitness ...\n\033[1;37m")
        runeyewitness = ("python3 "+toolsdir+"EyeWitness/Python/EyeWitness.py -f "+subdir+"/hosts.txt --no-prompt -d "+resultsdir+"")
        os.system(runeyewitness)

def port_scan():
        print("\n[\033[0;36m!\033[0;0m]\033[1;34m Starting nmap port scan ...\n\033[1;37m")
        runportscan = ("cat "+subdir+"ips.txt | naabu -silent | bash "+toolsdir+"naabu2nmap.sh | tee "+resultsdir+"scan.nmap")
        os.system(runportscan)

def install_tools():
        if not os.path.exists(toolsdir):
                os.makedirs(toolsdir)

        install = {"system updates":"sudo apt-get update -y; sudo apt-get upgrade -y; sudo apt-get install zip -y; snap install go --classic; sudo apt-get install -y python3-pip; apt install nmap -y",
                   "sublert":"cd "+toolsdir+"; git clone https://github.com/yassineaboukir/sublert.git; cd sublert; pip3 install -r requirements.txt; chmod +x "+toolsdir+"sublert/sublert.py",
                   "subfinder":"cd "+toolsdir+"; git clone https://github.com/projectdiscovery/subfinder.git; cd subfinder/v2/cmd/subfinder; go build .; cp subfinder /usr/local/bin/",
                   "assetfinder":"go get -u -v github.com/tomnomnom/assetfinder; cp "+godir+"bin/assetfinder /usr/local/bin/",
                   "amass":"GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...; cp "+godir+"bin/amass /usr/local/bin/",
                   "findomain":"wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O "+toolsdir+"findomain; chmod +x "+toolsdir+"findomain; sudo cp "+toolsdir+"findomain /usr/local/bin",
                   "Subl1st3r":"cd "+toolsdir+"; git clone https://github.com/aboul3la/Sublist3r.git; cd Sublist3r; pip3 install -r requirements.txt",
                   "crobat":"go get -u -v github.com/cgboal/sonarsearch/crobat; cp "+godir+"bin/crobat /usr/local/bin/",
                   "massdns":"cd "+toolsdir+"; git clone https://github.com/blechschmidt/massdns.git; cd "+toolsdir+"massdns; make -j; sudo cp "+toolsdir+"massdns/bin/massdns /usr/local/bin/",
                   "shuffledns":"GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns; cp "+godir+"bin/shuffledns /usr/local/bin/",
                   "httprobe":"go get -u -v github.com/tomnomnom/httprobe; cp "+godir+"bin/httprobe /usr/local/bin/",
                   "dnsprobe":"GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsprobe; cp "+godir+"bin/dnsprobe /usr/local/bin/",
                   "subjack":"go get -u -v github.com/haccer/subjack; cp "+godir+"bin/subjack /usr/local/bin/",
                   "nuclei":"cd "+toolsdir+";  git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; cp nuclei /usr/local/bin/; cd "+toolsdir+"; git clone https://github.com/projectdiscovery/nuclei-templates.git",
                   "naabu":"GO111MODULE=on go get -u -v github.com/projectdiscovery/naabu/cmd/naabu ; cp "+godir+"bin/naabu /usr/local/bin/",
                   "naabu2nmap":"wget https://raw.githubusercontent.com/maverickNerd/naabu/master/scripts/naabu2nmap.sh -O "+toolsdir+"naabu2nmap.sh; chmod +x "+toolsdir+"naabu2nmap.sh",
                   "Eyewitness":"cd "+toolsdir+"; git clone https://github.com/FortyNorthSecurity/EyeWitness.git; bash "+toolsdir+"EyeWitness/Python/setup/setup.sh",
                   "gau":"go get -u -v github.com/lc/gau; cp "+godir+"bin/gau /usr/local/bin",
                   "unfurl":"go get -u -v github.com/tomnomnom/unfurl; cp "+godir+"bin/unfurl /usr/local/bin",
                   "httpx":"GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx; cp "+godir+"bin/httpx /usr/local/bin",
                   "linkfinder":"cd "+toolsdir+"; git clone https://github.com/GerbenJavado/LinkFinder.git; cd LinkFinder; python3 setup.py install; pip3 install -r requirements.txt",
                   "secretfinder":"cd "+toolsdir+"; git clone https://github.com/m4ll0k/SecretFinder.git secretfinder; cd secretfinder; pip install -r requirements.txt",
                   "meg":"go get -u -v github.com/tomnomnom/meg; cp "+godir+"bin/meg /usr/local/bin",
                   "gf":"go get -u github.com/tomnomnom/gf; cp "+godir+"bin/gf /usr/local/bin; cd "+toolsdir+"; git clone https://github.com/1ndianl33t/Gf-Patterns; cp "+toolsdir+"Gf-Patterns/*.json ~/.gf",
                   "waybackurls":"go get -u -v github.com/tomnomnom/hacks/waybackurls; cp "+godir+"bin/waybackurls /usr/local/bin",
                   "kxss":"cd "+toolsdir+"; git clone https://github.com/tomnomnom/hacks.git; cd hacks; cd kxss; go build; cp kxss /usr/local/bin"}

        for i_msg, i_tool in install.items():
            print("\n[\033[0;32m+\033[0;0m]\033[1;34m Installing "+ i_msg +" ...\n\033[1;37m")
            os.system(i_tool)

        print("\n\033[1;31mHexRecon is now ready to run.\n\033[1;37m")

if __name__ == "__main__":    
        logo()
        args = get_args()
        url = args.url
        install = args.install
        toolsdir = "/root/tools/"
        godir = "/root/go/"      
        if url is not False:
                outputdir = "/root/HexRecon/output/"
                subdir = "/root/HexRecon/output/"+url+"/subdomains/"
                resolvedir = "/root/HexRecon/output/"+url+"/resolvers/"
                resultsdir = "/root/HexRecon/output/"+url+"/results/"  
                endpointsdir = "/root/HexRecon/output/"+url+"/endpoints/"
                nucleidir = "/root/HexRecon/output/"+url+"/nuclei/"
                make_dir()
                sub_enum()
                sub_resolve()           
                sub_takeovers()
                get_endpoints()
                sub_xss()
                run_meg()
                nuclei_scan()
                screen_shots()
                port_scan()
        else:
                print("Please select an option. Use -h for help.\n")
        if install is not False:
                install_tools()