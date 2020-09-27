# HexRecon
 Personal recon script for subdomain enumeration.

 Used on DigitalOcean Ubuntu 20.04 Droplet.

# Notes

# Environment Configuration

## Update VPS
```
sudo apt-get update -y
sudo apt-get upgrade -y
```
## Make Folders
```
mkdir assets
mkdir assets/subdomains
```
## Install go
```
snap install go --classic
```
## Install python3-pip
```
sudo apt-get install -y python3-pip
```
# Subdomain Enumeration

## Get IP Resolvers
```
wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O resolvers.txt
```
## sublert
>Install
```
cd $HOME/tools/
git clone https://github.com/yassineaboukir/sublert.git
cd sublert
pip3 install -r requirements.txt
chmod +x $HOME/tools/sublert/sublert.py
```
>Run
```
cd "$HOME"/tools/sublert
yes | python3 sublert.py -u $domain
cp "$HOME"/tools/sublert/output/"$domain".txt /assets/subdomains/sublert.txt
```
## subfinder
>Install
 ```   
git clone https://github.com/projectdiscovery/subfinder.git
cd subfinder/v2/cmd/subfinder
go build .
cp subfinder /usr/local/bin/
```
>Run
```
subfinder -d icann.org -all -o /assets/subdomains/subfinder.txt
```
>Run with config
```
subfinder -d $domain -all -config $HOME/ReconPi/configs/config.yaml -o /assets/subdomains subfinder.txt
```
## assetfinder
>Install
```
go get -u -v github.com/tomnomnom/assetfinder
cp $HOME/go/bin/assetfinder /usr/local/bin/
```
>Run
```
assetfinder --subs-only icann.org > /assets/subdomains/assetfinder.txt
```
## Amass
>Install
```
GO111MODULE=on go get -v github.com/OWASP/Amass/v3/...
cp $HOME/go/bin/amass /usr/local/bin/
```
>Run
```
amass enum -passive -d icann.org -o /assets/subdomains/amass.txt
```
>Run with config
```
amass enum -passive -d $domain" -config $HOME/ReconPi/configs/config.ini -o /assets/subdomains/amass.txt
```
## findomain
>Install
```
wget https://github.com/Edu4rdSHL/findomain/releases/latest/download/findomain-linux -O $HOME/tools/findomain
chmod +x $HOME/tools/findomain
sudo cp "$HOME"/tools/findomain /usr/local/bin
```
>Run
```
findomain -t icann.org -u /assets/subdomains/findomain.txt
```
## Sublist3r
>Install
```
cd $HOME/tools/
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip3 install -r requirements.txt
```
>Run
```
cd $HOME/tools/Sublist3r
python3 sublist3r.py -d icann.org -o /assets/subdomains/Sublist3r.txt
```
## crobat
>Install
```
go get -u github.com/cgboal/sonarsearch/crobat
```
>Run
```
crobat -s icann.org | sort -u | tee rrapiddns_subdomains.txt
```
## Combine and Sort
```
cat *.txt | sort -u > subdomains.txt
```
>Count lines
```
wc -l subdomains.txt
```
## Resolve Subdomains
>Install massdns
```
cd $HOME/tools/
git clone https://github.com/blechschmidt/massdns.git
cd $HOME/tools/massdns
make -j
sudo cp $HOME/tools/massdns/bin/massdns /usr/local/bin/
```
>Install shuffledns
```
GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
cp $HOME/go/bin/shuffledns /usr/local/bin/
```
>Run
```
cat subdomains.txt | sort -u | shuffledns -silent -d icann.org -r resolvers.txt > alive_subdomains.txt
```
>Count lines
```
wc -l alive_subdomains.txt
```
## Get alive hosts
>Install httprobe
```
go get -u -v github.com/tomnomnom/httprobe
cp $HOME/go/bin/httprobe /usr/local/bin/
```
>Run
```
cat alive_subdomains.txt | httprobe -prefer-https | tee hosts.txt
```
>Count lines
```
wc -l hosts.txt
```
## Get CNAME
>Install dnsprobe
```
GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsprobe
cp $HOME/go/bin/dnsprobe /usr/local/bin
```
>Run
```
cat subdomains.txt | dnsprobe -r CNAME -o subdomains_cname.txt
```
## Gather IP's
>Run
```
cat subdomains.txt | dnsprobe -silent -f ip | sort -u | tee ips.txt
```
>Clean IP's - Use clean.py script from ReconPi repo - **Remember to give credits**
```
python3 $HOME/ReconPi/scripts/clean_ips.py ips.txt origin-ips.txt
```
# Subdomain Takeovers
```
	"$HOME"/go/bin/subjack -w "$SUBS"/hosts -a -ssl -t 50 -v -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json -o "$SUBS"/all-takeover-checks.txt -ssl
	grep -v "Not Vulnerable" <"$SUBS"/all-takeover-checks.txt >"$SUBS"/takeovers
	rm "$SUBS"/all-takeover-checks.txt

	vulnto=$(cat "$SUBS"/takeovers)
	if [[ $vulnto == *i* ]]; then
		echo -e "[$GREEN+$RESET] Possible subdomain takeovers:"
		for line in "$SUBS"/takeovers; do
			echo -e "[$GREEN+$RESET] --> $vulnto "
		done
	else
		echo -e "[$GREEN+$RESET] No takeovers found."
	fi

	startFunction "nuclei to check takeover"
	cat "$SUBS"/hosts | nuclei -t subdomain-takeover/ -c 50 -o "$SUBS"/nuclei-takeover-checks.txt
	vulnto=$(cat "$SUBS"/nuclei-takeover-checks.txt)
	if [[ $vulnto != "" ]]; then
		echo -e "[$GREEN+$RESET] Possible subdomain takeovers:"
		for line in "$SUBS"/nuclei-takeover-checks.txt; do
			echo -e "[$GREEN+$RESET] --> $vulnto "
		done
	else
		echo -e "[$GREEN+$RESET] No takeovers found."
	fi
}

```