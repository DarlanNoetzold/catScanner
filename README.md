# catScanner
 A vulnerability scanner

## Development:
* Python 3.8 was used as the base language;
* Auxiliary libraries were used to aid development (threading, subprocess, argparser ...);
* The RapidScan scan was used as a basis.

## Project:
* This project aims to help in the search for vulnerabilities, using several scripts from famous tools to scan websites;
* This Scanner is just a Proof of Work with the aim of studying vulnerabilities and how to identify them, this knowledge can be used in any Web project to prevent attacks and leaks.

## Scanning Tools:
tools = [
    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"],
    ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"], ["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"],
    ["golismero"], ["dnsenum"], ["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
]

## How to execute:
* This project was developed and tested in a kali environment, therefore it is recommended to use it;
* To run it, just download it and run it in the root of the project: python ./main www.example.com

---

⭐️ From [DarlanNoetzold](https://github.com/DarlanNoetzold)
