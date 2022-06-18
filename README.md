# catScanner
 A vulnerability scanner

## Desenvolvimento:
* Foi usado Python 3.8 como linguagem base;
* Foram usado bibliotecas auxiliares para auxilio no desenvolvimento (threading, subprocess, argparser ...);
* Foi usado como base o Scan RapidScan.

## Projeto:
* Este projeto tem como objetivo ajudar na busca por vulnerabilidades, usando diversos scripts de ferramentas famosas para Scanear sites;
* Este Scanner é apenas uma Proof of Work com o objetivo de estudo de vulnerabilidades e como identificá-las, tal conhecimento pode ser usado em qualquer projeto Web como prevenção de ataques e vazamentos.

## Ferramentas de Scaneamento:
tools = [
    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"],
    ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"], ["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"],
    ["golismero"], ["dnsenum"], ["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
]

## Como executar:
* Este projeto foi desenvolvido e testado em um ambiente kali, portanto é recomedável o uso do mesmo;
* Para executálo basta baixá-lo e na raiz do projeto executar: python ./main www.example.com

---

⭐️ From [DarlanNoetzold](https://github.com/DarlanNoetzold)
