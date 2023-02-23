# Remedy4me
CVEs Remediation Scripts without a need to update the affected system, software, components & etc...

![image](https://user-images.githubusercontent.com/62406753/218900452-fa29b867-c034-4b6f-905c-63d1b9d42715.png)


# Introduction
These scripts will help you in mitigate, limit and prevent the CVEs attacks & exploits by applying specific changes to the affected versions of a system, software or components without any updates or For some reasons in the environment you can't apply new version updates. This repository will be always updated to include new scripts for the old & new discovered CVEs. 

# CVEs By Year

- <a href="#2023">2023</a>
- <a href="#2022">2022</a>
- <a href="#2021">2021</a>
- <a href="#2020">2020</a>
- <a href="#2017">2017</a>

# 2023

## CVE-2023-22809
<h4> Description: </h4> In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
<h4>Script Link:</h4> https://www.vicarius.io/vsociety/vulnerabilities/319243/CVE-2023-22809

# 2022

## CVE-2022-30190
<h4> Description: </h4>Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability and known as Follina.
<h4>Script Link:</h4> https://www.vicarius.io/vsociety/vulnerabilities/301665/CVE-2022-30190

## CVE-2021-4034
<h4> Description: </h4> A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.
<h4>Script Link:</h4>https://www.vicarius.io/vsociety/vulnerabilities/293297/CVE-2021-4034

# 2021

## CVE-2021-41773
<h4> Description: </h4> A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.
<h4>Script Link:</h4> https://www.vicarius.io/vsociety/vulnerabilities/285640/CVE-2021-41773

## CVE-2021-34527
<h4> Description: </h4> Windows Print Spooler Remote Code Execution also known as PrintNightmare is a vulnerability that affects Print Spooler services which is a Microsoft service for managing and monitoring files printing, The threat actor can exploit this issue to control the affected host remotely.
<h4>Script Link:</h4> https://www.vicarius.io/vsociety/vulnerabilities/279814/CVE-2021-34527

# 2020

## CVE-2020-1472
<h4> Description: </h4> An elevation of privilege vulnerability "Zerologon" exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.
<h4>Script Link:</h4> https://www.vicarius.io/vsociety/vulnerabilities/262479/CVE-2020-1472

# 2017

## CVE-2017-0144
<h4> Description: </h4> The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0143, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.
<h4>Script Link:</h4> https://www.vicarius.io/vsociety/vulnerabilities/183041/CVE-2017-0144

# Author
Made By: <a href="https://zeyadazima.com/">Zeyad Azima</a> && Made By: <a href="https://www.linkedin.com/in/yosef0x1/">Youssef Muhammad</a>
