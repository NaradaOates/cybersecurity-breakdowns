# CPUID Supply Chain Attack - STX RAT Incident Breakdown
 
> **Series:** Cybersecurity Incident Breakdowns  
> **Status:** Draft - work in progress  
> **Last updated:** May 2026
 
---
## Why this incident? 
At the beginning of 2026, I built a new gaming PC, and like most PC owners, I wanted to monitor my component's temperature and performance. My go-to method to doing this was via CPUID's CPU-Z and HWMonitor. I had their homepage open in my browser tab ready to download the software. However, life got in the way, and I never got round to it. 

Fast forward to mid-April, I am on my long-awaited two week spring holiday, and the tab is still sitting there. Before clicking download, I did what I had been doing for the past couple of months and checked Tom's Hardware for the latest news on the RAM crisis and the tech industry in general. This is when I saw that the CPUID's download links had been compromised and was distributing malware to anyone who had downloaded their software during a specific window. 

Had I not checked first and/or decided to install the software earlier, I would have very likely have been among the victims. That near-miss is what made this incident personal, which made me want to dive in and conduct my own reseach into the breach. This breakdown is the result of that. 

---
 
## Table of Contents

1. [Incident Overview](#01--incident-overview)
2. [Attack Timeline](#02--attack-timeline)
3. [Technical Breakdown](#03--technical-breakdown)
4. [Indicators of Compromise](#04--indicators-of-compromise-iocs)
5. [Impact Assessment](#05--impact-assessment)
6. [Detection & Mitigation](#06--detection--mitigation)
7. [Sources & References](#07--sources--references)

## 01 - Incident Overview
 
| Field | Detail |
|---|---|
| **Malware name** | STX RAT |
| **Malware type** | Remote Access Trojan (RAT) with infomation stealing capabilities |
| **Incident name** | CPUID Supply Chain Attack |
| **First observed** | July 2025 (earliest known sample); April 9–10 2026 (CPUID breach window) |
| **Attributed actor** | Unknown Russian-speaking threat actor |
| **Motivation** | Financial - primary goal was browser credential theft; actor may also operate as an initial access broker |
| **Target sectors** | Individuals (majority), Retail, Manufacturing, Consulting, Telecommunications, Agriculture |
| **Target regions** | Brazil, Russia, China (confirmed); broader global exposure due to CPUID's international user base |
| **Severity** | High - sophisticated, fileless malware delivered via a trusted software supplier to millions of potential victims |

---

## 02 - Attack Timeline
 
| Date | Event |
|---|---|
| **July 2025** | Earliest known STX RAT sample (`superbad.exe`) observed communicating with C2 address `95.216.51[.]236`, marking the start of what Breakglass Intelligence assessed as a 10-month campaign |
| **March 2026** | A related campaign distributes STX RAT via trojanised FileZilla installers hosted on fake sites, using the same C2 infrastructure. This was later linked to the CPUID breach |
 **April 3, 2026** | Breakglass Intelligence finds evidence suggesting the CPUID breach may have begun on this date |
| **April 9, 2026 - 15:00 UTC** | CPUID's side API is confirmed compromised; download links for CPU-Z, HWMonitor, PerfMonitor, and PowerMAX are replaced with links pointing to trojanised installers hosted on attacker-controlled Cloudflare R2 infrastructure |
| **April 9, 2026 (evening)** | A Reddit user notices their HWMonitor update downloaded a file named `HWiNFO_Monitor_Setup.exe` instead of the expected `hwmonitor_1.63.exe`; Windows Defender flags it immediately; VirusTotal confirms it malicious, flagged by at least 32 AV engines |
| **April 10, 2026 — 10:00 UTC** | Breach window closes; CPUID fixes the compromised API and restores clean download links; approximately 19 hours of active malware distribution |
| **April 10, 2026** | CPUID contributor Samuel Demeulemeester issues a public statement confirming the breach, noting the main developer was away on holiday at the time |
| **April 10, 2026** | vx-underground and malware researcher Giuseppe Massaro publish early technical analysis confirming the malware is deeply trojanised, fileless, and targets browser credentials |
| **April 11, 2026** | Kaspersky publishes findings confirming 150+ victims and linking the campaign to the earlier FileZilla attacks |
| **April 13, 2026** | Breakglass Intelligence publishes additional analysis attributing the attack to a Russian-speaking threat actor and extending the campaign timeline back to July 2025 |

> **Note:** The April 3 start date from Breakglass Intelligence conflicts slightly with the April 9 confirmed breach window. April 3 likely refers to preparatory activity rather than active malware distribution. Additionally, CPUID's statement references "approximately six hours" which refers to the active redirect window specifically, not the total compromise period.

## 03 - Technical Breakdown
 
> **MITRE ATT&CK:** The technique IDs referenced throughout this section use the [MITRE ATT&CK framework](https://attack.mitre.org). A globally recognised, standardised catalogue of the methods threat actors use to carry out attacks. Each technique is assigned a unique ID (prefixed with `T`) so that researchers and security teams worldwide can reference the same technique without ambiguity. Sub-techniques are denoted with a dot (e.g. `T1574.001`).

---

### Initial Vector
 
It was a supply chain attack which led to CPUID's side API being compromised. This caused the official `cpuid[.]com` website to randomly serve malicious download links in place of legitimate ones. The trojanised installers were hosted on attacker-controlled Cloudflare R2 infrastructure under the domain `supp0v3[.]com`, and distributed both as ZIP archives and standalone installers.
 
**MITRE ATT&CK:** `T1195.002` - Supply Chain Compromise: Compromise Software Supply Chain
 
---
 
### Delivery Mechanism
 
Users downloading CPU-Z, HWMonitor, PerfMonitor, or PowerMAX during the breach window received a trojanised package containing two components:
 
- The **legitimate, signed CPUID executable** - unmodified, providing a convincing disguise
- A **malicious DLL** named `CRYPTBASE.dll` - the actual malicious component

The malicious installer masqueraded as `HWiNFO_Monitor_Setup.exe`, mimicking a separate legitimate tool (HWiNFO) to avoid suspicion. A technique known as **file masquerading**. The installer used an **Inno Setup wrapper** (a legitimate packaging tool used by developers to bundle software into installers) that launched in Russian, which was atypical for CPUID's software and helped alert early victims. Only the **64-bit versions** of the affected software were impacted.
 
---
 
### Execution - DLL Sideloading
 
When the victim ran the installer and launched the 64-bit executable (e.g. `HWMonitor_x64.exe`), Windows automatically loaded `CRYPTBASE.dll` from the same folder **before** looking for the legitimate system version in Windows' System32 directory.
 
This technique is known as **DLL sideloading**, or more specifically **DLL search order hijacking**. The malware placed a rogue DLL with the same name as a trusted system file in a location Windows checks first, tricking the system into loading the malicious version instead.
 
The malicious DLL's compilation timestamp had been deliberately falsified to `2077-08-31 05:16:43`. A technique known as **timestomping**, used to confuse forensic investigators attempting to establish when the file was created.
 
**MITRE ATT&CK:** `T1574.001` - Hijack Execution Flow: DLL Search Order Hijacking  
**MITRE ATT&CK:** `T1070.006` - Indicator Removal: Timestomp

---

### The Loader & Multi-Stage Unpacking Chain
 
Once the malicious DLL was loaded, it executed a fairly advanced, multi-staged loader. Rather than immediately running the malicious payload, the loader unpacked it across **five stages entirely in memory** using:
 
- **Reflective PE loading** - loading executable code directly into memory without writing it to disk
- **XOR decryption** - a method of scrambling data that is reversed at runtime
- **Layered bitwise transformations** - additional mathematical operations applied to further obscure the payload
In plain terms - the malware assembled and decrypted itself piece by piece inside RAM, never writing the fully formed payload to disk where antivirus tools could scan it. This is sometimes referred to as a **fileless attack**. At one stage, it also downloaded additional code and compiled a .NET payload directly on the victim's machine before injecting it into other running processes.
 
**MITRE ATT&CK:** `T1027` - Obfuscated Files or Information  
**MITRE ATT&CK:** `T1140` - Deobfuscate/Decode Files or Information  
**MITRE ATT&CK:** `T1055` - Process Injection

---

### Sandbox Evasion
 
Before proceeding with any of the above, the malware first checked whether it was running inside a **sandbox**, which is a controlled, isolated environment that security researchers use to safely rum and study malware. If it detected it was being analysed, it would stop executing, making it significantly harder for researchers to study its full behaviour. Only if all checks passed would it proceed to connect to the C2 server.
 
**MITRE ATT&CK:** `T1497` - Virtualisation/Sandbox Evasion
 
---
 
### C2 Communication
 
The final payload connected to a hardcoded C2 domain - `welcome[.]supp0v3[.]com` - and transmitted host metadata back to the attacker for victim identification and campaign tracking. This C2 address had been **reused from the earlier FileZilla campaign**, which is the operational security mistake that allowed researchers to link the two attacks to the same threat actor. The malware communicated over HTTP/S.

---

### NTDLL Proxying
 
To avoid detection by EDR (Endpoint Detection and Response) tools monitoring Windows system calls, the malware **proxied NTDLL functionality from a .NET assembly**.
 
NTDLL is a core Windows system file that security tools monitor closely because almost everything a program does on Windows passes through it. Rather than using the real NTDLL, which security tools watch closely, the malware created its own version of those functions and routed its activity through that instead, effectively stepping around the security camera watching the front door.

---

### Payload & Primary Objective
 
The final payload was **STX RAT** - a Remote Access Trojan with infostealer capabilities. The malware's primary objective was **browser credential theft**, specifically targeting Google Chrome's IElevation COM interface to access and decrypt stored passwords and session cookies.
 
Session cookies are particularly valuable to attackers because they represent an already-authenticated session. This means they can allow access to accounts without the password, and in some cases can **bypass multi-factor authentication (MFA)** entirely. The malware also segmented victims profile data by campaign tag and referrer software. This suggest the attacker was methodically cataloguing victims for potential follow-on exploitation or sale.
 
**MITRE ATT&CK:** `T1539`- Steal Web Session Cookie  
**MITRE ATT&CK:** `T1555.003`- Credentials from Password Stores: Credentials from Web Browsers
 
---

### Affected Software & Systems
 
| Field | Detail |
|---|---|
| **Affected software** | CPU-Z, HWMonitor, HWMonitor PRO, PerfMonitor, PowerMAX |
| **Affected versions** | 64-bit versions only |
| **Affected OS** | Windows (64-bit) |
| **Original binaries compromised?** | No. CPUID's signed original files were never tampered with |
 
---

### MITRE ATT&CK Summary
 
| ID | Technique |
|---|---|
| `T1195.002` | Supply Chain Compromise: Compromise Software Supply Chain |
| `T1574.001` | Hijack Execution Flow: DLL Search Order Hijacking |
| `T1027` | Obfuscated Files or Information |
| `T1055` | Process Injection |
| `T1140` | Deobfuscate/Decode Files or Information |
| `T1070.006` | Indicator Removal: Timestomp |
| `T1539` | Steal Web Session Cookie |
| `T1555.003` | Credentials from Password Stores: Credentials from Web Browsers |
| `T1497` | Virtualisation/Sandbox Evasion |
 
---

## 04 - Indicators of Compromise (IOCs)
 
> All domains and IP addresses below are **defanged**. The `[.]` notation replaces `.` to prevent accidental clicks on malicious links. Use the live versions when importing into security tools.
 
---
 
### Malicious Domains & C2 Infrastructure
 
| Indicator | Type | Description |
|---|---|---|
| `supp0v3[.]com` | Domain | Attacker-controlled domain used to host trojanised installers |
| `welcome[.]supp0v3[.]com` | Domain | Hardcoded C2 domain embedded in the STX RAT payload |
| `95.216.51[.]236` | IP Address | C2 IP address reused from the July 2025 campaign and the FileZilla attack |
 
---

### Malicious File Names
 
| File Name | Description |
|---|---|
| `HWiNFO_Monitor_Setup.exe` | Trojanised installer masquerading as a legitimate HWiNFO file |
| `CRYPTBASE.dll` | Malicious DLL sideloaded by the legitimate CPUID executables |
| `superbad.exe` | Earliest known STX RAT sample, observed July 2025 |
 
---
 
### Affected Legitimate File Names
 
> These are the legitimate CPUID files. Only trojanised versions distributed during the breach window were malicious. The originals were clean.
 
- `hwmonitor_1.63.exe`
- CPU-Z installer
- PerfMonitor installer
- PowerMAX installer
---

### File Hashes
 
File hashes for the malicious DLLs and installer files were published by Kaspersky in their threat intelligence report. These should be pulled directly from the Kaspersky report at `securelist[.]com` and added here, as reproducing them without direct verification risks introducing errors.
 
eSentire's YARA rules are also available for detecting STX RAT samples across endpoints - search *"eSentire STX RAT YARA rules"* to locate them.
 
---
 
### AV Detection Names
 
Various antivirus engines flagged the malicious files under different labels, including:
 
- `Trojan.Teddy`
- `Trojan.Artemis`
At least **32 engines** on VirusTotal flagged the installer as malicious at the time of discovery. Note that different AV engines assign different names to the same malware - `Teddy` and `Artemis` are generic catch-all labels used when an engine detects trojan-like behaviour but does not have a precise signature match. They are not separate malware families.
 
---
 
### Additional Forensic Indicators
 
| Indicator | Detail |
|---|---|
| **Falsified timestamp** | `2077-08-31 05:16:43` - malicious `CRYPTBASE.dll` compilation timestamp artificially set to a future date via timestomping |
| **Delivery infrastructure** | Attacker-controlled Cloudflare R2 storage used to host trojanised packages |
| **Distribution format** | Both ZIP archives and standalone installers |
 
---

## 05 - Impact Assessment

| Field | Detail |
|---|---|
| **Victims confirmed** | 150+ (Kaspersky visibility at time of reporting. Likely a significant undercount) |
| **Financial damage** | Not publicly disclosed |
| **Data compromised** | Browser-stored passwords, session cookies, host metadata |
| **Operational impact** | CPUID download infrastructure disrupted for approximately six hours |
 
---
 
### Victim Breakdown
 
The majority of confirmed victims were individuals. Organisations across the following sectors were also impacted:
 
- Retail
- Manufacturing
- Consulting
- Telecommunications
- Agriculture
Confirmed affected regions: **Brazil, Russia, China**
 
---
 
### Scale of Potential Exposure
 
CPU-Z alone has tens of millions of users globally, and HWMonitor is standard equipment for IT professionals, system administrators, data centre operators, and PC enthusiasts worldwide. The six-hour breach window on software of this reach represented an extraordinary infection opportunity - the true number of people who downloaded the malicious installer during that window is not publicly known, and CPUID has not disclosed download statistics for the period.
 
The **150+ figure should be treated as a floor, not a ceiling.** The malware's fileless, in-memory design means many victims would have seen no obvious signs of compromise and may never know they were affected.
 
---
 
### Data at Risk
 
- **Browser-stored passwords and login credentials** - harvested via Chrome's IElevation COM interface
- **Session cookies** - particularly valuable as they can allow account access without a password and in some cases bypass MFA entirely
- **Host metadata** - transmitted to the C2 server for victim identification and campaign tracking
---
 
### Broader Campaign Context
 
This breach was not an isolated incident. Breakglass Intelligence assessed it as part of a **10-month campaign** beginning in July 2025, with the earlier FileZilla trojanisation attack using the same infrastructure and payload. The pattern of targeting widely used, trusted utilities suggests the threat actor has an established and repeatable playbook for supply chain attacks, and further campaigns targeting other popular software cannot be ruled out.
 
If the stolen credentials were sold rather than used directly, which is consistent with the initial access broker theory, then the impact may extend far beyond what any single report can capture. Victims could potentially be facing follow-up attacks from entirely different threat actors who purchased access to the stolen credentials. 
 
---

---
 
## 06 - Detection & Mitigation
 
### Detection
 
**VirusTotal**
 
At the time of discovery, the malicious installer was flagged by at least 32 antivirus engines on VirusTotal (`virustotal[.]com`). Users who suspect they downloaded a compromised file during the breach window can upload it to VirusTotal to check it against multiple AV engines simultaneously. File hashes published by Kaspersky can also be checked directly without needing to upload the file itself.
 
**YARA Rules**
 
eSentire published YARA rules specifically capable of detecting STX RAT samples. Security teams can deploy these rules within their EDR or SIEM tools to hunt for signs of the malware across their environments.
 
> **SIEM** stands for *Security Information and Event Management* - a platform that aggregates and analyses security logs from across an organisation's systems in one place, helping teams spot suspicious patterns.
 
**Kaspersky IOCs**
 
Kaspersky published a full set of IOCs including file hashes, malicious domains, and the C2 IP address. These can be imported directly into threat intelligence platforms or firewall blocklists. Available at `securelist[.]com`.
 
**Behavioural Indicators**
 
Look for the following on any system that ran a CPUID installer during the breach window:
 
- Unexpected outbound connections to `supp0v3[.]com` or `welcome[.]supp0v3[.]com`
- `CRYPTBASE.dll` loaded from any location other than the Windows System32 directory
- `HWMonitor_x64.exe` spawning unexpected child processes
- PowerShell activity triggered by a hardware monitoring application
- .NET compilation activity occurring at the same time as a CPUID product launch
- Unusual interaction with Google Chrome's IElevation COM interface

**Windows Defender**
 
Several victims reported that Windows Defender flagged the malicious installer immediately upon download, before execution. Users with Defender active and up to date were partially protected at the point of delivery, though this would not have caught every variant given the malware's evasion capabilities.
 
**Hash Verification**
 
CPUID's original signed binaries were never compromised. The legitimate `hwmonitor_1.63.exe` remained accessible via its direct download URL throughout the breach window - its hash would not have matched the malicious version. This highlights the value of verifying file hashes before executing any installer.
 
---
 
### Mitigation
 
**If you downloaded CPUID software between April 9, 15:00 UTC and April 10, 10:00 UTC:**
 
- Assume compromise and treat any credentials stored in your browser as potentially stolen
- Immediately change passwords for all important accounts. Prioritise email, banking, cryptocurrency, and any corporate accounts
- Revoke active session cookies where possible. Most platforms allow this by signing out of all devices in your account security settings
- Enable MFA on all accounts if not already active. Consider switching to an authenticator app rather than SMS-based MFA
- Run a full system scan using an updated AV tool and cross-reference against Kaspersky's published IOCs
- If you are part of an organisation, notify your security team immediately. Do not attempt to remediate alone

**For security teams and organisations:**
 
- Block the known malicious domains and C2 IP address at the firewall and DNS level using Kaspersky's IOCs
- Deploy eSentire's YARA rules to hunt for STX RAT across endpoints
- Search endpoint logs for the behavioural indicators listed above, particularly unexpected `CRYPTBASE.dll` loads outside of System32
- Review browser credential stores on any machine that ran a CPUID installer during the breach window and rotate credentials as a precaution
- Check for lateral movement. Given STX RAT's remote access capabilities, a compromised machine should be treated as a potential foothold for further activity within the network

**General hardening recommendations highlighted by this incident:**
 
- Always verify file hashes before running installers downloaded from the web. Most developers publish expected hash values alongside their downloads
- Be suspicious of installers that launch in an unexpected language or under an unexpected file name
- Avoid storing passwords in your browser where possible. Use a dedicated password manager instead, as these are significantly harder for infostealers to access
- Keep EDR and AV tools updated. The malware's evasion techniques were sophisticated, but several engines still detected it
- Monitor outbound DNS and HTTP/S traffic for connections to unexpected domains, particularly from applications that have no legitimate reason to make network connections (such as hardware monitoring tools)
---
 
### CVEs (Common Vulnerabiliuties and Exposures)
> CVEs are a standardised naming system for publicly know security vulnerabilities. Every know vulnerability is assigned a unique ID, which allows security professionals, vendors, and tools to discuss issues without confusions. The system is maintained by the MITRE Corporation, with input from vendors, researchers, and organizations worldwide.

No specific CVEs have been publicly assigned to this incident at time of writing. The attack exploited a compromised API rather than a known software vulnerability. This means there is no patch to apply in the traditional sense. The vector was the supply chain itself rather than a flaw in the end user's software.

## 07 - Sources & References
 
> Sources accessed April 2026. Cybersecurity reports are sometimes updated or revised after publication. Please check each source directly for the most current version.
 
---
 
### Primary Research & Threat Intelligence
 
| Source | Notes |
|---|---|
| **Kaspersky** (`securelist[.]com`) | Primary technical analysis - breach window, victim count, DLL sideloading, C2 infrastructure, FileZilla campaign link, and full IOC set |
| **Breakglass Intelligence** | Attribution analysis - Russian-speaking threat actor, 10-month campaign timeline, April 3 possible earlier start date |
| **Cyderes Howler Cell** (`cyderes[.]com/howler-cell/how-cpuids-hwmonitor-supply-chain-was-hijacked-to-deploy-stx-rat`) | In-depth technical breakdown - five-stage unpacking chain, DLL sideloading mechanics, timestomping, NTDLL proxying |
| **eSentire** | YARA rules for STX RAT detection and infostealer capability documentation |
| **vx-underground** (`x[.]com/vxunderground`) | Early community analysis, fileless operation, evasion techniques, browser credential theft objective |
 
---
 
### News & Media Coverage
 
| Source | URL |
|---|---|
| **BleepingComputer** | `bleepingcomputer[.]com/news/security/supply-chain-attack-at-cpuid-pushes-malware-with-cpu-z-hwmonitor` |
| **The Hacker News** | `thehackernews[.]com/2026/04/cpuid-breach-distributes-stx-rat-via.html` |
| **The Register** | `theregister[.]com/2026/04/10/cpuid_site_hijacked` |
| **SecurityWeek** | `securityweek[.]com/cpuid-hacked-to-serve-trojanized-cpu-z-and-hwmonitor-downloads` |
| **Tom's Hardware** | `tomshardware[.]com/tech-industry/cyber-security/hwmonitor-and-cpu-z-developer-cpuid-breached-by-unknown-attackers` |
| **Cybernews** | `cybernews[.]com/security/cpuid-hwmonitor-hwinfo-cpuz-deliver-malware` |
| **Help Net Security** | `helpnetsecurity[.]com/2026/04/13/cpuid-download-malware` |
| **UpGuard** | `upguard[.]com/news/cpuid-data-breach-2026-04-13` |
 
---
 
### Reference Frameworks & Tools
 
| Resource | URL | Purpose |
|---|---|---|
| **MITRE ATT&CK** | `attack[.]mitre[.]org` | Reference for all technique IDs listed in Section 03 |
| **VirusTotal** | `virustotal[.]com` | Multi-engine malware scanning; check Kaspersky hashes here |
| **MalwareBazaar** | `bazaar.abuse[.]ch` | STX RAT sample cross-referencing |
 
---
 
### Primary Statement
 
**Samuel Demeulemeester (CPUID contributor)** - Official public statement issued 10th April 2026, confirming the breach, acknowledging the compromised side API, and confirming the fix. Quoted across multiple outlets.
 
---
 
*Part of the Cybersecurity Incident Breakdowns series.*
