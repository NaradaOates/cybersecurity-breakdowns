# CPUID Supply Chain Attack - STX RAT Incident Breakdown
 
> **Series:** Cybersecurity Incident Breakdowns  
> **Status:** Draft - work in progress  
> **Last updated:** April 2026
 
---
## Why this incident? 
At the beginning of 2026, I built a new gaming PC, and like most PC owners, I wanted to monitor my component's temperature and performance. My go-to method to doing this was via CPUID's CPU-Z and HWMonitor. I had their homepage open in my browser tab ready to download the software. However, life got in the way, and I never got round to it. 

Fast forward to mid-April, I am on my long-awaited two week spring holiday, and the tab is still sitting there. Before clicking download, I did what I had been doing for the past couple of months and checked Tom's Hardware for the latest news on the RAM crisis. That is when I saw that the CPUID's download links had been compromised and was serving malware to anyone who had downloaded their software during a specific window. 

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
| **Malware type** | Remote Access Trojan (RAT) with infostealer capabilities |
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
 
> **Background - MITRE ATT&CK:** The technique IDs referenced throughout this section use the [MITRE ATT&CK framework](https://attack.mitre.org). A globally recognised, standardised catalogue of the methods threat actors use to carry out attacks. Each technique is assigned a unique ID (prefixed with `T`) so that researchers and security teams worldwide can reference the same technique without ambiguity. Sub-techniques are denoted with a dot (e.g. `T1574.001`).

---

### Initial Vector
 
It was a supply chain attack which led to CPUID's side API being compromised. This caused the official `cpuid[.]com` website to randomly serve malicious download links in place of legitimate ones. The trojanised installers were hosted on attacker-controlled Cloudflare R2 infrastructure under the domain `supp0v3[.]com`, and distributed both as ZIP archives and standalone installers.
 
**MITRE ATT&CK:** `T1195.002` — Supply Chain Compromise: Compromise Software Supply Chain
 
---
 
### Delivery Mechanism
 
Users downloading CPU-Z, HWMonitor, PerfMonitor, or PowerMAX during the breach window received a trojanised package containing two components:
 
- The **legitimate, signed CPUID executable** — unmodified, providing a convincing disguise
- A **malicious DLL** named `CRYPTBASE.dll` — the actual malicious component
The malicious installer masqueraded as `HWiNFO_Monitor_Setup.exe`, mimicking a separate legitimate tool (HWiNFO) to avoid suspicion. A technique known as **file masquerading**. The installer used an **Inno Setup wrapper** (a legitimate packaging tool used by developers to bundle software into installers) that launched in Russian, which was atypical for CPUID's software and helped alert early victims. Only the **64-bit versions** of the affected software were impacted.
 
---
 
### Execution - DLL Sideloading
 
When the victim ran the installer and launched the 64-bit executable (e.g. `HWMonitor_x64.exe`), Windows automatically loaded `CRYPTBASE.dll` from the same folder **before** looking for the legitimate system version in Windows' System32 directory.
 
This technique is known as **DLL sideloading**, or more specifically **DLL search order hijacking**. The malware placed a rogue DLL with the same name as a trusted system file in a location Windows checks first, tricking the system into loading the malicious version instead.
 
The malicious DLL's compilation timestamp had been deliberately falsified to `2077-08-31 05:16:43` — a technique known as **timestomping**, used to confuse forensic investigators attempting to establish when the file was created.
 
**MITRE ATT&CK:** `T1574.001` — Hijack Execution Flow: DLL Search Order Hijacking  
**MITRE ATT&CK:** `T1070.006` — Indicator Removal: Timestomp

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
 
**MITRE ATT&CK:** `T1497` — Virtualisation/Sandbox Evasion
 
---
 
### C2 Communication
 
The final payload connected to a hardcoded C2 domain — `welcome[.]supp0v3[.]com` — and transmitted host metadata back to the attacker for victim identification and campaign tracking. This C2 address had been **reused from the earlier FileZilla campaign**, which is the operational security mistake that allowed researchers to link the two attacks to the same threat actor. The malware communicated over HTTP/S.

---

### NTDLL Proxying
 
To avoid detection by EDR (Endpoint Detection and Response) tools monitoring Windows system calls, the malware **proxied NTDLL functionality from a .NET assembly**.
 
NTDLL is a core Windows system file that security tools monitor closely because almost everything a program does on Windows passes through it. Rather than using the real NTDLL - which security tools watch closely - the malware created its own version of those functions and routed its activity through that instead, effectively stepping around the security camera watching the front door.
