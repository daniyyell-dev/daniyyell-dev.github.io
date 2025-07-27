---
title: "Memory Forensics Attack Simulation Dataset"
classes: wide
header:
  teaser: /assets/images/memory-forensics/data.png
ribbon: DarkRed
description: "A curated memory forensics dataset containing simulated attacks involving process injection, credential dumping, and malware such as Cobalt Strike, AsyncRAT, and MasonRAT. This resource supports research, detection engineering, and training in malware analysis and incident response."
categories:
  - Datasets
toc: true
date: 2025-07-20
---



# Introduction

This post presents a curated **memory forensics dataset** designed to support research, detection engineering, and hands-on training in the fields of **malware analysis**, **incident response**, and **threat simulation**. The dataset contains memory dumps collected from controlled attack scenarios on Windows 10 systems, covering various techniques such as:

* **Process injection**
* **Credential dumping**
* **Remote access trojans (RATs)**
* **Fileless malware**
* **Cobalt Strike beacons**

Each scenario includes a detailed description, artefacts (e.g., `.mem` files), and relevant attack characteristics such as evasion techniques, persistence indicators, and suspected C2 activity.

The cases range in complexity from unknown infections to targeted Cobalt Strike intrusions, offering varied examples useful for building or testing memory analysis workflows using tools like **Volatility**, **YARA**, and **Malcat**.

Whether you're a student, analyst, or researcher, this resource is intended to provide practical value for learning and advancing your memory forensics capabilities.




## attack1_Unknown_Win10_hard

### `attack1_Unknown_Win10_hard`

### Summary

This folder contains forensic materials from a malware infection on a Windows 10 system where the exact threat could not be identified. Although the infection shows signs of post-compromise activity, the malware family remains undetermined. Live memory was captured during the suspicious activity for further investigation.

### Artifacts

- **Win10_Unknown.mem**: Memory dump from the affected Windows 10 system

### Attack Details

- **Malware**: Unknown
- **Behaviour**: Exhibits typical signs of compromise and suspicious execution
- **Persistence**: Not confirmed
- **Network Activity**: Requires analysis for possible IP connections or beacons
- **Evasion**: May rely on masquerading or native tool abuse

[DOWNLOAD HERE!](https://drive.google.com/file/d/1RywhSgqoDdDjpXSvrg8d7-Lq90iAuutz/view?usp=sharing)

## attack2_process_Injection_hard

### Folder: `attack2_process_Injection_hard`

### Summary

This folder contains forensic evidence of a process injection attack on a Windows 10 host. The attacker injected malicious code into a legitimate process to evade detection and maintain access. Memory was captured while the injection was active.

### Artifacts

- **Process_Injection.mem**: Captured memory from the system under attack

### Attack Details

- **Technique**: Process injection involving code execution within a trusted process
- **Behaviour**: Malicious threads observed in legitimate system binaries
- **Persistence**: Not yet determined
- **Network Activity**: Possible outbound connection or C2 traffic
- **Evasion**: Code concealed within trusted process context

DOWNLOAD HERE!

## attack3_cobaltstrike_beacon_Hard

### Folder: `attack3_cobaltstrike_beacon_Hard`

### Summary

This folder contains memory forensic artefacts from a Windows 10 system compromised using Cobalt Strike. The captured data reflects an active beacon stage, suggesting post-exploitation activity was ongoing at the time of acquisition.

### Artifacts

- ColbaltStrike_memdump.mem: Live memory image containing Cobalt Strike components

### Attack Details

- **Malware**: Cobalt Strike
- **Behaviour**: Active beacon likely injected into or running alongside system processes
- **Persistence**: Not confirmed
- **Network Activity**: C2 activity expected; analysis required for domain/IP extraction
- **Evasion**: Likely use of obfuscation, named pipes, and in-memory execution

[DOWNLOAD HERE!](https://drive.google.com/file/d/1bdMgyckWjUtzV5HuFqEjXcqEY10Ji3mG/view?usp=sharing)

## attack4_AsyncRAT_infection_Intermediate

### Folder: `attack4_AsyncRAT_infection_Intermediate`

### Summary

This folder contains memory forensics materials related to an AsyncRAT infection on a Windows 10 system. The attacker successfully compromised the host and established a remote access session. Live memory was captured during the infection for further analysis.

### Artifacts

- **AsyncRAT_Win10.mem**: Memory dump of the infected system captured post-compromise.

### Attack Details

- **Malware**: AsyncRAT
- **Behaviour**: Executes as a standalone process alongside normal system activity
- **Persistence**: Not yet confirmed (may include registry or scheduled task)
- **Network Activity**: Likely beaconing to C2 over encrypted HTTP/HTTPS
- **Evasion**: Blended with normal processes to avoid detection, but not injected into them.

[DOWNLOAD HERE!](https://drive.google.com/file/d/11weo6uTh6toXoxzDwqXLJdLXkywtoeTt/view?usp=sharing)

## attack5_MasonRAT_intermediate

### Folder: `attack5_MasonRAT_intermediate`

### Summary

This folder contains forensic data related to a MasonRAT infection on a Windows 10 host. The malware executed as a standalone .NET application and maintained remote access capability. Memory was acquired during the active infection phase.

### Artifacts

- **MasonRATmemdump.mem**: Captured memory image containing active RAT process

### Attack Details

- **Malware**: MasonRAT
- **Behaviour**: Runs as an independent .NET process separate from legitimate applications
- **Persistence**: Not yet identified
- **Network Activity**: Indicators of outbound connections likely present
- **Evasion**: Operates discretely without injecting into other processes

[DOWNLOAD HERE!](https://drive.google.com/file/d/1k-ETi3MpB6bkXzzzz3NYP3c2iQVAW7oK/view?usp=sharing)

## attack6_Cobaltstrike_process_inj_Hard

### Folder: `attack6_Cobaltstrike_process_inj_Hard`

### Summary

This folder includes evidence from a Cobalt Strike infection involving process injection on a Windows 10 system. Memory capture occurred while the beacon was active within a legitimate process context.

### Artifacts

- **CobaltStrike_Injection_2.mem**: Memory image taken during the injected beacon session

### Attack Details

- **Malware**: Cobalt Strike
- **Technique**: Injected beacon into a trusted system process
- **Persistence**: Unknown
- **Network Activity**: Potential C2 communication with local or external IP
- **Evasion**: Executed in memory, concealed through process injection tactics

[DOWNLOAD HERE!](https://drive.google.com/file/d/105g0-zDoD8vlAHoNFzd27UHk2Knj9nrj/view?usp=sharing)