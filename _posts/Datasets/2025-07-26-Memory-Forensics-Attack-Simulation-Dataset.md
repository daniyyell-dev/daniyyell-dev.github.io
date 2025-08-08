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

The cases range in complexity from unknown infections to targeted Cobalt Strike intrusions, offering varied examples useful for building or testing memory analysis workflows using tools like **Volatility3**, **YARA**, and **Malcat**.

Whether you're a student, analyst, or researcher, this resource is intended to provide practical value for learning and advancing your memory forensics capabilities.


| **Attack ID** | **Name** | **Technique(s)** | **Malware** | **Persistence** | **Network Activity** | **Evasion** | **Download Link** |
|---------------|----------|------------------|-------------|-----------------|----------------------|-------------|-------------------|
| attack1 | Unknown_Win10_hard | Suspicious execution | Unknown | Not confirmed | Possible beaconing | Masquerading, native tool abuse | [Download](https://drive.google.com/file/d/1RywhSgqoDdDjpXSvrg8d7-Lq90iAuutz/view?usp=sharing) |
| attack2 | process_Injection_hard | Process injection | NimPlantv2 | ScheduleTask | Outbound C2 suspected | Code in legitmate process | [Download](https://drive.google.com/file/d/1R9Wpn1obaUGT0-IOSlTMjR7s2v6ahROR/view?usp=sharing) |
| attack3 | cobaltstrike_beacon_Hard | Beacon stage | Cobalt Strike | Not confirmed | C2 activity | Named pipes, obfuscation | [Download](https://drive.google.com/file/d/1bdMgyckWjUtzV5HuFqEjXcqEY10Ji3mG/view?usp=sharing) |
| attack4 | AsyncRAT_infection | Standalone RAT | AsyncRAT | Unknown | Encrypted HTTP/HTTPS beaconing | Blends with normal processes | [Download](https://drive.google.com/file/d/11weo6uTh6toXoxzDwqXLJdLXkywtoeTt/view?usp=sharing) |
| attack5 | MasonRAT_intermediate | Standalone RAT | MasonRAT | Unknown | Outbound C2 | No injection | [Download](https://drive.google.com/file/d/1k-ETi3MpB6bkXzzzz3NYP3c2iQVAW7oK/view?usp=sharing) |
| attack6 | cobaltstrike_process_inj_Hard | Process injection | Cobalt Strike | Unknown | C2 suspected | Process injection | [Download](https://drive.google.com/file/d/105g0-zDoD8vlAHoNFzd27UHk2Knj9nrj/view?usp=sharing) |



**Stay tuned for updating...**
