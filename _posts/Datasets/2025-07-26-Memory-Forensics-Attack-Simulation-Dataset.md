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



## Dataset downloads on Zenodo

<p><a href="https://zenodo.org/records/23575239" class="btn btn--primary btn--x-large btn--block" aria-describedby="zenodo-download-status">DOWNLOAD HERE</a></p>

<p id="zenodo-download-status">The six memory images are now hosted on Zenodo. Use the button above to open the complete dataset record, or download individual files from the scenario table below.</p>

This website remains the guide to the attack scenarios and memory analysis context. The dataset is archived on Zenodo with a persistent DOI for citation and access.

**Dataset DOI:** [10.5281/zenodo.23575239](https://doi.org/10.5281/zenodo.23575239)  
**Dataset version:** 1.0.0  
**Original publication date:** 20 July 2025  
**Dataset licence:** Creative Commons Attribution 4.0 International (CC BY 4.0)

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
| attack1 | Unknown_Win10_hard | Suspicious execution | Unknown | Not confirmed | Possible beaconing | Masquerading, native tool abuse | [Download](https://zenodo.org/records/23575239/files/Win10_Unknown.mem?download=1) |
| attack2 | process_Injection_hard | Process injection | NimPlantv2 | ScheduleTask | Outbound C2 suspected | Code in legitimate process | [Download](https://zenodo.org/records/23575239/files/attack2_process_Injection.mem?download=1) |
| attack3 | cobaltstrike_beacon_Hard | Beacon stage | Cobalt Strike | Not confirmed | C2 activity | Named pipes, obfuscation | [Download](https://zenodo.org/records/23575239/files/ColbaltStrike_memdump.mem?download=1) |
| attack4 | AsyncRAT_infection | Standalone RAT | AsyncRAT | Unknown | Encrypted HTTP/HTTPS beaconing | Blends with normal processes | [Download](https://zenodo.org/records/23575239/files/AsyncRAT_Win10.mem?download=1) |
| attack5 | MasonRAT_intermediate | Standalone RAT | MasonRAT | Unknown | Outbound C2 | No injection | [Download](https://zenodo.org/records/23575239/files/MasonRATmemdump.mem?download=1) |
| attack6 | cobaltstrike_process_inj_Hard | Process injection | Cobalt Strike | Unknown | C2 suspected | Process injection | [Download](https://zenodo.org/records/23575239/files/CobaltStrike_Injection_2.mem?download=1) |



## Citation

Jeremiah, Daniel, and Rafiq, Husnain. (2025). *Memory Forensics Attack Simulation Dataset* (Version 1.0.0) [Data set]. Zenodo. [https://doi.org/10.5281/zenodo.23575239](https://doi.org/10.5281/zenodo.23575239).
