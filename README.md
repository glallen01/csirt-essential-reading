# csirt-essential-reading

Reading List for CSIRT Team Members

The goal of this list is to develop a prioritized list of essential reading for network defenders.

## Overview Reading:

* [CIS Top 20](https://www.sans.org/critical-security-controls)
* [NSA Manageable Network Plan Guide](https://www.iad.gov/iad/customcf/openAttachment.cfm?FilePath=/iad/library/ia-guidance/security-configuration/networks/assets/public/upload/manageable-network-plan-guide.pdf)
* [NSA Methodology for Adversary Obstruction](https://www.iad.gov/iad/library/reports/nsa-methodology-for-adversary-obstruction.cfm)

## Essential Reading, in order of priority:

* [@sroberts Introduction to DFIR](https://sroberts.github.io/2016/01/11/introduction-to-dfir-the-beginning/)
* [SANS Digital Forensics Cheat-Sheets](https://digital-forensics.sans.org/community/cheat-sheets)
* [Spotting the Adversary with Windows Event Log Monitoring](https://www.iad.gov/iad/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm)
* [Reducing the Effectiveness of Pass-the-Hash](https://www.iad.gov/iad/library/reports/reducing-the-effectiveness-of-pass-the-hash.cfm)
* [Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft](https://www.microsoft.com/en-us/download/details.aspx?id=36036)


## Topic Specific Essential Reading:

### Host Analysis

### Network Security Monitoring (NSM)

* <http://www.malware-traffic-analysis.net/>
* <http://blog.malwaremustdie.org>

### Host Monitoring

* [WMI VS. WMI: Monitoring for Malicious Activity](https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html)

### Threats

* [Fireeye Red Team Tool Roundup](https://www.fireeye.com/blog/threat-research/2016/07/red_team_tool_roundup.html)

## Github Repos:

* [Threat Hunting Project](https://github.com/ThreatHuntingProject/ThreatHunting)
* [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)
A curated list of tools and resources for security incident response, aimed to
help security analysts and DFIR teams.
* [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)
A curated list of Awesome Threat Intelligence resources 
* [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
A curated list of awesome malware analysis tools and resources. 
* [Awesome Security](https://github.com/sbilly/awesome-security)
A collection of awesome software, libraries, documents, books, resources and cool stuff about security.
* [APTnotes](https://github.com/aptnotes/data) APTnotes is a repository of publicly-available papers and blogs (sorted by year) related to malicious campaigns/activity/software that have been associated with vendor-defined APT (Advanced Persistent Threat) groups and/or tool-sets.
* [OLD APTnotes](https://github.com/kbandla/APTnotes) Various public documents, whitepapers and articles about APT campaigns
* [Awesome pcaptools](https://github.com/caesar0301/awesome-pcaptools)
* [Awesome Infosec](https://github.com/onlurking/awesome-infosec)

## Essential References:

* [CIS Secure Configuration Benchmarks](https://benchmarks.cisecurity.org/)

* [Security Technical Implementation Guides (STIGs)](http://iase.disa.mil/stigs/Pages/index.aspx)
Hardening templates from the Defense Information Systems Agency. Also [StigViewer](https://www.stigviewer.com/stigs)

* [National Vulnerability Database](https://web.nvd.nist.gov/view/vuln/search)
NVD is the U.S. government repository of standards based vulnerability management data represented using the Security Content Automation Protocol (SCAP). This data enables automation of vulnerability management, security measurement, and compliance. NVD includes databases of security checklists, security related software flaws, misconfigurations, product names, and impact metrics.

## Books:

* * *

# Uncategorized / Unprioritized documents:

These need triage to move into the list. If so, add a summary of each link also.

## queue up to reading list

* [The Diamond Model of Intrusion Analysis](https://www.threatconnect.com/wp-content/uploads/ThreatConnect-The-Diamond-Model-of-Intrusion-Analysis.pdf)
This paper presents a novel model of intrusion analysis built by analysts, derived from years of experience, asking the simple question, “What is the underlying method to our work?” The model establishes the basic atomic element of any intrusion activity, the event, composed of four core features: adversary, infrastructure, capability, and victim. These features are edge-connected representing their underlying relationships and arranged in the shape of a diamond, giving the model its name: the Diamond Model. It further defines additional meta-features to support higher-level constructs such as linking events together into activity threads and further coalescing events and threads into activity groups. These elements, the event, thread, and group all contribute to a foundational and comprehensive model of intrusion activity built around analytic processes. It captures the essential concepts of intrusion analysis and adversary operations while allowing the model flexibility to expand and encompass new ideas and concepts. The model establishes, for the first time, a formal method applying scientific principles to intrusion analysis – particularly those of measurement, testability, and repeatability – providing a comprehensive method of activity documentation, synthesis, and correlation. This scientific approach and simplicity produces improvements in analytic effectiveness, efficiency, and accuracy. Ultimately, the model provides opportunities to integrate intelligence in real-time for network defense, automating correlation across events, classifying events with confidence into adversary campaigns, and forecasting adversary operations while planning and gaming mitigation strategies.

* [SANS Digital Forensics and Incident Response Blog | Protecting Privileged Domain
Accounts: PsExec Deep-Dive](https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive)

* [An Analysis of Meterpreter during Post-Exploitation](https://www.sans.org/reading-room/whitepapers/forensics/analysis-meterpreter-post-exploitation-35537)
Abstract: Much has been written about using the Metasploit Framework, but what has received minimal attention is an analysis of how it accomplishes what it does. This paper provides an analysis of the post-exploitation activity of a Meterpreter shell on a compromised Windows 7 system. Areas looked at include the characteristics of the stager and payload, fingerprinting the HTTP C2 and beaconing traffic, finding Meterpreter in memory, and several post-exploitation modules that could be used. By focusing on what occurs instead of how to accomplish it, defenders are better equipped to detect and respond.

* [Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
Abstract: DNS is a foundational protocol which enables applications such as web browsers to function based on domain names. DNS is not intended for a command channel or general purpose tunneling. However, several utilities have been developed to enable tunneling over DNS. Because it is not intended for general data transfer, DNS often has less attention in terms of security monitoring than other protocols such as web traffic. If DNS tunneling goes undetected, it represents a significant risk to an organization. This paper reviews DNS tunneling utilities and discusses practical techniques for detecting DNS tunneling. Two categories of detection considered are payload analysis and traffic analysis. The payload detection techniques have been used to detect successfully specific DNS tunneling utilities. The traffic analysis based technique can be used to universally detect DNS tunneling. With these detection techniques implemented organizations can reduce the risk associated with DNS tunneling.


## queue up to references

* [SANS Intrusion Discovery Cheatsheet, Windows](https://www.sans.org/media/score/checklists/ID-Windows.pdf)

* [SANS Intrusion Discovery Cheatsheet, Linux](https://www.sans.org/media/score/checklists/ID-Linux.pdf)

## needs assessment:

* Shedding Light on Security Incidents Using Network Flows
<https://www.sans.org/reading-room/whitepapers/networkdevs/shedding-light-security-incidents-network-flows-33935>

* An Approach to Detect Malware Call-Home Activities
<https://www.sans.org/reading-room/whitepapers/detection/approach-detect-malware-call-home-activities-34480>

* Assessing Outbound Traffic to Uncover Advanced Persistent Threat:
<https://www.sans.edu/student-files/projects/JWP-Binde-McRee-OConnor.pdf>

* An Approach Detect Malware Call Home Activities:
<https://www.sans.org/reading-room/whitepapers/detection/approach-detect-malware-call-home-activities-34480>

* Detect, Contain and Control Cyberthreats:
<https://www.sans.org/reading-room/whitepapers/analyst/detect-control-cyberthreats-36187>

* Automated Defense - Using Threat Intelligence to Augment:
<https://www.sans.org/reading-room/whitepapers/threats/automated-defense-threat-intelligence-augment-35692>

* Trends in Bot Net Command and Control:
<https://www.giac.org/paper/gsec/4396/trends-bot-net-command-control/107402>

* Covert Channels Over Social Networks:
<https://www.sans.org/reading-room/whitepapers/threats/covert-channels-social-networks-33960>

* Detecting and Preventing Unauthorized Outbound Traffic:
<https://www.sans.org/reading-room/whitepapers/detection/detecting-preventing-unauthorized-outbound-traffic-1951>

* gh0st-dshell-decoding-undocumented-protocols:
<https://www.sans.org/reading-room/whitepapers/detection/gh0st-dshell-decoding-undocumented-protocols-37032>

* SANS: The Conficker Worm:
<https://www.sans.org/security-resources/malwarefaq/conficker-worm.php>

* SANS Digital Forensics Cheat Sheets
<https://digital-forensics.sans.org/community/cheat-sheets>

* Profiling SSL Clients with tshark:
<https://isc.sans.edu/forums/diary/Profiling+SSL+Clients+with+tshark/21361/>

* SANS Digital Forensics and Incident Response Blog | The Importance of Command
and Control Analysis for Incident Response
<https://digital-forensics.sans.org/blog/2014/03/31/the-importance-of-command-and-control-analysis-for-incident-response>

* Using Risk Analysis to Inform Intelligence Analysis:
<http://www.rand.org/pubs/working_papers/WR464.html>

* IOCs: How to Create, Manage, and Understand:
<https://malwerewolf.com/2014/12/iocs-create-manage-understand-manifesto/>

* [yahoo/PyIOCe](https://github.com/yahoo/PyIOCe)

* Fireeye IOC Editor:
<https://www.fireeye.com/services/freeware/ioc-editor.html>

* The Incident Object Description Exchange Format:
<https://tools.ietf.org/html/rfc5070>

* Cyber Threat Intel and IR Report Template:
<https://zeltser.com/media/docs/cyber-threat-intel-and-ir-report-template.pdf>

* SANS Security Information/Event Management Security Development Life Cycle Version 5: 
<https://www.sans.org/media/score/esa-current.pdf>

* Cyber Security Incident Response: Are we as prepared as we think?:
<https://www.lancope.com/sites/default/files/Lancope-Ponemon-Report-Cyber-Security-Incident-Response.pdf>

* APT Incident Handling Checklist:
<https://www.sans.org/media/score/checklists/APT-IncidentHandling-Checklist.pdf>

* An Introduction to the Computer Security Incident Response Team (CSIRT) Set-Up
and Operational Considerations:
<https://www.giac.org/paper/gsec/3907/introduction-computer-security-incident-response/106281>

* Incident Handlers Handbook:
<https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901>

* Slicksheet Segregating Networks And Functions
<https://www.nsa.gov/ia/_files/factsheets/I43V_Slick_Sheets/Slicksheet_SegregatingNetworksAndFunctions_Web.pdf>

* Slicksheet Limiting Workstation to Workstation Communication
<https://www.nsa.gov/ia/_files/factsheets/I43V_Slick_Sheets/Slicksheet_LimitingWtWCommunication_Web.pdf>

## License

Licensed under [Apache License 2.0](LICENSE).
