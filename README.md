# April2025-TheActiveDefender-DrCatherineUllman


Notes from The Active Defender: Immersion in the Offensive Security Mindset


### Preface/Intro:

- Security belongs to everyone, even those who are infosec adjacent and everyone should be cognizant of the role they plany in securing their environment

- Don't just think defensively, but offensively as well

- Thesis: Active defenders are an alternative approach to cybersecurity defense, rather than passive/reactive Active Defenders engage in an offensive/attacker mindset to be more effective.
- Broadly: Defensive security teams are responsible for protecting systems against risks, ID'ing flaws, patching, and providing recodmmendations to increase the security posture of the org (i.e. network admins, devs, security engineers, etc...)
- Broadly: Offensive security teams are responsible for testing the defensive mechanisms put in place to protect an orgs systems from pen testing to full adversarial emulation.
- Challenges defensive secuirty teams face: Increasing cost of data breaches ($4.35 million, 2022) and time (avg time to discover/contain an attacker 277 days), compromised creds are the most popular intial attack method.
- Additional challenges: Teams are overwhlemed with work and there's not enough incentives in place for proper vuln management and other critical security tasks
- Cloud computing is an ongoing chllenge area b/c of new environments, tools, and configs that aren't fully established
- Environments can often be easily breached within hours and further compromised when defensive security teams don't know what to look for
- How we got here AV, Firewalls, SSL, IDS/IPS, SIEM aggregation
- References Robert M. Lee's Sliding Scale of Cyberscurity whitepaper (2015) which has 5 categories of actions/competencies/investments/resources: architecture, passive dfesne, active defense, intel, and offense.
- Passive defense: systems added to the architecture to provide consistent protection against or insight into threats without constant human interaction. (AV, IPS/IDS, firewalls, etc..)
- "Lee explains that active defense for cybersecurity is “the process of analysts monitoring for, responding to, learning from, and applying their knowledge to threats internal to the network.”
- Things keeping security practitioners stuck: inertia and org culture.  Inertia: That's how we've always done it, tools used, alert/warning fatigue via false positivies, financial constraints (that usually only change when a breach/incident occurs), understaffing/little training
- Org culture can be resistance to change (e.g. only changing firewall rules during a prescribed change time, which doesn't help much during an ongoing incident), siloing, outsourcing/vendors, shadow IT, BYOD, leadership/management buy in
- A key missing piece is defenders being unaware of offensive security practices or they intentionally avoid them for reasons including leadership, frequent auditing/fatigue, being an egotistical dick/know it all,

### Ch 1: What is an active defender

- Must have a more than superficial understanding of other sides behaviors/tactices to include understanding their objectives, thought processes, motivations, etc...
- Hacker mindset: one of curiosity, creativity, persistance, and nonlinear thinking examples include phone phreakers, MIT Model Railroad Train club, etc... there is consistent investigation and exploration
- Traditional Defender Mindset: As John Lambert, Distinguished Engineer, Microsoft Threat Intelligence Center says, “Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win.
    - e.g. NIST, ISO, PCI compliance, etc...
 
- lists = linear thinking where they can do everything right according to the list, but it's not enough against someone who thinks outside the box
- Defenders usually go through a walk through flowchart as opposed to a deep investigation

"""
Being an Active Defender requires more than the ability to break through the darkness. They also must understand the difference between the ability to “see” and the ability to “observe” the various pieces of information that they discover, whether in log files, security tools, or incoming intelligence. Simply “seeing” something is a passive function, whereas “observing” something is an active function. This ability is part of the hacker mindset and is crucial to making the connections often overlooked by traditional defenders. (Ullman, 5)
"""



- Data + business context = key artifacts for the active defender to use

"""
Active Defenders take the joyful and creative exploration of the hacker mindset and apply it to their defensive roles. By their nature, they have a proactive security ethos. In other words, it is in their character to actively seek out ways for their organizations to become more secure, whether by traditional means such as network segmentation or more innovative ways such as taking extra steps to understand how specific attack vectors work. They view the notion of “security” as a verb, something that they actively work at doing or being rather than a destination or an ultimate goal to achieve. (Ullman, 6)
"""

- Active security is a constant and evolving practice, not a destination in order to achieve excellence/the best possible version of security for the context you are in.
- Active defenders engage w/ the offensive security in a number of ways via social media, meetups, threat modeling, thrunting, etc...

- Threat modeling: proactive risk based eval on what attacks are likely/possible for a given environment/situation by assessing what you/your org has of value and what vulns/threats could be leveraged against your org.
- Threat models include MS STRIDE (Spoofing, Tampering, Repuidation, Information Disclosure, Denial of Service, Esclation of Privileges), CVSS, Threat Modeling Manifesto, etc...
- Thrunting: Defenders who proactively search data to find threats that evade traditional security measures leveraging tools beyond alerts/SIEMs.  Thrunters can help detect misconfigs, poor practives, reduce attack surface, and identify gaps.
- The thrunt process should be repeatable, not random be it searching logs, getting more framiliar w/ the environment, or accessing additonal datasets.


- Attack simulations allows the utilization of actions/behaviors that an attacker might perform in the environment being defended to allow for tuning, testing, and developing new procedures. This can include free software such as Atomic Red team and paid software such as SCYTHE adversary emulation.
  
- Active defense does not mean hack back, only defending up to/including anything within your area of responsibility/network
- There are different interpertations of what active defense can/does mean, John Strand definse it as "the employment of limited offensive action/counter attacks to deny a contested position" this includes annoyance (imposting cost/deception/honeypots), attribution, and attack(malware/canaries).
- Even security vendors are getting in on "active defense" w/ Fortinet offering tools to "slow down hackers/make cyberattacks more difficult to carry out" or Illusive offering observability/visiblity to "create a hositle environment and accelerating the time to detection for adversaries"
- While automated tools help, true active defense requires human intervention*

Active defense advantages: 

- More inovlement in the environment
- Less tunnel vision/alert fatigue
- better detection/prevention
- able to engage/understand the environment as a whole rather than just focusing on the next fire
- Reduced attack surface, longer breakout/infiltration time, fewer resources needed for remediation
- Greater relevent intel recognition and how to apply it (e.g. vendor/ISCA alerts and being able to integrate the suggestions or IoCs into the environment)
- Better understanding of existing threats, living off the land, and attacker behavior

- THere are a number of tools active defenders can use to categorize/understand attackers such as the Pyramid of Pain (1), writeups, MITRE ATT&CK framework, TTP pyramid, etc...
(1) ranks the indicators used to detect an attacker's activity by the “pain” it would cause them if they are discovered by the defender.xix The higher the indicator, the more pain for the attacker (Ullman, 14)
![image](https://github.com/user-attachments/assets/fcd4e25d-5875-48ae-9af4-84d0e43f2bfe)

- Active defenders who are aware of attacker capabilities, TTPs, etc... are more likely to spot ongoing attacks and be able to stop them or prevent them altogether.

### Ch 2: Immersion into the hacker mindset

- Media portrayls, fear of government retaliation, rock star myth, and imposter syndrome are among the reasons why people might not engage w/ the offensive security community, but you belong and the security community is awesome.

- Finding community can happen a number of different ways including local security conferences, BSides, CTFs, DEFCON, local DEFCON groups, 2600, online security resources, etc...

### Ch 3: Offensive Security Engagements, Trainings, and Gathering Intel

- For most security engagements usually there is a contract that lays out the scope, timeframe, and any additional considerations.  For an engagement there are usually 6 stages: targeting, inital access, persistence, expansion, exfiltration, and detection.
- Targeting: A continuous process of selecting the target network/determining specific attack strategies/tactics.  This includes recon, gather passwords/usernames, being oportunistic and taking advantage of opportunities that present themselves.
- Initial access: Obtaining a foothold in the environment to run commands on a target system.  Often you will see phishing/social engineering engage here to bypass defenses and then move to persistence/lateral movement.
- Persistance: Moving from initial foothold into being able to secur future/recurring access via any means necessary such as regedit, updating boot process, backdoors, etc...
- Expansion: Moving beyond initial access and ability to stay connected for greater persistance and opportunities and involves traversing multiple networks/network points and can be very time consuming
- Exfiltration: Pulling data from the network in a way that is reasonably stealthy while still pulling down large volumes of data
- Detection: The final setp of an offensive security engagement, when the target uncovers what the offsec professionals have been doing...which might take a while :)

- Offsec trainings: BSides, DEFCON, other conferences, OffSec, TrustedSec, Black Hills Infosec, SANS, HTB, THM, CTFs, etc...
- Gathering Intel can be done from visiting places where offensive security practitioners obtain the intel they use for engagements this can often be social media or specific platforms.  This can include Google's Project Zero research blog, Rapid7's Attacker KB, various discord/slack channels, Twitter/Bluesky, LinkedIn, Pastebin, Github, and other forums, HaveiBeenPwned, etc...

### Ch 4: Understanding the offensive toolset

- While there are many tools, some of them custom, having a basic understanding of the following tools should provide a useful foundation.
- The tools presented may fall into one or more MITRE ATT&CK categories of recon, resource development, intial access, execution, persistance, priv esc, defense evasion, cred access, discovery, lateral movement, collection, command and control, exfiltration, and impact
- Nmap(command line)/Zenmap(GUI): open surce scanning tools used for network discovery/auditing, determing what services are open/available on a host, OS fingerprinting, etc... Usually used for recon but can be mitigated with firewall and ADS rules to detect/block cans being used, and block unecessary ports and traffic.
- Burp Suite/Zed Attack Proxy (ZAP): Used for appsec to map and analyze the attack surface of a web application and test/exploit potential vulns.  To prevent this use secure coding practices and follow the OWASP Top 10.
- SQLMap: Open source testing tool used to test DBs often for SQL injections, DB fingerprinting, and command execution.  To mitigate these, have accounts use principle of least privilige, use prepared statements, and query sanitization.
- Wireshark: Open source protocol analyzer that can be used offensively for enumeration/mapping.  The best mitigation is network segmentation and moving away from insecure protocols
- Metasploit: Tool to test/utilizae vulns against a remote machine via payloads, exploits, brute force, etc... Since this fits into several categories such as recon, persitance, lateral movement, there are several mitigations including patching, fully configured host based firewalls, principle of least priv, etc...
- Shodan: Specalized search engine that allows users to query for internet connected devices and most commonly used for recon.  To mitigate this block scanners via firewall rules and you can use shodan to verify that no devices from your networks are on there.
- Social Engineer TOolkit: An open source toolkit used to test an org by social engineerint its employees can be used for initial access, credential gathering, execution, etc...The best mitigations include technical controls such as URL/file download inspection, EDR, SPF/DMARC/DKIM, and security awareness training.
- Mimikatz: Open source tool used for obtaining plaintext windows account logins, and often bundled w/ other frameworks and tools.  Usually used for credential access to mitigate this you can disable WDigest caching, enabling Local Security Authority, and disabling storage of plaintext passwords.
- Responder: Open source tool to obtain credentials/remote access on Windows systems via using insecure protocols and can often act as a host for an on path attack.  Mitigation includes hardcoding DNS prferences, host based firewalls to disable broadcast traffic(when possible), and enabling SMB signing, or you can monitor traffic out of specific ports such as UDP 5355 and 137.
- Cobalt strike: Tool to simulate adversary activities and often used for command/control applications and used in conjunction w/ backdoor BEACON payloads. To mitigate there are a number of options though it can be difficult system logging, baseline analysis, in memory scanning, and command line monitoring are useful, but every environment is different with different indicators
- Impacket: Collection of tools that provide low-level programmatic access for working w/ network protocols within custom scripts/command line.  The best set of defenses against this (depending on environment) is to limit inbound communication for RPC, SMB, and WinRM connections
- Mitm6: Tool to spoof replies to IPv6 DHCP requests/DNS quries for Windows.  THe best mitigation is to disable IPv6 on endpoints that don't use it or monitor for rogue DHCPv6 servers
- CrackMapExec: Open source tool to test large AD environments via remote instructions and active recon/lateral movement.  Mitigation includes limiting inbound access on endpoints and limiting outgoing connections when possible.
- Bloodhound/Sharphound: Open source tool that analyzes AD domain security in terms of rights/relationships and maps them via graph theory.  Limit accounts w/ admin permissions and use EDR and egress filtering where possible.

### Ch 5: Implementing Defense while thinking like a hacker

- OSINT/Opsec: Used to prevent sensitive information in the wrong hands OPSEC/Operational Security is best practice to prevent information from being inadvertnly used against the org.  OSINT on the other hand is open source intelligence is any data that is available from public sources that can give someone an advantage.
- Social Engineering: This can be things like Phishing, Smishing, Vishing, but is usally any attack that influences a target getting them to provide information/access.  Usually used for initial access
- Active defenders should be aware of OSINT that is available about their org and should regularly engage in attack surface monitoring/ASM, and should employ account takeover/ATO prevention methods.
- Attack Surface monitoring is used to discover, evaluate, proiritze, adn remediate an orgs external attack vectors over a consistent period of time> Attack surfaces anything that is an entry/exit point of the network that could be used to gain unauthorize access.
- To prevent attack takeover, engage in educational awareness, 2FA, account monitoring (e.g. haveIBeenPwned), etc...
- More threat modeling: Frame the engagement by better understanding what the business does and its critical resources/revenue streams to help prioritize what to protect and drive the scope of the engagement and potential motivations (money, information/intel gathering, etc...).
- One way in vs. the right way in.  While an attacker might only need one way in, they usually need to be efficent and to be most efficent means understanding their objectives and environment and accesses to be most effective
- After framing, understanding motivations, and understanding key objectives/resources offensive security professionals begin to build an attack chain to evade any mitigations/protections this means looking for the right recon points, checking for controls on those points, seeing if there is any EDR or sandbox tech in use which could hinder their movements in a system.
- LOLBins/Living off the Land Binaries, tools that usually help admins/defenders can also be used by attackers to try and fly under the radar.  These include binaries such as:
    - Rundll32 to execute DLLs
    - Regsvr32 to register/unregister DLLs or run malicious scripts
    - MSBuild to complie/execute code
    - Cscript to execute scripts
    - Csc to compile and run C# code
 
- To determine if usage is legitimate dfenders can look at filepaths, command line activity, process monitoring, etc...

More threat hunting as an active defender:

- Start with a question, it can be as simple as: "How would I get in from the outside"
- Hunting should take a layered approach such as log analysis, anaomly detection, memory dumps, searching for potential lateral movement


### Ch 6: Becoming an advanced active defender

- An advanced attack emulation means pperforming tests/adversarial access in a way that an attacker would trying to get access to the resources they want most efficently
- Advanced defenders can use deceptive technology such as honey tokens/canary tokens, decoy accounts, fake/honey token email addresses, fake DB data, placing fake AWS keys in honey files
- Other forms of deception include false web server headers/user agent strings to prvent attackers from getting useful information, Fake DNS info, etc...
- When working with offensive security teams for any kind of testing, emulation, etc... try and have an outcome in mind and keep in mind good communication.  Objectives can include vuln identification, vuln exploitation as proof of concept/to determine impact, testing detection response/analysis.
- When working w/ offsec teams make sure to have proper scope of the users/apps/environment you want to test along with proper rules of engagement.  Scope is one of those things that can be too broad or to narrow so as to be useless, but there can be a number of factors/considerations including SLAs, vendors, fines, budget, cloud vs on prom, etc...
- When working w/ offsec teams you can test a number of things from verifying existing defenses, to seeing if offsec teams can access critically importantdata/revenue streams.
- When selecting an external or vendor offsec team there can be a number of thingsto consider from cost, to reputation, complance, experience/expertise, controls/data security/NDAs, and how results will be communicated.
- 
