# ICMP DOOR

>ICMP is mainly used to ping computers and appliances across networks. This blog post explains why leaving ICMP unfiltered by a corporate and host-based firewall can form a bigger risk than you might initially think. Our ICMP reverse shell called icmpdoor can tunnel out a covert channel to control a compromised machine and exfiltrate data as an insider threat. Your Anti-Virus (AV) will most likely not detect and block icmpdoor either. This ICMP reverse shell works both on Linux and Windows 10.

>Reverse Shell
A reverse shell is a remote interactive shell for command execution initiated by the attacker to gain control over a compromised system. A reverse shell can also be abused by an insider threat to exfiltrate data over this covert channel. Corporate edge and core firewalls are typically configured to filter/deny/block TCP and UDP ports, or ever specific applications (layer 7 firewalling). Figure 1 shows how a well-configured firewall should block a traditional TCP or UDP reverse shell:

>ICMP Reverse Shell
ICMP stands for Internet Control Message Protocol. This protocol is often overlooked or depreciated when planning a firewall strategy. ICMP firewall filtering is rarely configured which allows malicious actors to evade firewalls. Abusing ICMP as a backdoor has been done by at least one APT (Advanced Persistent Threat) group in the past. Blocking the ICMP protocol completely would also imply hosts can no longer ping each other.

>ICMP deep dive
We first analyze a traditional ping. Typically a ping echo-request (type 8) is sent and expect a ping echo-reply (type 0) in return. Code block 1 shows us the RFC 792 ICMP echo-request and echo-reply packets header.
```
0                   1                     2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier (ID)     |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Optional Data                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
>Code block 1: ICMP echo-request and echo-reply packet headers

>The optional ICMP Data field is normally used for error messaging. However, instead of an error message, we will abuse this data field for our reverse shell payload (Raw) which can be a maximum of 576 bytes in size. We will fragment the payload if the total size exceeds this maximum of 576 bytes.

>We also modify and abuse the ICMP Identifier field to a static value of 13170 in order to filter out legitimate ICMP packets and match our ICMP reverse shell. In total we filter/manipulate the following header fields:

![image](https://user-images.githubusercontent.com/83721477/146623147-83af23a5-63c5-4b3a-935b-38cc0da04119.png)

## Mitigation
>Network administrators and security engineers should limit or deny ICMP traffic as much as possible. When this is not feasible due to protocol requirements or network planning, scope the accepted source and destination of ICMP packets. This blog post elaborates on how to configure this with iptables.

>Always take the scenario of lateral movement into account when you are planning network segmentation and configuring firewall settings. Lateral movement is a technique used by malicious actors after gaining initial access, to progressively move further into a domain, network or infrastructure. This means isolation of assets and firewall filters are only limited to the scope of a certain level.
Firewalls and gateways can also rate-limit ICMP packets. However, this control is mostly used to mitigate DDoS attacks and would imply ICMP-based data exfiltration is only slowed down.
DPI (Deep Packet Inspection) and IPS (Intrusion Prevention System) solutions such as Zeek and Snort or next-gen firewalls could possibly detect this ICMP tunnel due to the presence of the (plain-text) payload and static ID value. Network Anomaly Detection solutions could also flag this reverse shell. We have a modified version of icmpdoor we use for client engagements which does not get detected by these IDS/IPS systems.

#### Copyright Cryptsus
