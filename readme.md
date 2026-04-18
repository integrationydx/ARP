# SDN Firewall using Mininet & Ryu Controller

> **Course Project** | SDN Mininet-based Simulation | Orange Problem Statement  
> **Controller:** Ryu (OpenFlow 1.3) | **Simulator:** Mininet | **Protocol:** OpenFlow 1.3

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Our Approach](#our-approach)
3. [Technologies Used](#technologies-used)
4. [Architecture & Topology](#architecture--topology)
5. [How It Works](#how-it-works)
6. [Firewall Rules](#firewall-rules)
7. [Setup & Installation](#setup--installation)
8. [Running the Project](#running-the-project)
9. [Test Scenarios](#test-scenarios)
10. [Expected Output](#expected-output)
11. [Performance Metrics](#performance-metrics)
12. [File Structure](#file-structure)
13. [References](#references)

---

## Project Overview

This project implements a **Software-Defined Networking (SDN) Firewall** using the **Ryu controller** and **Mininet network emulator**. It demonstrates how a centralized SDN controller can enforce fine-grained packet filtering policies across a virtual network — without requiring manual configuration on individual network devices.

The controller acts as both a **learning switch** and a **stateful firewall**. It inspects every packet entering the network, identifies its protocol type, applies firewall rules, and installs optimized OpenFlow flow rules on the switch so that future packets matching the same flow are handled directly in hardware — without reaching the controller again.

**Key capabilities demonstrated:**

- Controller–switch interaction via OpenFlow 1.3
- MAC learning and intelligent packet forwarding (Learning Switch)
- IP-level and ARP-level traffic filtering (Firewall)
- Proactive DROP rule installation with timeouts
- Full protocol-aware packet logging (ARP, ICMP, TCP, UDP, IPv4, IPv6)
- Flow table statistics and port-level packet counters
- Automated test validation with iperf throughput measurement

---

## Our Approach

### Problem Decomposition

We broke the problem into three layers that work together:

```
┌─────────────────────────────────────┐
│         Ryu SDN Controller          │
│  ┌─────────────┐  ┌──────────────┐  │
│  │  Learning   │  │  Firewall    │  │
│  │  Switch     │  │  Engine      │  │
│  │  (MAC table)│  │  (block list)│  │
│  └──────┬──────┘  └──────┬───────┘  │
│         └────────┬────────┘         │
│            ┌─────▼──────┐           │
│            │  Packet     │           │
│            │  Logger     │           │
│            └────────────┘           │
└──────────────────┬──────────────────┘
                   │ OpenFlow 1.3
              ┌────▼────┐
              │   OVS   │  (Open vSwitch — s1)
              └────┬────┘
        ┌──────────┼──────────┐
       h1         h2         h3    h4
```

### Design Decisions

**1. Reactive + Proactive hybrid approach**  
The first packet of a blocked flow hits the controller (reactive), which then installs a proactive OpenFlow DROP rule with `priority=10`. All subsequent packets in that flow are dropped directly at the switch — the controller is never involved again. This is more efficient and realistic than purely reactive filtering.

**2. ARP blocking alongside IP blocking**  
Blocking only IP traffic is insufficient. If ARP is allowed, the blocked host can still discover the MAC address of the other host. We block ARP packets between forbidden IP pairs to prevent host discovery entirely.

**3. Flow timeouts**  
All installed flow rules have `idle_timeout` and `hard_timeout` values. This prevents stale rules from accumulating in the flow table, which is important in dynamic networks.

**4. Priority hierarchy**

| Rule Type         | Priority | Timeout            |
|-------------------|----------|--------------------|
| Table-miss (flood to ctrl) | 0   | permanent          |
| Forwarding (learned paths) | 1   | idle=10s, hard=30s |
| Firewall DROP              | 10  | idle=30s, hard=60s |

DROP rules have higher priority than forwarding rules, so a blocked flow is always dropped even if the switch has a forwarding entry for the same destination.

---

## Technologies Used

| Technology | Version | Role |
|---|---|---|
| **Mininet** | 2.3+ | Network emulator — creates virtual hosts, switches, and links |
| **Ryu** | 4.34+ | SDN controller framework written in Python |
| **Open vSwitch (OVS)** | 2.13+ | Software switch that supports OpenFlow 1.3 |
| **OpenFlow** | 1.3 | Protocol for controller–switch communication |
| **Python** | 3.8+ | Programming language for controller and topology scripts |
| **iperf** | 2.x | Network throughput measurement tool |
| **ovs-ofctl** | — | CLI tool to inspect OVS flow tables and port statistics |
| **Wireshark / tcpdump** | — | Packet capture for proof of execution |

### Why Ryu?

Ryu is a Python-based SDN controller framework with first-class support for OpenFlow 1.0–1.5. It provides clean event-driven APIs (`@set_ev_cls`) for handling switch events, making controller logic easy to read and extend. Compared to POX, Ryu has better OpenFlow 1.3 support and is actively maintained.

### Why Mininet?

Mininet creates a realistic virtual network on a single Linux machine using Linux network namespaces. It supports real OpenFlow switches (OVS), allows actual TCP/IP traffic, and integrates with remote SDN controllers out of the box. This makes it ideal for prototyping and demonstrating SDN concepts without physical hardware.

### Why OpenFlow 1.3?

OpenFlow 1.3 introduced important improvements over 1.0: multiple flow tables, group tables, meters, and better match field support (including IPv4 src/dst matching without workarounds). We use `OFP_VERSION = 1.3` throughout.

---

## Architecture & Topology

```
                    ┌─────────────────────────┐
                    │   Ryu SDN Controller    │
                    │   (sdn_firewall.py)     │
                    │   127.0.0.1 : 6653      │
                    └──────────┬──────────────┘
                               │ OpenFlow 1.3 (TCP)
                    ┌──────────▼──────────────┐
                    │    OVS Switch  s1        │
                    │  (OpenFlow 1.3 enabled)  │
                    └──┬──────┬──────┬──────┬──┘
                       │      │      │      │
                 ┌─────┘  ┌───┘  ┌───┘  ┌──┘
                 │        │      │      │
            ┌────▼───┐ ┌──▼───┐ ┌▼────┐ ┌▼────┐
            │   h1   │ │  h2  │ │ h3  │ │ h4  │
            │10.0.0.1│ │10.0.0│ │10.0.│ │10.0.│
            │        │ │  .2  │ │0.3  │ │0.4  │
            └────────┘ └──────┘ └─────┘ └─────┘

         ✅ h1 ↔ h2   ALLOWED
         ✅ h1 ↔ h4   ALLOWED
         ✅ h2 ↔ h3   ALLOWED
         ✅ h2 ↔ h4   ALLOWED
         ✅ h3 ↔ h4   ALLOWED
         ❌ h1 ↔ h3   BLOCKED (bidirectional, IP + ARP)
```

**All links:** 100 Mbps bandwidth, 1 ms delay (configured via TCLink in Mininet).

---

## How It Works

### Step 1 — Switch Connects to Controller

When Mininet starts, OVS switch `s1` connects to the Ryu controller on TCP port 6653. The controller's `switch_features_handler` fires and installs a **table-miss flow rule** (priority 0, match-all) that sends any unmatched packet to the controller.

### Step 2 — Packet Arrives at Switch

When host h1 pings h2, h1's ARP request hits s1. Since no flow rule matches it yet, OVS sends it to the controller via a `PacketIn` message.

### Step 3 — Controller Receives PacketIn

The `packet_in_handler` runs:

1. **Packet Logger** — inspects the packet, identifies protocol (ARP/ICMP/TCP/UDP), and logs all fields.
2. **MAC Learning** — records `src_mac → in_port` in the `mac_to_port` table.
3. **Firewall Check (IP)** — if the packet is IPv4 and matches a blocked pair, installs a DROP rule and discards the packet.
4. **Firewall Check (ARP)** — if the packet is ARP and matches a blocked pair, discards it.
5. **Forwarding** — if the destination MAC is known, forwards to that port; otherwise floods.
6. **Flow Installation** — installs a forwarding rule so future packets on this flow bypass the controller.

### Step 4 — Flow Rules Accumulate in Switch

After a few packets, the switch has all the learned routes. Traffic flows at wire speed without involving the controller. Blocked flows are dropped in hardware by the high-priority DROP rules.

### Step 5 — Rule Expiry

Forwarding rules expire after 10 seconds of inactivity (idle_timeout) or 30 seconds absolute (hard_timeout). DROP rules last 30/60 seconds respectively. After expiry, the next packet triggers a new PacketIn — the controller re-evaluates and re-installs as needed.

---

## Firewall Rules

The blocked pairs are defined in the controller's `__init__` method:

```python
self.blocked_pairs = [
    ("10.0.0.1", "10.0.0.3"),  # h1 → h3  BLOCKED
    ("10.0.0.3", "10.0.0.1"),  # h3 → h1  BLOCKED (bidirectional)
]
```

To add more rules, simply add tuples to this list. For example, to also block h2 from reaching h4:

```python
self.blocked_pairs = [
    ("10.0.0.1", "10.0.0.3"),
    ("10.0.0.3", "10.0.0.1"),
    ("10.0.0.2", "10.0.0.4"),  # new rule
    ("10.0.0.4", "10.0.0.2"),  # new rule (reverse)
]
```

The DROP rule installed in the switch looks like:

```
priority=10, ip, nw_src=10.0.0.1, nw_dst=10.0.0.3, actions=drop
priority=10, ip, nw_src=10.0.0.3, nw_dst=10.0.0.1, actions=drop
```

---

## Setup & Installation

### Prerequisites

You need a **Linux environment** (Ubuntu 20.04 or 22.04 recommended). Options:

- **Option A:** Download the pre-built Mininet VM from [mininet.org](http://mininet.org/download/)
- **Option B:** Native Ubuntu install

### Install Dependencies

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Mininet
sudo apt-get install -y mininet

# Install Ryu
pip3 install ryu

# Install iperf and network tools
sudo apt-get install -y iperf wireshark net-tools

# Verify installations
mn --version
ryu-manager --version
ovs-vsctl --version
```

### Clone the Repository

```bash
git clone https://github.com/<your-username>/sdn-firewall-project.git
cd sdn-firewall-project
```

### File Structure

```
sdn-firewall-project/
├── sdn_firewall.py      # Ryu controller — firewall + learning switch + logger
├── topology.py          # Mininet topology + automated test scenarios
└── README.md            # This file
```

---

## Running the Project

> ⚠️ **Always start the controller BEFORE the topology.**

### Terminal 1 — Start Ryu Controller

```bash
cd sdn-firewall-project
ryu-manager sdn_firewall.py
```

Wait until you see:
```
SDN Firewall Controller Initialized
loading app sdn_firewall.py
```

### Terminal 2 — Start Mininet Topology

```bash
cd sdn-firewall-project
sudo python3 topology.py
```

The topology script will:
1. Build the network (4 hosts, 1 switch)
2. Wait 4 seconds for the controller to connect
3. Run all test scenarios automatically
4. Print PASS/FAIL for each test
5. Run iperf throughput test
6. Dump the flow table
7. Drop into the Mininet CLI for manual testing

### Manual Testing in the Mininet CLI

Once inside the `mininet>` prompt:

```bash
# Ping tests
mininet> h1 ping h2 -c 5          # allowed — should succeed
mininet> h1 ping h3 -c 5          # blocked  — should fail (100% loss)
mininet> h3 ping h1 -c 5          # blocked  — should fail (100% loss)
mininet> h2 ping h3 -c 5          # allowed — should succeed

# iperf throughput
mininet> iperf h1 h2               # allowed pair — should show ~Gbps

# Dump OpenFlow flow table
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1

# Dump port statistics
mininet> sh ovs-ofctl -O OpenFlow13 dump-ports s1

# Run all host combinations
mininet> pingall

# Open Wireshark on a specific interface
mininet> h1 wireshark &

# Exit
mininet> exit
```

---

## Test Scenarios

### Scenario 1 — ALLOWED Communication

| Source | Destination | Expected Result |
|--------|-------------|-----------------|
| h1 (10.0.0.1) | h2 (10.0.0.2) | ✅ Ping succeeds |
| h2 (10.0.0.2) | h3 (10.0.0.3) | ✅ Ping succeeds |
| h1 (10.0.0.1) | h4 (10.0.0.4) | ✅ Ping succeeds |
| h3 (10.0.0.3) | h4 (10.0.0.4) | ✅ Ping succeeds |

### Scenario 2 — BLOCKED Communication (Firewall)

| Source | Destination | Expected Result |
|--------|-------------|-----------------|
| h1 (10.0.0.1) | h3 (10.0.0.3) | ❌ 100% packet loss |
| h3 (10.0.0.3) | h1 (10.0.0.1) | ❌ 100% packet loss |

ARP is also blocked for these pairs, so h1 cannot even discover h3's MAC address.

---

## Expected Output

### Controller Terminal (Ryu)

```
============================================================
  SDN Firewall Controller Initialized
  Blocked pairs: [('10.0.0.1', '10.0.0.3'), ('10.0.0.3', '10.0.0.1')]
============================================================
[SWITCH] Connected: dpid=0000000000000001
[PKT] dpid=0000000000000001 port=1  | ETH src=00:00:00:00:00:01 dst=ff:ff:ff:ff:ff:ff | Proto=ARP    | op=REQUEST src_ip=10.0.0.1    dst_ip=10.0.0.2
[SWITCH] 🌊 FLOOD   src=00:00:00:00:00:01 dst=ff:ff:ff:ff:ff:ff (unknown dst)
[PKT] dpid=0000000000000001 port=1  | ETH src=00:00:00:00:00:01 dst=00:00:00:00:00:03 | Proto=ICMP   | src_ip=10.0.0.1    dst_ip=10.0.0.3    type=ECHO_REQ  code=0
[FIREWALL] ❌ BLOCKED IP  10.0.0.1 → 10.0.0.3 (dpid=0000000000000001, total_pkts_seen=3)
[FLOW] DROP rule installed: OFPMatch(...)
```

### Mininet Terminal

```
============================================================
  TEST SCENARIO 1: ALLOWED Communication
============================================================

>>> [TEST] h1 → h2 — h1 → 10.0.0.2  (expect: SUCCESS ✅)
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.87 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=0.91 ms
--- 10.0.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
  ✅ VALIDATION PASSED: communication allowed

============================================================
  TEST SCENARIO 2: BLOCKED Communication (Firewall)
============================================================

>>> [TEST] h1 → h3 [FIREWALL] — h1 → 10.0.0.3  (expect: BLOCKED ❌)
PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
--- 10.0.0.3 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss
  ✅ VALIDATION PASSED: traffic correctly blocked
```

### Flow Table Dump

```
OFPST_FLOW reply (OF1.3):
 cookie=0x0, duration=12s, table=0, n_packets=3, n_bytes=294,
   priority=10,ip,nw_src=10.0.0.1,nw_dst=10.0.0.3 actions=drop
 cookie=0x0, duration=12s, table=0, n_packets=3, n_bytes=294,
   priority=10,ip,nw_src=10.0.0.3,nw_dst=10.0.0.1 actions=drop
 cookie=0x0, duration=8s, table=0, n_packets=5, n_bytes=434,
   priority=1,in_port=1,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02 actions=output:2
 cookie=0x0, duration=0s, table=0, n_packets=0, n_bytes=0,
   priority=0 actions=CONTROLLER:65535
```

---

## Performance Metrics

| Metric | Tool | How to Measure |
|---|---|---|
| Latency (RTT) | `ping` | `h1 ping h2 -c 10` |
| Throughput | `iperf` | `iperf h1 h2` |
| Flow table entries | `ovs-ofctl` | `ovs-ofctl -O OpenFlow13 dump-flows s1` |
| Packet/byte counts | `ovs-ofctl` | `ovs-ofctl -O OpenFlow13 dump-ports s1` |
| Controller packet count | Ryu logger | Displayed in controller terminal |

**Typical results (Mininet VM):**

- Allowed pair ping latency: ~1–3 ms
- Blocked pair ping: 100% loss, 0 bytes received
- iperf throughput (h1 → h2): ~9–50 Gbps (virtual, no real NIC limit)

---

## References

1. Ryu SDN Framework Documentation — https://ryu.readthedocs.io/en/latest/
2. Mininet Documentation — http://mininet.org/walkthrough/
3. OpenFlow 1.3 Specification — https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf
4. Open vSwitch Documentation — https://docs.openvswitch.org/
5. B. Lantz, B. Heller, and N. McKeown, "A Network in a Laptop: Rapid Prototyping for Software-Defined Networks," in *Proc. 9th ACM SIGCOMM Workshop on Hot Topics in Networks (Hotnets)*, 2010.
6. N. McKeown et al., "OpenFlow: Enabling Innovation in Campus Networks," *ACM SIGCOMM Computer Communication Review*, vol. 38, no. 2, pp. 69–74, 2008.