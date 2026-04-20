# ARP Handling in SDN Networks

## Problem Statement

In traditional networks, ARP (Address Resolution Protocol) operates by broadcasting requests across the entire network segment. Every host receives every ARP request, even when most are irrelevant to them. This creates:

- **ARP flooding**: Broadcast storms that waste bandwidth
- **Scalability issues**: Flood traffic grows linearly with the number of hosts
- **Security vulnerabilities**: ARP spoofing and poisoning attacks

In an SDN (Software-Defined Networking) environment, the centralized controller can intercept ARP packets, maintain a global ARP table, and generate proxy replies — completely eliminating the need to flood the network.

### Project Objective

Implement an SDN-based ARP handler using **Mininet** (topology) and **POX** (OpenFlow 1.0 controller) that:

| Expectation | Implementation |
|---|---|
| Intercept ARP packets | `PacketIn` handler captures all ARP frames |
| Generate ARP responses | Controller builds and sends proxy ARP replies |
| Enable host discovery | Controller learns IP↔MAC from every ARP packet |
| Validate communication | Ping, iperf, and flow-table tests confirm correct behavior |

---

## Architecture

```
┌─────────────────────────────────────────┐
│           POX Controller                │
│  ┌───────────────────────────────────┐  │
│  │   ARP Table  (IP → MAC, port)     │  │
│  │   10.0.0.1 → 00:00:00:00:00:01 1  │  │
│  │   10.0.0.2 → 00:00:00:00:00:02 2  │  │
│  │   10.0.0.3 → 00:00:00:00:00:03 3  │  │
│  │   10.0.0.4 → 00:00:00:00:00:04 4  │  │
│  └───────────────────────────────────┘  │
│  PacketIn → ARP proxy reply             │
│           → install flow rules          │
└──────────────┬──────────────────────────┘
               │ OpenFlow 1.0 (port 6633)
        ┌──────▼──────┐
        │    OVS S1   │
        └──┬──┬──┬──┬─┘
           │  │  │  │
          h1 h2 h3 h4
     10.0.0.1  .2  .3  .4
```

### Flow Rule Priority Scheme

| Priority | Match Fields | Action | Purpose |
|---|---|---|---|
| 0 | (all) | → controller | Table-miss: sends unknown packets to controller |
| 10 | eth_dst, eth_src, in_port | → output port | L2 unicast forwarding |
| 20 | ip_src, ip_dst | → output port | Proactive IP forwarding after ARP resolution |

### ARP Handling Logic

```
Packet arrives at switch
        │
        ▼
  Is it ARP?
  ├── YES → PacketIn to controller
  │         │
  │         ├── Learn sender IP→MAC in ARP table
  │         │
  │         ├── ARP REQUEST?
  │         │     ├── dst_ip in ARP table? → Proxy Reply (no flood)
  │         │     └── dst_ip unknown?      → Flood once
  │         │
  │         └── ARP REPLY?
  │               ├── Update ARP table
  │               ├── Forward reply to requester
  │               └── Install bidirectional flow rules
  │
  └── NO  → IPv4: L2 forwarding (install flow if port known)
```

---

## Repository Structure

```
arp_sdn_project/
├── controller/
│   └── arp_handler.py        # POX OpenFlow 1.0 controller
├── topology/
│   └── topology.py           # Mininet 4-host single-switch topology
├── tests/
│   └── test_scenarios.py     # Automated test suite (4 scenarios)
└── README.md
```

---

## Setup & Installation

### Prerequisites

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Mininet and Open vSwitch
sudo apt install -y mininet openvswitch-switch iperf3 tshark wireshark

# Install POX
cd ~
git clone https://github.com/noxrepo/pox
```

### Place the Controller File

```bash
cp controller/arp_handler.py ~/pox/pox/misc/arp_handler.py
```

---

## Running the Project

### Step 1 — Start the POX Controller (Terminal 1)

```bash
cd ~/pox
python3 pox.py log.level --DEBUG misc.arp_handler
```

Expected output:
```
POX 0.x.x / ...
=======================================================
  ARP Handler SDN Controller (POX) Started
=======================================================
INFO:openflow.of_01:[...] connected
INFO:misc.arp_handler:New switch connected: 00-00-00-00-00-01
```

### Step 2 — Start the Mininet Topology (Terminal 2)

```bash
sudo python3 topology/topology.py
```

Expected output:
```
*** Creating controller
*** Creating switch
*** Creating hosts
*** Creating links (10 Mbps, 5ms delay)
*** Starting network
========================================================
Topology Ready:
  h1: 10.0.0.1  MAC: 00:00:00:00:00:01
  h2: 10.0.0.2  MAC: 00:00:00:00:00:02
  h3: 10.0.0.3  MAC: 00:00:00:00:00:03
  h4: 10.0.0.4  MAC: 00:00:00:00:00:04
========================================================
mininet>
```

### Step 3 — Run Automated Tests (Terminal 2, alternative to above)

```bash
sudo python3 tests/test_scenarios.py
```

### Step 4 — Quick Manual Checks from Mininet CLI

```bash
# Basic connectivity
mininet> pingall

# Specific ping
mininet> h1 ping h2 -c 4

# iperf throughput test
mininet> iperf h1 h2

# Dump flow table
mininet> sh ovs-ofctl dump-flows s1

# Check ARP cache on h1
mininet> h1 arp -n
```

---

## Test Scenarios

### Scenario 1 — ARP Discovery & Basic Connectivity

**Goal**: Verify the controller intercepts the first ARP request, floods once (destination unknown), learns the MAC from the reply, and installs a flow rule so subsequent traffic bypasses the controller.

**Steps**:
1. Clear ARP caches on all hosts
2. `h1 ping h2` — triggers ARP REQUEST (who has 10.0.0.2?)
3. Controller floods (h2 not yet known); h2 replies
4. Controller learns h2's MAC, installs flow rules
5. Second ping uses installed flow rule (no PacketIn)

**Expected Controller Log**:
```
[ARP  ] REQUEST  who-has 10.0.0.2   tell 10.0.0.1 (00:00:00:00:00:01)
[ARP  ] FLOOD    10.0.0.2 not in table yet
[ARP  ] Learned  10.0.0.2 -> 00:00:00:00:00:02  (port 2)
[FLOW ] Installed flow 10.0.0.1 <-> 10.0.0.2
```

**Expected Ping Output**:
```
PING 10.0.0.2 (10.0.0.2): 4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max = 10.2/11.1/12.3 ms
```

---

### Scenario 2 — ARP Proxy Reply (No Flooding for Known Hosts)

**Goal**: After the controller's ARP table is populated, it must answer ARP requests directly without flooding the network.

**Steps**:
1. All-pairs ping to warm up — controller learns all 4 MACs
2. Clear only h1's ARP cache
3. h1 sends ARP request for h3 — controller has h3 in its table
4. Controller sends proxy reply directly to h1
5. h3 and h4 receive zero ARP broadcast traffic

**Expected Controller Log**:
```
[ARP  ] REQUEST  who-has 10.0.0.3   tell 10.0.0.1
[ARP  ] PROXY REPLY  10.0.0.3 is-at 00:00:00:00:00:03  (controller)
```

---

### Scenario 3 — Performance Measurement

**Goal**: Measure latency and throughput to validate network performance under the SDN ARP handler.

**Expected Results** (approximate):

```
Latency (ping h1 → h2, 10 packets):
  rtt min/avg/max/mdev = 10.1/10.9/12.5/0.6 ms

TCP Throughput (iperf3, 5 seconds):
  Bitrate: ~9.4 Mbits/sec  (link limit: 10 Mbps)

UDP Throughput + Jitter (iperf3 -u):
  Transfer: ~5.9 MBytes   Jitter: ~0.3 ms   Lost: 0/0 (0%)
```

---

### Scenario 4 — Flow Table Verification

**Goal**: Confirm that flow rules are installed correctly after host communication, with proper match fields and output actions.

**Expected Flow Table** (after all-pairs traffic):
```
cookie=0x0, priority=20, ip, nw_src=10.0.0.1, nw_dst=10.0.0.2
    actions=output:2

cookie=0x0, priority=20, ip, nw_src=10.0.0.2, nw_dst=10.0.0.1
    actions=output:1

cookie=0x0, priority=0
    actions=CONTROLLER:65535
```

Non-default flow count should increase from 0 → 12+ after all-pairs communication.

---

## Proof of Execution

### Wireshark / tshark ARP Capture

```bash
# Capture ARP on switch port while running tests
sudo tshark -i s1-eth1 -f "arp" -w arp_capture.pcap

# Display capture summary
sudo tshark -r arp_capture.pcap
```

You should see ARP requests from h1 and ARP replies originating from the controller (source MAC = destination host's MAC, sent from controller port).

### Full pingall

```bash
mininet> pingall
```

Expected:
```
*** Ping: testing ping reachability
h1 -> h2 h3 h4
h2 -> h1 h3 h4
h3 -> h1 h2 h4
h4 -> h1 h2 h3
*** Results: 0% dropped (12/12 received)
```

### Flow Table Dump

```bash
sudo ovs-ofctl dump-flows s1
```

### iperf Results

```bash
# From Mininet CLI
mininet> iperf h1 h2
```

---

## SDN Concepts Demonstrated

| Concept | How It Is Demonstrated |
|---|---|
| Controller–switch interaction | `_handle_ConnectionUp` installs table-miss rule on switch connect |
| PacketIn events | All ARP packets trigger `PacketIn` to controller |
| Match–action rules | `ofp_flow_mod` with IP src/dst match and port output action |
| Flow rule priorities | 0 (table-miss) → 10 (L2) → 20 (IP after ARP resolution) |
| Proactive rule installation | Bidirectional IP flows installed after every ARP resolution |
| Host discovery | `arp_table` and `mac_to_port` dicts built from every PacketIn |
| ARP proxy | Controller replies to ARP requests for known hosts — no flooding |

---

## Troubleshooting

**POX not starting / import errors**
```bash
# Make sure you are NOT in a virtualenv
deactivate
cd ~/pox
python3 pox.py log.level --DEBUG misc.arp_handler
```

**Switch not connecting to controller**
```bash
# Verify OVS is running
sudo service openvswitch-switch start

# Check controller is listening
sudo netstat -tlnp | grep 6633
```

**Mininet leftover state**
```bash
sudo mn -c
```

**arping not found**
```bash
sudo apt install iputils-arping
```

---

## References

1. OpenFlow 1.0 Specification – Open Networking Foundation
   https://opennetworking.org/wp-content/uploads/2013/04/openflow-spec-v1.0.0.pdf

2. POX SDN Controller Documentation
   https://noxrepo.github.io/pox-doc/html/

3. POX GitHub Repository
   https://github.com/noxrepo/pox

4. Mininet Documentation
   http://mininet.org/walkthrough/

5. RFC 826 – An Ethernet Address Resolution Protocol
   https://datatracker.ietf.org/doc/html/rfc826

6. Open vSwitch Project
   https://www.openvswitch.org/