# ARP Handling in SDN Networks

## Problem Statement

In traditional networks, ARP (Address Resolution Protocol) operates by broadcasting requests across the entire network segment. Every host receives every ARP request, even when most are irrelevant to them. This creates:

- **ARP flooding**: Broadcast storms that waste bandwidth.
- **Scalability issues**: Flood traffic grows linearly with the number of hosts.
- **Security vulnerabilities**: ARP spoofing and poisoning attacks.

In an SDN (Software-Defined Networking) environment, the centralized controller can intercept ARP packets, maintain a global ARP table, and generate proxy replies — completely eliminating the need to flood the network.

### Project Objective

Implement an SDN-based ARP handler using **Mininet** (topology) and **Ryu** (OpenFlow 1.3 controller) that:

| Expectation | Implementation |
|---|---|
| Intercept ARP packets | `packet_in` handler captures all ARP frames |
| Generate ARP responses | Controller builds and sends proxy ARP replies |
| Enable host discovery | Controller learns IP↔MAC from every ARP packet |
| Validate communication | Ping, iperf, flow-table tests confirm correct behavior |

---

## Architecture

```
┌─────────────────────────────────────┐
│         Ryu Controller              │
│  ┌─────────────────────────────┐    │
│  │  ARP Table (IP→MAC, port)   │    │
│  │  10.0.0.1 → 00:...:01  p1   │    │
│  │  10.0.0.2 → 00:...:02  p2   │    │
│  └─────────────────────────────┘    │
│  packet_in → ARP proxy reply        │
│           → install flow rules      │
└──────────────┬──────────────────────┘
               │ OpenFlow 1.3 (port 6633)
        ┌──────▼──────┐
        │    OVS S1   │
        └──┬──┬──┬──┬─┘
           │  │  │  │
          h1 h2 h3 h4
     10.0.0.1  .2  .3  .4
```

### Flow Rule Priority Scheme

| Priority | Match | Action | Purpose |
|---|---|---|---|
| 0 | (all) | → controller | Table-miss, sends unknown packets to controller |
| 10 | eth_dst, eth_src, in_port | → output_port | L2 unicast forwarding |
| 20 | ip_src, ip_dst | → output_port | Proactive IP forwarding after ARP resolution |

---

## Repository Structure

```
arp_sdn_project/
├── controller/
│   └── arp_handler.py       # Ryu OpenFlow 1.3 controller
├── topology/
│   └── topology.py          # Mininet 4-host single-switch topology
├── tests/
│   └── test_scenarios.py    # Automated test suite (4 scenarios)
└── README.md
```

---

## Setup & Execution

### Prerequisites

```bash
# Ubuntu 20.04 / 22.04
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip wireshark tshark iperf3

pip3 install ryu
```

### Step 1 — Start the Ryu Controller

Open **Terminal 1**:

```bash
cd arp_sdn_project/
ryu-manager --verbose controller/arp_handler.py
```

You should see:
```
ARP Handler SDN Controller Started
loading app arp_handler.py
instantiating app arp_handler.py
```

### Step 2 — Start the Mininet Topology

Open **Terminal 2**:

```bash
sudo python3 topology/topology.py
```

You should see the Mininet CLI prompt `mininet>`.

### Step 3 — Run the Test Suite (Optional Automated Tests)

Open **Terminal 3** (instead of step 2):

```bash
sudo python3 tests/test_scenarios.py
```

Or run individual scenarios from the Mininet CLI:

```
mininet> h1 ping h2 -c 4
mininet> h1 ping h3 -c 4
mininet> iperf h1 h2
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

## Test Scenarios

### Scenario 1 — ARP Discovery & Basic Connectivity

**Goal**: Verify the controller intercepts first ARP, floods once, and learns host MACs.

**Steps**:
1. Clear ARP caches on all hosts.
2. `h1 ping h2` — first ping triggers ARP REQUEST.
3. Controller intercepts ARP, h2 unknown → controller floods.
4. h2 replies → controller learns h2's MAC and installs flow rule.
5. Second ping uses installed flow rule (no controller packet_in).

**Expected Output**:
```
PING 10.0.0.2: 4 packets transmitted, 4 received, 0% packet loss
[ARP  ] REQUEST  who-has 10.0.0.2   tell 10.0.0.1 (00:00:00:00:00:01)
[ARP  ] FLOOD    10.0.0.2 not in table yet
[ARP  ] Learned  10.0.0.2 -> 00:00:00:00:00:02
[FLOW ] Installed flow 10.0.0.1 -> 10.0.0.2
```

---

### Scenario 2 — ARP Proxy (No Flood on Known Hosts)

**Goal**: After warm-up, controller answers ARP requests itself without flooding.

**Steps**:
1. All-pairs ping to populate the controller's ARP table.
2. Clear only h1's ARP cache.
3. `h1` sends ARP request for h3 → controller has h3 in table → replies directly.
4. h3 never sees a broadcast ARP request.

**Expected Output**:
```
[ARP  ] REQUEST  who-has 10.0.0.3   tell 10.0.0.1
[ARP  ] REPLY    10.0.0.3 is-at 00:00:00:00:00:03  (controller proxy)
```

---

### Scenario 3 — Performance Measurement (iperf)

**Goal**: Measure latency and throughput to validate functional network performance.

**Expected Output** (approximate):
```
Latency (ping h1→h2, 10 packets):
  rtt min/avg/max = 10.1/10.8/12.4 ms

TCP Throughput (iperf3, 5s):
  Bitrate: ~9.5 Mbits/sec  (link limit: 10 Mbps)

UDP Throughput + Jitter (iperf3 -u):
  Transfer: ~5.9 MBytes   Jitter: ~0.3 ms
```

---

### Scenario 4 — Flow Table Verification

**Goal**: Confirm that flow rules are correctly installed after host communication.

**Expected Output**:
```
Non-default flows BEFORE traffic: 0
Non-default flows AFTER  traffic: 12

cookie=0x0, duration=2s, table=0, priority=20,
  ip,nw_src=10.0.0.1,nw_dst=10.0.0.2
  actions=output:2

cookie=0x0, duration=2s, table=0, priority=20,
  ip,nw_src=10.0.0.2,nw_dst=10.0.0.1
  actions=output:1
```

---

## Proof of Execution

### Wireshark / tshark ARP Capture

To capture ARP traffic during testing:

```bash
# On a separate terminal while tests run
sudo tshark -i s1-eth1 -f "arp" -w arp_capture.pcap

# Display summary
sudo tshark -r arp_capture.pcap
```

Expected to see ARP requests from h1 and proxy replies sourced from the controller.

### Flow Table Screenshot

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

### Ping Results

```bash
# From Mininet CLI
mininet> pingall
```

Expected:
```
h1 -> h2 h3 h4
h2 -> h1 h3 h4
h3 -> h1 h2 h4
h4 -> h1 h2 h3
*** Results: 0% dropped (12/12 received)
```

---

## SDN Concepts Demonstrated

| Concept | How It Is Demonstrated |
|---|---|
| Controller–switch interaction | `switch_features_handler` installs table-miss rule on connect |
| packet_in events | All ARP packets trigger `packet_in` to controller |
| Match–action rules | `OFPFlowMod` with IP match and port output actions |
| Flow rule priorities | 0 (table-miss) → 10 (L2) → 20 (IP after ARP) |
| Proactive rule installation | After ARP resolution, bidirectional IP flows installed |
| Host discovery | `arp_table` and `mac_to_port` dicts built from packet_in |
| ARP proxy | Controller replies to ARP requests for known hosts |

---

## References

1. OpenFlow 1.3 Specification – Open Networking Foundation  
   https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf

2. Ryu SDN Framework Documentation  
   https://ryu.readthedocs.io/en/latest/

3. Mininet Documentation  
   http://mininet.org/walkthrough/

4. RFC 826 – An Ethernet Address Resolution Protocol  
   https://datatracker.ietf.org/doc/html/rfc826

5. Open vSwitch Project  
   https://www.openvswitch.org/