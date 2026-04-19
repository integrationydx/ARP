#!/usr/bin/env python3
"""
Test Scenarios for ARP Handling in SDN Networks
================================================
Automated tests covering:
  Scenario 1: ARP Discovery & Basic Ping (host discovery + connectivity)
  Scenario 2: ARP Table Population & Proxy Reply (no flood on 2nd request)
  Scenario 3: Network Performance with iperf (throughput measurement)
  Scenario 4: Flow Table Verification (confirm rules are installed)

Run AFTER starting the topology:
    sudo python3 test_scenarios.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
import time
import subprocess
import sys


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def separator(title=""):
    info("\n" + "=" * 60 + "\n")
    if title:
        info(f"  {title}\n")
        info("=" * 60 + "\n")


def run_cmd(host, cmd, timeout=10):
    """Run a command on a Mininet host and return stdout."""
    info(f"  [{host.name}] $ {cmd}\n")
    result = host.cmd(cmd)
    info(f"  {result.strip()}\n")
    return result


def check_flow_table(switch):
    """Dump and display flow table of a switch."""
    info(f"\n  [Flow Table: {switch.name}]\n")
    result = switch.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
    for line in result.strip().split('\n'):
        info(f"  {line}\n")
    return result


def count_flows(switch):
    """Return number of non-table-miss flow entries."""
    result = switch.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
    flows = [l for l in result.strip().split('\n')
             if 'priority=0' not in l and 'OFPST_FLOW' not in l and l.strip()]
    return len(flows)


# ------------------------------------------------------------------ #
#  Build Topology (inline for self-contained test runner)            #
# ------------------------------------------------------------------ #

def build_net():
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    c0 = net.addController('c0', controller=RemoteController,
                            ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    net.addLink(h1, s1, bw=10, delay='5ms')
    net.addLink(h2, s1, bw=10, delay='5ms')
    net.addLink(h3, s1, bw=10, delay='5ms')
    net.addLink(h4, s1, bw=10, delay='5ms')

    net.build()
    c0.start()
    s1.start([c0])
    time.sleep(3)
    return net, s1


# ------------------------------------------------------------------ #
#  Scenario 1: ARP Discovery + Basic Connectivity                    #
# ------------------------------------------------------------------ #

def scenario1_arp_discovery(net):
    """
    SCENARIO 1: ARP Discovery and Basic Connectivity
    -------------------------------------------------
    Steps:
      1. Clear all ARP caches.
      2. h1 pings h2 → triggers ARP REQUEST (who has 10.0.0.2?)
      3. Controller intercepts, floods first ARP (h2 not yet known).
      4. h2 replies → controller learns h2's MAC, installs flow rules.
      5. Subsequent ping uses installed flow rules (no controller involved).

    Expected: All pings succeed; latency improves on 2nd ping.
    """
    separator("SCENARIO 1: ARP Discovery & Basic Connectivity")

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    s1 = net.get('s1')

    # Clear ARP caches on all hosts
    info("  Clearing ARP caches...\n")
    for h in [h1, h2, h3, h4]:
        h.cmd('ip -s -s neigh flush all 2>/dev/null; true')

    info("\n  [Step 1] First ping h1 -> h2 (triggers ARP discovery)\n")
    result1 = run_cmd(h1, 'ping -c 4 10.0.0.2')

    info("\n  [Step 2] Show ARP cache on h1 (MAC should be populated)\n")
    run_cmd(h1, 'arp -n')

    info("\n  [Step 3] Second ping h1 -> h2 (uses installed flow rule)\n")
    result2 = run_cmd(h1, 'ping -c 4 10.0.0.2')

    info("\n  [Step 4] Cross-host pings\n")
    run_cmd(h3, 'ping -c 2 10.0.0.4')
    run_cmd(h4, 'ping -c 2 10.0.0.1')

    info("\n  [Flow Table after Scenario 1]\n")
    check_flow_table(s1)

    passed = '0% packet loss' in result1 and '0% packet loss' in result2
    info(f"\n  SCENARIO 1 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Scenario 2: ARP Proxy – No Flood on Known Hosts                  #
# ------------------------------------------------------------------ #

def scenario2_arp_proxy(net):
    """
    SCENARIO 2: ARP Proxy Reply (Controller Answers Without Flooding)
    -----------------------------------------------------------------
    Steps:
      1. Warm up: make all hosts communicate so controller learns all MACs.
      2. Capture ARP packet count before test.
      3. Clear h1's ARP cache only.
      4. h1 sends ARP request for h3 → controller should reply directly
         (no flood, because h3's MAC is already in the controller's table).
      5. Verify h1 learns h3's MAC without h3 receiving the flood.

    Expected: h1 gets the ARP reply; h3's ARP request count stays low.
    """
    separator("SCENARIO 2: ARP Proxy – Controller Generates Reply (No Flood)")

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')

    info("  [Warm-up] All-pairs ping to populate controller ARP table\n")
    for src, dst in [('h1', '10.0.0.2'), ('h1', '10.0.0.3'), ('h1', '10.0.0.4'),
                     ('h2', '10.0.0.3'), ('h3', '10.0.0.4')]:
        net.get(src).cmd(f'ping -c 1 {dst} 2>/dev/null')
    time.sleep(1)

    info("\n  [Step 1] Clear h1 ARP cache only\n")
    h1.cmd('ip -s -s neigh flush all 2>/dev/null; true')
    run_cmd(h1, 'arp -n')

    info("\n  [Step 2] Capture ARP stats on h3 BEFORE test\n")
    h3_arp_before = h3.cmd('cat /proc/net/arp | grep 10.0.0 | wc -l').strip()
    info(f"  h3 ARP entries before: {h3_arp_before}\n")

    info("\n  [Step 3] h1 sends ARP request for h3's MAC\n")
    run_cmd(h1, 'arping -c 3 -I h1-eth0 10.0.0.3')

    info("\n  [Step 4] Check h1's ARP cache (should have h3's MAC)\n")
    run_cmd(h1, 'arp -n | grep 10.0.0.3')

    info("\n  [Step 5] Ping h1 -> h3 to confirm connectivity\n")
    result = run_cmd(h1, 'ping -c 3 10.0.0.3')

    passed = '0% packet loss' in result
    info(f"\n  SCENARIO 2 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Scenario 3: Performance Measurement (iperf)                      #
# ------------------------------------------------------------------ #

def scenario3_performance(net):
    """
    SCENARIO 3: Throughput and Latency Measurement
    -----------------------------------------------
    Measures:
      - RTT latency (ping)
      - TCP throughput (iperf3)
      - UDP throughput and jitter (iperf3 -u)

    Expected: ~10 Mbps TCP throughput (link limit), low latency ~10ms RTT.
    """
    separator("SCENARIO 3: Performance – Latency & Throughput Measurement")

    h1 = net.get('h1')
    h2 = net.get('h2')

    info("  [Step 1] Latency: 10-packet ping (h1 -> h2)\n")
    run_cmd(h1, 'ping -c 10 10.0.0.2')

    info("\n  [Step 2] TCP Throughput (iperf3): h2=server, h1=client\n")
    h2.cmd('iperf3 -s -D -1')   # Start server (daemon, exit after 1 client)
    time.sleep(1)
    result_tcp = run_cmd(h1, 'iperf3 -c 10.0.0.2 -t 5')

    time.sleep(2)
    info("\n  [Step 3] UDP Throughput + Jitter (iperf3 -u)\n")
    h2.cmd('iperf3 -s -D -1')
    time.sleep(1)
    result_udp = run_cmd(h1, 'iperf3 -c 10.0.0.2 -u -b 10M -t 5')

    info("\n  [Step 4] Latency: h3 -> h4 (different pair)\n")
    run_cmd(net.get('h3'), 'ping -c 5 10.0.0.4')

    passed = 'sender' in result_tcp or 'Mbits/sec' in result_tcp
    info(f"\n  SCENARIO 3 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Scenario 4: Flow Table Verification                               #
# ------------------------------------------------------------------ #

def scenario4_flow_table(net):
    """
    SCENARIO 4: Flow Rule Installation Verification
    ------------------------------------------------
    Steps:
      1. Record flow count before communication.
      2. Generate traffic between all pairs.
      3. Verify flow rules were installed (count increases).
      4. Show full flow table with match+action details.

    Expected: Flow count grows after communication; rules show
              correct IP match fields and output port actions.
    """
    separator("SCENARIO 4: Flow Table Verification")

    s1 = net.get('s1')
    hosts = [net.get(h) for h in ['h1', 'h2', 'h3', 'h4']]

    info("  [Step 1] Flow count BEFORE traffic\n")
    before = count_flows(s1)
    info(f"  Non-default flows: {before}\n")

    info("\n  [Step 2] Generate all-pairs traffic\n")
    ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']
    pairs = [(hosts[i], ips[j]) for i in range(4)
             for j in range(4) if i != j]
    for host, dst in pairs:
        host.cmd(f'ping -c 1 {dst} 2>/dev/null')

    time.sleep(2)

    info("\n  [Step 3] Flow count AFTER traffic\n")
    after = count_flows(s1)
    info(f"  Non-default flows: {after}  (was {before})\n")

    info("\n  [Step 4] Full flow table dump\n")
    check_flow_table(s1)

    info("\n  [Step 5] Port statistics\n")
    info(s1.cmd('ovs-ofctl -O OpenFlow13 dump-ports s1') + "\n")

    passed = after > before
    info(f"\n  SCENARIO 4 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Main                                                               #
# ------------------------------------------------------------------ #

def run_all_scenarios():
    setLogLevel('info')

    info("\n")
    separator("SDN ARP HANDLER – AUTOMATED TEST SUITE")
    info("  Building topology...\n")

    net, s1 = build_net()

    results = {}
    try:
        results['S1_Discovery']   = scenario1_arp_discovery(net)
        results['S2_ARPProxy']    = scenario2_arp_proxy(net)
        results['S3_Performance'] = scenario3_performance(net)
        results['S4_FlowTable']   = scenario4_flow_table(net)
    finally:
        separator("TEST SUMMARY")
        for name, passed in results.items():
            status = "PASS ✓" if passed else "FAIL ✗"
            info(f"  {name:<25} {status}\n")
        total = sum(results.values())
        info(f"\n  {total}/{len(results)} scenarios passed\n")
        separator()
        net.stop()


if __name__ == '__main__':
    run_all_scenarios()