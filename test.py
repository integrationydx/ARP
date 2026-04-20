#!/usr/bin/env python3
"""
Test Scenarios for ARP Handling in SDN Networks (POX Version)
=============================================================
Scenarios:
  1. ARP Discovery & Basic Connectivity
  2. ARP Proxy Reply (no flood for known hosts)
  3. Performance Measurement (ping latency + iperf throughput)
  4. Flow Table Verification

Run AFTER starting POX controller and topology:
    sudo python3 test_scenarios.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


def separator(title=""):
    info("\n" + "=" * 60 + "\n")
    if title:
        info(f"  {title}\n")
        info("=" * 60 + "\n")


def run_cmd(host, cmd):
    info(f"  [{host.name}] $ {cmd}\n")
    result = host.cmd(cmd)
    info(f"  {result.strip()}\n")
    return result


def check_flow_table(switch):
    # POX / OpenFlow 1.0 uses dump-flows without -O flag
    info(f"\n  [Flow Table: {switch.name}]\n")
    result = switch.cmd('ovs-ofctl dump-flows s1')
    for line in result.strip().split('\n'):
        info(f"  {line}\n")
    return result


def count_flows(switch):
    result = switch.cmd('ovs-ofctl dump-flows s1')
    flows = [l for l in result.strip().split('\n')
             if 'priority=0' not in l and 'OFPST_FLOW' not in l and l.strip()]
    return len(flows)


def build_net():
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    c0 = net.addController('c0', controller=RemoteController,
                            ip='127.0.0.1', port=6633)
    # OpenFlow 1.0 for POX
    s1 = net.addSwitch('s1', protocols='OpenFlow10')

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
#  Scenario 1                                                         #
# ------------------------------------------------------------------ #
def scenario1_arp_discovery(net):
    separator("SCENARIO 1: ARP Discovery & Basic Connectivity")

    h1, h2, h3, h4 = [net.get(h) for h in ['h1','h2','h3','h4']]
    s1 = net.get('s1')

    info("  Clearing ARP caches...\n")
    for h in [h1, h2, h3, h4]:
        h.cmd('ip -s -s neigh flush all 2>/dev/null; true')

    info("\n  [Step 1] First ping h1 -> h2 (triggers ARP discovery)\n")
    result1 = run_cmd(h1, 'ping -c 4 10.0.0.2')

    info("\n  [Step 2] ARP cache on h1\n")
    run_cmd(h1, 'arp -n')

    info("\n  [Step 3] Second ping h1 -> h2 (uses installed flow rule)\n")
    result2 = run_cmd(h1, 'ping -c 4 10.0.0.2')

    info("\n  [Step 4] Cross pings\n")
    run_cmd(h3, 'ping -c 2 10.0.0.4')
    run_cmd(h4, 'ping -c 2 10.0.0.1')

    info("\n  [Flow Table]\n")
    check_flow_table(s1)

    passed = '0% packet loss' in result1 and '0% packet loss' in result2
    info(f"\n  SCENARIO 1 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Scenario 2                                                         #
# ------------------------------------------------------------------ #
def scenario2_arp_proxy(net):
    separator("SCENARIO 2: ARP Proxy – Controller Generates Reply")

    h1, h2, h3, h4 = [net.get(h) for h in ['h1','h2','h3','h4']]

    info("  [Warm-up] All-pairs ping\n")
    for src, dst in [('h1','10.0.0.2'),('h1','10.0.0.3'),('h1','10.0.0.4'),
                     ('h2','10.0.0.3'),('h3','10.0.0.4')]:
        net.get(src).cmd(f'ping -c 1 {dst} 2>/dev/null')
    time.sleep(1)

    info("\n  [Step 1] Clear h1 ARP cache only\n")
    h1.cmd('ip -s -s neigh flush all 2>/dev/null; true')
    run_cmd(h1, 'arp -n')

    info("\n  [Step 2] arping from h1 to h3 (controller should proxy reply)\n")
    run_cmd(h1, 'arping -c 3 -I h1-eth0 10.0.0.3')

    info("\n  [Step 3] Check h1 ARP cache\n")
    run_cmd(h1, 'arp -n | grep 10.0.0.3')

    info("\n  [Step 4] Ping h1 -> h3\n")
    result = run_cmd(h1, 'ping -c 3 10.0.0.3')

    passed = '0% packet loss' in result
    info(f"\n  SCENARIO 2 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Scenario 3                                                         #
# ------------------------------------------------------------------ #
def scenario3_performance(net):
    separator("SCENARIO 3: Performance – Latency & Throughput")

    h1, h2 = net.get('h1'), net.get('h2')

    info("  [Step 1] Latency: 10-packet ping\n")
    run_cmd(h1, 'ping -c 10 10.0.0.2')

    info("\n  [Step 2] TCP Throughput (iperf3)\n")
    h2.cmd('iperf3 -s -D -1')
    time.sleep(1)
    result_tcp = run_cmd(h1, 'iperf3 -c 10.0.0.2 -t 5')

    time.sleep(2)
    info("\n  [Step 3] UDP Throughput + Jitter\n")
    h2.cmd('iperf3 -s -D -1')
    time.sleep(1)
    run_cmd(h1, 'iperf3 -c 10.0.0.2 -u -b 10M -t 5')

    info("\n  [Step 4] h3 -> h4 latency\n")
    run_cmd(net.get('h3'), 'ping -c 5 10.0.0.4')

    passed = 'sender' in result_tcp or 'Mbits/sec' in result_tcp
    info(f"\n  SCENARIO 3 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Scenario 4                                                         #
# ------------------------------------------------------------------ #
def scenario4_flow_table(net):
    separator("SCENARIO 4: Flow Table Verification")

    s1 = net.get('s1')
    hosts = [net.get(h) for h in ['h1','h2','h3','h4']]
    ips   = ['10.0.0.1','10.0.0.2','10.0.0.3','10.0.0.4']

    info("  [Step 1] Flow count BEFORE traffic\n")
    before = count_flows(s1)
    info(f"  Flows: {before}\n")

    info("\n  [Step 2] All-pairs traffic\n")
    for i in range(4):
        for j in range(4):
            if i != j:
                hosts[i].cmd(f'ping -c 1 {ips[j]} 2>/dev/null')
    time.sleep(2)

    info("\n  [Step 3] Flow count AFTER traffic\n")
    after = count_flows(s1)
    info(f"  Flows: {after}  (was {before})\n")

    info("\n  [Step 4] Full flow table\n")
    check_flow_table(s1)

    info("\n  [Step 5] Port statistics\n")
    info(s1.cmd('ovs-ofctl dump-ports s1') + "\n")

    passed = after > before
    info(f"\n  SCENARIO 4 RESULT: {'PASS ✓' if passed else 'FAIL ✗'}\n")
    return passed


# ------------------------------------------------------------------ #
#  Main                                                               #
# ------------------------------------------------------------------ #
def run_all():
    setLogLevel('info')
    separator("SDN ARP HANDLER (POX) – AUTOMATED TEST SUITE")

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
            info(f"  {name:<25} {'PASS ✓' if passed else 'FAIL ✗'}\n")
        info(f"\n  {sum(results.values())}/{len(results)} scenarios passed\n")
        net.stop()


if __name__ == '__main__':
    run_all()