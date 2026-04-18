#!/usr/bin/env python3
"""
SDN Firewall — Mininet Topology
================================
Topology:
    h1 (10.0.0.1) ──┐
    h2 (10.0.0.2) ──┤
                    s1 ── Ryu Controller (127.0.0.1:6653)
    h3 (10.0.0.3) ──┤
    h4 (10.0.0.4) ──┘

Firewall Rule : h1 <──X──> h3  (bidirectional, both IP and ARP blocked)
Allowed       : h1↔h2, h1↔h4, h2↔h3, h2↔h4, h3↔h4

Test Scenario 1 — ALLOWED communication (h1↔h2, h2↔h3, h1↔h4)
Test Scenario 2 — BLOCKED communication (h1→h3, h3→h1)

Usage:
    sudo python3 topology.py
"""

import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.link import TCLink


# =============================================================================
# TOPOLOGY DEFINITION
# =============================================================================
class FirewallTopo(Topo):
    """
    Single-switch star topology with 4 hosts.
    All links have 100 Mbps bandwidth and 1 ms delay for realistic metrics.
    """
    def build(self):
        # Add OpenFlow switch
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # Add hosts with static IPs and MACs for reproducibility
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Links: 100Mbps, 1ms delay
        link_opts = dict(bw=100, delay='1ms')
        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s1, **link_opts)
        self.addLink(h3, s1, **link_opts)
        self.addLink(h4, s1, **link_opts)


# =============================================================================
# TEST HELPERS
# =============================================================================
def separator(title=""):
    info("\n" + "=" * 60 + "\n")
    if title:
        info("  " + title + "\n")
        info("=" * 60 + "\n")


def ping_test(src, dst_ip, label, expect_success=True):
    """Run a 3-packet ping and validate the result."""
    info("\n>>> [TEST] %s — %s → %s  (expect: %s)\n" % (
        label, src.name, dst_ip,
        "SUCCESS ✅" if expect_success else "BLOCKED ❌"
    ))
    result = src.cmd('ping -c 3 -W 2 %s' % dst_ip)
    info(result)

    passed = ("0 received" in result or "100% packet loss" in result)
    if expect_success:
        # We expected success → fail if we got 100% loss
        if not passed:
            info("  ✅ VALIDATION PASSED: communication allowed\n")
        else:
            info("  ❌ VALIDATION FAILED: expected success but got blocked\n")
    else:
        # We expected block → pass if we got 100% loss
        if passed:
            info("  ✅ VALIDATION PASSED: traffic correctly blocked\n")
        else:
            info("  ❌ VALIDATION FAILED: expected block but traffic went through\n")

    return result


# =============================================================================
# AUTOMATED TEST SCENARIOS
# =============================================================================
def run_tests(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')

    # ------------------------------------------------------------------
    # TEST SCENARIO 1: ALLOWED communication
    # ------------------------------------------------------------------
    separator("TEST SCENARIO 1: ALLOWED Communication")

    ping_test(h1, '10.0.0.2', 'h1 → h2', expect_success=True)
    ping_test(h2, '10.0.0.3', 'h2 → h3', expect_success=True)
    ping_test(h1, '10.0.0.4', 'h1 → h4', expect_success=True)
    ping_test(h3, '10.0.0.4', 'h3 → h4', expect_success=True)

    # ------------------------------------------------------------------
    # TEST SCENARIO 2: BLOCKED communication (h1 ↔ h3)
    # ------------------------------------------------------------------
    separator("TEST SCENARIO 2: BLOCKED Communication (Firewall)")

    ping_test(h1, '10.0.0.3', 'h1 → h3 [FIREWALL]', expect_success=False)
    ping_test(h3, '10.0.0.1', 'h3 → h1 [FIREWALL]', expect_success=False)

    # ------------------------------------------------------------------
    # PERFORMANCE METRICS: iperf throughput (allowed pair h1 → h2)
    # ------------------------------------------------------------------
    separator("PERFORMANCE: iperf Throughput (h1 → h2, ALLOWED)")
    info("Starting iperf server on h2...\n")
    h2.cmd('iperf -s -p 5001 &')
    time.sleep(1)
    info("Running iperf client on h1 (10 seconds)...\n")
    iperf_result = h1.cmd('iperf -c 10.0.0.2 -p 5001 -t 10')
    info(iperf_result)
    h2.cmd('kill %iperf 2>/dev/null')

    # ------------------------------------------------------------------
    # FLOW TABLE DUMP: Show installed OpenFlow rules
    # ------------------------------------------------------------------
    separator("FLOW TABLE: OpenFlow Rules on s1")
    flow_table = h1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
    info(flow_table)

    # ------------------------------------------------------------------
    # PACKET STATISTICS: Port counters
    # ------------------------------------------------------------------
    separator("PORT STATISTICS: s1 interface counters")
    port_stats = h1.cmd('ovs-ofctl -O OpenFlow13 dump-ports s1')
    info(port_stats)

    separator("All tests complete — entering Mininet CLI")


# =============================================================================
# MAIN
# =============================================================================
def main():
    setLogLevel('info')

    info("Building FirewallTopo...\n")
    topo = FirewallTopo()

    net = Mininet(
        topo=topo,
        controller=RemoteController('c0', ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
        waitConnected=True,
    )

    net.start()

    info("\nWaiting for Ryu controller to push initial flow rules...\n")
    time.sleep(4)   # give controller time to install table-miss entry

    run_tests(net)

    info("\nType 'exit' or Ctrl-D to stop Mininet.\n")
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()