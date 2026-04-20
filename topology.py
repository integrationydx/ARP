#!/usr/bin/env python3
"""
Mininet Topology for ARP Handling in SDN Networks
==================================================
Controller: POX (OpenFlow 1.0)

NOTE: POX uses OpenFlow 1.0, so the switch protocol is set to OpenFlow10.

Usage:
    # Terminal 1 — start POX controller first
    cd ~/pox
    python3 pox.py log.level --DEBUG misc.arp_handler

    # Terminal 2 — start topology
    sudo python3 topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


def build_topology():
    setLogLevel('info')

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Creating controller\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633          # POX default port
    )

    info("*** Creating switch\n")
    # POX uses OpenFlow 1.0
    s1 = net.addSwitch('s1', protocols='OpenFlow10')

    info("*** Creating hosts\n")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    info("*** Creating links (10 Mbps, 5ms delay)\n")
    net.addLink(h1, s1, bw=10, delay='5ms')
    net.addLink(h2, s1, bw=10, delay='5ms')
    net.addLink(h3, s1, bw=10, delay='5ms')
    net.addLink(h4, s1, bw=10, delay='5ms')

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])

    info("*** Waiting for controller (3s)\n")
    time.sleep(3)

    info("\n" + "=" * 60 + "\n")
    info("Topology Ready:\n")
    info("  h1: 10.0.0.1  MAC: 00:00:00:00:00:01\n")
    info("  h2: 10.0.0.2  MAC: 00:00:00:00:00:02\n")
    info("  h3: 10.0.0.3  MAC: 00:00:00:00:00:03\n")
    info("  h4: 10.0.0.4  MAC: 00:00:00:00:00:04\n")
    info("=" * 60 + "\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    build_topology()