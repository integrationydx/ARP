"""
ARP Handling in SDN Networks - POX Controller
==============================================
Problem: ARP requests flood the network causing inefficiency.
Solution: SDN controller intercepts ARP packets, maintains an ARP table,
          generates ARP replies directly, and installs proactive flow rules.

Author: SDN Project
Controller: POX (OpenFlow 1.0)

Usage:
    cd ~/pox
    python3 pox.py log.level --DEBUG misc.arp_handler
    (place this file in ~/pox/pox/misc/arp_handler.py)
"""

from pox.core import core
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4
from pox.lib.packet.ethernet import ethernet as eth_type
import pox.lib.packet as pkt

log = core.getLogger()


class ARPHandler(object):
    """
    POX SDN ARP Handler

    This controller:
    1. Intercepts all ARP requests via PacketIn events
    2. Maintains a centralized ARP table (IP -> MAC mapping)
    3. Generates ARP replies on behalf of destination hosts (proxy ARP)
    4. Installs proactive flow rules for unicast traffic
    5. Prevents ARP flooding by handling replies at the controller
    """

    def __init__(self, connection):
        self.connection = connection

        # ARP Table: IP (string) -> (EthAddr, port)
        self.arp_table = {}

        # MAC Table: MAC (string) -> port
        self.mac_to_port = {}

        # Listen to PacketIn and ConnectionDown events
        connection.addListeners(self)

        log.info("Switch %s connected — installing table-miss rule",
                 dpidToStr(connection.dpid))
        self._install_table_miss()

    # ------------------------------------------------------------------ #
    #  Table-Miss Rule                                                    #
    # ------------------------------------------------------------------ #
    def _install_table_miss(self):
        """
        Install a low-priority catch-all rule so every unmatched packet
        is sent to the controller via PacketIn.
        """
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.match = of.ofp_match()          # Match everything
        msg.actions.append(
            of.ofp_action_output(port=of.OFPP_CONTROLLER)
        )
        self.connection.send(msg)

    # ------------------------------------------------------------------ #
    #  PacketIn Handler                                                   #
    # ------------------------------------------------------------------ #
    def _handle_PacketIn(self, event):
        """
        Main packet handler — called for every packet_in event.
        Routes ARP and IPv4 packets to their respective handlers.
        """
        packet_in = event.ofp          # Raw OpenFlow PacketIn message
        parsed   = event.parsed        # Parsed packet
        in_port  = event.port

        if not parsed.parsed:
            log.warning("Ignoring unparsed packet")
            return

        src_mac = parsed.src            # EthAddr
        dst_mac = parsed.dst

        # Learn MAC -> port
        self.mac_to_port[str(src_mac)] = in_port

        # ---- ARP ---------------------------------------------------- #
        arp_pkt = parsed.find('arp')
        if arp_pkt:
            self._handle_arp(event, parsed, arp_pkt, in_port)
            return

        # ---- IPv4 --------------------------------------------------- #
        ip_pkt = parsed.find('ipv4')
        if ip_pkt:
            self._handle_ipv4(event, parsed, ip_pkt, in_port)
            return

    # ------------------------------------------------------------------ #
    #  ARP Processing                                                     #
    # ------------------------------------------------------------------ #
    def _handle_arp(self, event, parsed, arp_pkt, in_port):
        """
        Handle ARP packets:
          ARP_REQUEST → if destination known, reply from controller (proxy).
                        if unknown, flood.
          ARP_REPLY   → update ARP table; forward to requester; install flows.
        """
        src_ip  = str(arp_pkt.protosrc)   # e.g. "10.0.0.1"
        dst_ip  = str(arp_pkt.protodst)
        src_mac = arp_pkt.hwsrc           # EthAddr

        # Always learn the sender
        self.arp_table[src_ip] = (src_mac, in_port)
        log.info("[ARP  ] Learned  %-15s -> %s  (port %s)",
                 src_ip, src_mac, in_port)

        # ---- ARP Request -------------------------------------------- #
        if arp_pkt.opcode == arp.REQUEST:
            log.info("[ARP  ] REQUEST  who-has %-15s tell %s (%s)",
                     dst_ip, src_ip, src_mac)

            if dst_ip in self.arp_table:
                dst_mac_known, _ = self.arp_table[dst_ip]
                log.info(
                    "[ARP  ] PROXY REPLY  %-15s is-at %s  (controller)",
                    dst_ip, dst_mac_known)
                self._send_arp_reply(
                    in_port,
                    src_ip=dst_ip,  src_mac=dst_mac_known,
                    dst_ip=src_ip,  dst_mac=src_mac
                )
            else:
                log.info("[ARP  ] FLOOD    %-15s not in table yet", dst_ip)
                self._flood(event)

        # ---- ARP Reply ---------------------------------------------- #
        elif arp_pkt.opcode == arp.REPLY:
            log.info("[ARP  ] REPLY    %-15s is-at %s", src_ip, src_mac)

            dst_mac = parsed.dst
            dst_mac_str = str(dst_mac)

            if dst_mac_str in self.mac_to_port:
                out_port = self.mac_to_port[dst_mac_str]
                self._send_packet(event.ofp, out_port)

                # Install bidirectional IP flow rules
                dst_ip_str = str(arp_pkt.protodst)
                if dst_ip_str in self.arp_table:
                    self._install_flow_pair(
                        src_ip, dst_ip_str,
                        src_mac, dst_mac,
                        in_port, out_port
                    )
            else:
                self._flood(event)

    # ------------------------------------------------------------------ #
    #  IPv4 Forwarding                                                    #
    # ------------------------------------------------------------------ #
    def _handle_ipv4(self, event, parsed, ip_pkt, in_port):
        """Standard L2 forwarding for IPv4 packets."""
        dst_mac     = parsed.dst
        dst_mac_str = str(dst_mac)

        if dst_mac_str in self.mac_to_port:
            out_port = self.mac_to_port[dst_mac_str]

            # Install L2 flow rule
            msg = of.ofp_flow_mod()
            msg.priority    = 10
            msg.idle_timeout = 30
            msg.hard_timeout = 120
            msg.match        = of.ofp_match.from_packet(parsed, in_port)
            msg.actions.append(of.ofp_action_output(port=out_port))
            msg.data         = event.ofp
            self.connection.send(msg)
        else:
            self._flood(event)

    # ------------------------------------------------------------------ #
    #  Helper: Generate and Send ARP Reply                               #
    # ------------------------------------------------------------------ #
    def _send_arp_reply(self, out_port, src_ip, src_mac, dst_ip, dst_mac):
        """
        Build an ARP reply packet and send it out of out_port.
        src_* = the host being queried (the one we're replying ON BEHALF OF)
        dst_* = the host that sent the ARP request (receives the reply)
        """
        # Build ARP layer
        arp_reply        = arp()
        arp_reply.opcode  = arp.REPLY
        arp_reply.hwsrc   = EthAddr(src_mac)
        arp_reply.hwdst   = EthAddr(dst_mac)
        arp_reply.protosrc = IPAddr(src_ip)
        arp_reply.protodst = IPAddr(dst_ip)

        # Build Ethernet layer
        eth_frame       = ethernet()
        eth_frame.type  = ethernet.ARP_TYPE
        eth_frame.src   = EthAddr(src_mac)
        eth_frame.dst   = EthAddr(dst_mac)
        eth_frame.payload = arp_reply

        # Send as PacketOut
        msg         = of.ofp_packet_out()
        msg.data    = eth_frame.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = of.OFPP_NONE
        self.connection.send(msg)

    # ------------------------------------------------------------------ #
    #  Helper: Install Bidirectional Flow Rules                          #
    # ------------------------------------------------------------------ #
    def _install_flow_pair(self, src_ip, dst_ip,
                           src_mac, dst_mac,
                           src_port, dst_port):
        """
        Install match-action IP flow rules in both directions.
        Priority 20, idle timeout 60s, hard timeout 300s.
        """
        # Forward: src -> dst
        msg_fwd = of.ofp_flow_mod()
        msg_fwd.priority     = 20
        msg_fwd.idle_timeout = 60
        msg_fwd.hard_timeout = 300
        msg_fwd.match        = of.ofp_match()
        msg_fwd.match.dl_type  = 0x0800          # IPv4
        msg_fwd.match.nw_src   = IPAddr(src_ip)
        msg_fwd.match.nw_dst   = IPAddr(dst_ip)
        msg_fwd.actions.append(of.ofp_action_output(port=dst_port))
        self.connection.send(msg_fwd)

        # Reverse: dst -> src
        msg_rev = of.ofp_flow_mod()
        msg_rev.priority     = 20
        msg_rev.idle_timeout = 60
        msg_rev.hard_timeout = 300
        msg_rev.match        = of.ofp_match()
        msg_rev.match.dl_type  = 0x0800
        msg_rev.match.nw_src   = IPAddr(dst_ip)
        msg_rev.match.nw_dst   = IPAddr(src_ip)
        msg_rev.actions.append(of.ofp_action_output(port=src_port))
        self.connection.send(msg_rev)

        log.info("[FLOW ] Installed flow %s <-> %s", src_ip, dst_ip)

    # ------------------------------------------------------------------ #
    #  Helper: Flood                                                     #
    # ------------------------------------------------------------------ #
    def _flood(self, event):
        """Send packet out all ports except the one it arrived on."""
        msg         = of.ofp_packet_out()
        msg.data    = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    # ------------------------------------------------------------------ #
    #  Helper: Send Packet Out (unicast)                                 #
    # ------------------------------------------------------------------ #
    def _send_packet(self, packet_in, out_port):
        """Forward a packet to a specific port."""
        msg         = of.ofp_packet_out()
        msg.data    = packet_in
        msg.in_port = packet_in.in_port
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)


# ------------------------------------------------------------------ #
#  Component Launch Function (POX entry point)                       #
# ------------------------------------------------------------------ #

class ARPHandlerLauncher(object):
    """Listens for new switch connections and spawns an ARPHandler."""

    def __init__(self):
        core.openflow.addListeners(self)
        log.info("=" * 55)
        log.info("  ARP Handler SDN Controller (POX) Started")
        log.info("=" * 55)

    def _handle_ConnectionUp(self, event):
        log.info("New switch connected: %s", dpidToStr(event.dpid))
        ARPHandler(event.connection)


def launch():
    """POX calls this function to start the component."""
    core.registerNew(ARPHandlerLauncher)