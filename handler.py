"""
ARP Handling in SDN Networks - Ryu Controller
=============================================
Problem: ARP requests flood the network causing inefficiency.
Solution: SDN controller intercepts ARP packets, maintains an ARP table,
          generates ARP replies directly, and installs proactive flow rules.

Author: SDN Project
Controller: Ryu OpenFlow 1.3
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib.packet import ether_types
import logging


class ARPHandler(app_manager.RyuApp):
    """
    SDN ARP Handler Controller

    This controller:
    1. Intercepts all ARP requests via packet_in events
    2. Maintains a centralized ARP table (IP -> MAC mapping)
    3. Generates ARP replies on behalf of destination hosts
    4. Installs proactive flow rules for unicast traffic
    5. Prevents ARP flooding by handling replies at the controller
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARPHandler, self).__init__(*args, **kwargs)

        # ARP Table: maps IP address -> (MAC address, datapath_id, port)
        self.arp_table = {}

        # MAC Table: maps (datapath_id, MAC) -> output_port  (for L2 forwarding)
        self.mac_to_port = {}

        self.logger.setLevel(logging.INFO)
        self.logger.info("=" * 60)
        self.logger.info("ARP Handler SDN Controller Started")
        self.logger.info("=" * 60)

    # ------------------------------------------------------------------ #
    #  Switch Handshake – install table-miss entry                        #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Called when a new switch connects.
        Installs a low-priority table-miss rule so unmatched packets
        are forwarded to the controller via packet_in.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info("[SWITCH] Connected: dpid=%016x", datapath.id)

        # Table-miss: match everything, priority 0, send to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

    # ------------------------------------------------------------------ #
    #  Packet-In Handler                                                  #
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Main packet handler.
        - ARP requests  → generate reply from controller ARP table
        - ARP replies   → update ARP table; install flow rules
        - IPv4 packets  → standard L2 forwarding
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        eth_type = eth.ethertype
        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id

        # Learn source MAC -> port mapping
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # ---- ARP Handling -------------------------------------------- #
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth, arp_pkt, msg)
            return

        # ---- IPv4 Forwarding ----------------------------------------- #
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self._handle_ipv4(datapath, in_port, eth, ip_pkt, msg)
            return

    # ------------------------------------------------------------------ #
    #  ARP Processing                                                     #
    # ------------------------------------------------------------------ #
    def _handle_arp(self, datapath, in_port, eth, arp_pkt, msg):
        """
        Handle ARP packets:
          - ARP_REQUEST: look up ARP table; if known, reply immediately.
          - ARP_REPLY:   update ARP table; install bidirectional flow rules.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip
        src_mac = arp_pkt.src_mac

        # Always learn the sender
        self.arp_table[src_ip] = (src_mac, dpid, in_port)
        self.logger.info("[ARP  ] Learned  %-15s -> %s  (dpid=%016x port=%s)",
                         src_ip, src_mac, dpid, in_port)

        # ---- ARP Request --------------------------------------------- #
        if arp_pkt.opcode == arp.ARP_REQUEST:
            self.logger.info("[ARP  ] REQUEST  who-has %-15s tell %s (%s)",
                             dst_ip, src_ip, src_mac)

            if dst_ip in self.arp_table:
                # We know the destination: generate a gratuitous reply
                dst_mac_known, _, _ = self.arp_table[dst_ip]
                self.logger.info(
                    "[ARP  ] REPLY    %-15s is-at %s  (controller proxy)",
                    dst_ip, dst_mac_known)
                self._send_arp_reply(
                    datapath, in_port,
                    src_ip=dst_ip, src_mac=dst_mac_known,
                    dst_ip=src_ip, dst_mac=src_mac
                )
            else:
                # Unknown destination: flood the ARP request
                self.logger.info(
                    "[ARP  ] FLOOD    %-15s not in table yet", dst_ip)
                self._flood(datapath, msg)

        # ---- ARP Reply ----------------------------------------------- #
        elif arp_pkt.opcode == arp.ARP_REPLY:
            self.logger.info("[ARP  ] REPLY    %-15s is-at %s", src_ip, src_mac)

            # Forward the reply to the requester if we know their port
            dst_mac = eth.dst
            if dst_mac in self.mac_to_port.get(dpid, {}):
                out_port = self.mac_to_port[dpid][dst_mac]
                self._send_packet(datapath, out_port, msg)

                # Install proactive flow rules for both directions
                dst_ip_known = arp_pkt.dst_ip
                if dst_ip_known in self.arp_table:
                    _, dst_dpid, dst_port = self.arp_table[dst_ip_known]
                    # src -> dst flow
                    self._install_flow_pair(
                        datapath, src_ip, dst_ip_known,
                        src_mac, dst_mac, out_port
                    )
                    self.logger.info(
                        "[FLOW ] Installed flow %s -> %s", src_ip, dst_ip_known)
            else:
                self._flood(datapath, msg)

    # ------------------------------------------------------------------ #
    #  IPv4 Forwarding                                                    #
    # ------------------------------------------------------------------ #
    def _handle_ipv4(self, datapath, in_port, eth, ip_pkt, msg):
        """Standard L2 forwarding for IPv4 packets."""
        dpid = datapath.id
        dst_mac = eth.dst
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dst_mac in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow rule if we know the exact port
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac,
                eth_src=eth.src
            )
            self._add_flow(datapath, priority=10, match=match, actions=actions,
                           idle_timeout=30, hard_timeout=120)

        self._send_packet(datapath, out_port, msg)

    # ------------------------------------------------------------------ #
    #  Helper: Generate ARP Reply Packet                                  #
    # ------------------------------------------------------------------ #
    def _send_arp_reply(self, datapath, out_port,
                        src_ip, src_mac, dst_ip, dst_mac):
        """
        Construct and send an ARP reply packet out of the specified port.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Build Ethernet + ARP reply
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        ))
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)

    # ------------------------------------------------------------------ #
    #  Helper: Install Bidirectional Flow Rules                           #
    # ------------------------------------------------------------------ #
    def _install_flow_pair(self, datapath, src_ip, dst_ip,
                           src_mac, dst_mac, dst_port):
        """
        Install match-action flow rules for both src->dst and dst->src.
        """
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Forward direction: src -> dst
        if src_mac in self.mac_to_port.get(dpid, {}):
            src_port = self.mac_to_port[dpid][src_mac]
            match_fwd = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip
            )
            actions_fwd = [parser.OFPActionOutput(dst_port)]
            self._add_flow(datapath, priority=20, match=match_fwd,
                           actions=actions_fwd,
                           idle_timeout=60, hard_timeout=300)

        # Reverse direction: dst -> src
        if dst_mac in self.mac_to_port.get(dpid, {}):
            rev_port = self.mac_to_port[dpid][src_mac]
            match_rev = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=dst_ip,
                ipv4_dst=src_ip
            )
            actions_rev = [parser.OFPActionOutput(rev_port)]
            self._add_flow(datapath, priority=20, match=match_rev,
                           actions=actions_rev,
                           idle_timeout=60, hard_timeout=300)

    # ------------------------------------------------------------------ #
    #  Helper: Add Flow Rule                                              #
    # ------------------------------------------------------------------ #
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """
        Install a flow rule on the switch.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    # ------------------------------------------------------------------ #
    #  Helper: Flood Packet                                               #
    # ------------------------------------------------------------------ #
    def _flood(self, datapath, msg):
        """Send packet out all ports except the one it arrived on."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    # ------------------------------------------------------------------ #
    #  Helper: Send Packet Out                                            #
    # ------------------------------------------------------------------ #
    def _send_packet(self, datapath, out_port, msg):
        """Forward a buffered or unbuffered packet to a specific port."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)