from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology.api import get_switch
from ryu.controller.event import EventBase
from ryu.lib import hub
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.app.ofctl.api import get_datapath
from config import forwarding_config, qos_config
from models import flow
from models.member import Member
from qos import App_UpdateEvent

import logging


class flowstatistic_monitor(app_manager.RyuApp):

    _EVENTS = [App_UpdateEvent]

    def __init__(self, *args, **kwargs):
        """Initial Setting method."""
        super(flowstatistic_monitor, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        logging.getLogger("requests").setLevel(logging.WARNING)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.monitor_thread = hub.spawn(self._monitor, datapath)

    def _monitor(self, datapath):
        while True:
            key_set = forwarding_config.flow_list.keys()
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
            ev = App_UpdateEvent('Update rate for app')
            self.send_event_to_observers(ev)
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            reason = 'IDLE TIMEOUT'
            if msg.match.get('eth_type') == ether.ETH_TYPE_IP:
                key_tuples = str(ev.msg.datapath.id)\
                             + '' or msg.match.get('eth_src')\
                             + msg.match.get('eth_dst')\
                             + msg.match.get('ipv4_src')\
                             + msg.match.get('ipv4_dst')\
                             + str(msg.match.get('ip_proto'))
                if msg.match.get('ip_proto') == inet.IPPROTO_TCP:
                    key_tuples += str(msg.match.get('tcp_src')) + str(msg.match.get('tcp_dst'))
                elif msg.match.get('ip_proto') == inet.IPPROTO_UDP:
                    key_tuples += str(msg.match.get('udp_src')) + str(msg.match.get('udp_dst'))
                del forwarding_config.flow_list[key_tuples]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            if stat.table_id != 3:
                continue
            if stat.match.get('eth_type') == ether.ETH_TYPE_IP:
                key_tuples = str(ev.msg.datapath.id)\
                             + '' or stat.match.get('eth_src')\
                             + stat.match.get('eth_dst')\
                             + stat.match.get('ipv4_src')\
                             + stat.match.get('ipv4_dst')\
                             + str(stat.match.get('ip_proto'))

                if stat.match.get('ip_proto') == inet.IPPROTO_TCP:
                    key_tuples += str(stat.match.get('tcp_src')) + str(stat.match.get('tcp_dst'))

                    if forwarding_config.flow_list.get(key_tuples) is None:
                        flow_value = flow.Flow(ev.msg.datapath.id,
                                               stat.match.get('eth_src'),
                                               stat.match.get('eth_dst'),
                                               stat.match.get('ipv4_src'),
                                               stat.match.get('ipv4_dst'),
                                               stat.match.get('ip_proto'),
                                               stat.match.get('tcp_src'),
                                               stat.match.get('tcp_dst'),
                                               stat.byte_count, 1)
                        flow_value.rate_calculation()
                        forwarding_config.flow_list.update({key_tuples: flow_value})
                    else:
                        flow_value = forwarding_config.flow_list.get(key_tuples)
                        flow_value.byte_count_1 = flow_value.byte_count_2
                        flow_value.byte_count_2 = stat.byte_count
                        flow_value.rate_calculation()

                elif stat.match.get('ip_proto') == inet.IPPROTO_UDP:
                    key_tuples += str(stat.match.get('udp_src'))\
                                      + str(stat.match.get('udp_dst'))
                    if forwarding_config.flow_list.get(key_tuples) is None:
                        flow_value = flow.Flow(ev.msg.datapath.id,
                                               stat.match.get('eth_src'),
                                               stat.match.get('eth_dst'),
                                               stat.match.get('ipv4_src'),
                                               stat.match.get('ipv4_dst'),
                                               stat.match.get('ip_proto'),
                                               stat.match.get('udp_src'),
                                               stat.match.get('udp_dst'),
                                               stat.byte_count, 1)
                        flow_value.rate_calculation()
                        forwarding_config.flow_list.update({key_tuples: flow_value})
                    else:
                        flow_value = forwarding_config.flow_list.get(key_tuples)
                        flow_value.byte_count_1 = flow_value.byte_count_2
                        flow_value.byte_count_2 = stat.byte_count
                        flow_value.rate_calculation()
                        flow_value.exist = 1

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # retrieve packet
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)

        if pkt_dhcp:
            for options in pkt_dhcp.options.option_list:
                if(options.tag == 12):
                    if forwarding_config.member_list.get(pkt_dhcp.chaddr) is not None:
                        member = forwarding_config.member_list.get(pkt_dhcp.chaddr)
                    else:
                        forwarding_config.member_list.setdefault(pkt_dhcp.chaddr,
                                                                 Member(pkt_dhcp.chaddr))
                        forwarding_config.member_list[pkt_dhcp.chaddr].datapath = datapath
                        forwarding_config.member_list[pkt_dhcp.chaddr].port = in_port
                    forwarding_config.member_list[pkt_dhcp.chaddr].hostname = options.value

        if pkt_arp:
            self._handle_arp(msg, in_port, pkt_eth, pkt_arp)
        elif pkt_ipv4:
            self._handle_ipv4(msg, in_port, pkt, pkt_eth, pkt_ipv4)

    def _handle_arp(self, msg, in_port, pkt_eth, pkt_arp):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        eth_src = pkt_eth.src

        # update member(host) in member_list
        member_list = forwarding_config.member_list
        member_list.setdefault(eth_src, Member(eth_src))
        member_list[eth_src].datapath = datapath
        member_list[eth_src].port = in_port

    def _handle_ipv4(self, msg, in_port, pkt, pkt_ethernet, pkt_ipv4):
        datapath = msg.datapath
        eth_src = pkt_ethernet.src

        # update ip info for members in member_list
        member_list = forwarding_config.member_list
        member_list.setdefault(eth_src, Member(eth_src))
        src_member = member_list[pkt_ethernet.src]
        src_member.ip = pkt_ipv4.src
        src_member.port = in_port
        src_member.datapath = datapath
