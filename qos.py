import json
import time
import datetime
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller.event import EventBase
from ryu.topology.api import get_switch, get_host
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from route import urls
from helper import ofp_helper
from config import forwarding_config, qos_config, service_config
qos_instance_name = 'qos_api_app'


class App_UpdateEvent(EventBase):
    def __init__(self, msg):
        self.msg = msg


class QosControl(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    _EVENTS = [App_UpdateEvent]
    MyDATAPATH = None

    def __init__(self, *args, **kwargs):
        super(QosControl, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(QosControlController,
                      {qos_instance_name: self})

        self.topology_api_app = self
        self.table_id = service_config.service_sequence['qos']
        self.member_limit_priority = service_config.service_priority['host_rate_limit']
        self.app_limit_priority = service_config.service_priority['app_rate_limit']
        self.goto_table_priority = service_config.service_priority['goto_table']

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.MyDATAPATH = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # update meter list
        self._request_meter_config_stats(datapath)

        # # Table Miss, forward packet to next table
        # match = parser.OFPMatch()
        # ofp_helper.add_flow_goto_next(datapath, table_id=self.table_id,
        #                               priority=self.goto_table_priority, match=match)

    def rate_limit_for_member(self, mac, bandwidth):
        meter_id = 0
        for myid, mybandwidth in qos_config.meter.iteritems():
            if mybandwidth == bandwidth:
                meter_id = myid
        forwarding_config.member_list.get(mac).meter_id = meter_id
        datapath = forwarding_config.member_list.get(mac).datapath
        out_port = forwarding_config.member_list.get(mac).port
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(eth_src=mac)
        ofp_helper.add_flow_rate_limit(datapath=datapath,
                                       table_id=self.table_id,
                                       priority=self.member_limit_priority,
                                       match=match,
                                       meter_id=meter_id,
                                       idle_timeout=10)

    def rate_limit_for_app(self, app, mac, bandwidth):
        if qos_config.app_list.get(app) is None:
            new_meter_id = self.get_free_meterid()
            self.add_meter(bandwidth, new_meter_id)
            rate_for_member = {mac: {"meter_id": new_meter_id, "bandwidth": bandwidth}}
            qos_config.app_list.update({app: rate_for_member})
        else:
            if qos_config.app_list.get(app).get(mac) is None:
                new_meter_id = self.get_free_meterid()
                self.add_meter(bandwidth, new_meter_id)
                qos_config.app_list.get(app).update({mac: {"meter_id": new_meter_id,
                                                           "bandwidth": bandwidth}})
            else:
                rate_for_member = {mac: {"bandwidth": bandwidth}}
                qos_config.app_list.get(app).get(mac)['bandwidth'] = bandwidth
        ev = App_UpdateEvent('Update rate for app')
        self.send_event_to_observers(ev)

    @set_ev_cls(App_UpdateEvent)
    def app_event_handler(self, ev):
        for app, target in qos_config.app_list.iteritems():
            for mac, meter in target.iteritems():
                meter_id = meter.get('meter_id')
                bandwidth = meter.get('bandwidth')
                # datapath = forwarding_config.member_list.get(mac).datapath
                datapath = self.MyDATAPATH
                parser = datapath.ofproto_parser
                # set the rule for the flows of the app
                flow_limited = []
                if mac == "all":
                    for key, flow in forwarding_config.flow_list.iteritems():
                        if flow.app == app:
                            flow.rate = meter_id
                            flow_limited.append(flow)
                else:
                    for key, flow in forwarding_config.flow_list.iteritems():
                        target_host = forwarding_config.member_list.get(mac)
                        if flow.dst_ip == target_host.ip and flow.app == app:
                            flow.rate = meter_id
                            flow_limited.append(flow)

                if len(flow_limited) == 0:
                    ofp_helper.mod_meter(datapath, bandwidth, meter_id)
                    self._request_meter_config_stats(datapath)
                    continue
                for flow in flow_limited:
                    match = parser.OFPMatch(ipv4_src=flow.src_ip,
                                            ipv4_dst=flow.dst_ip,
                                            ip_proto=flow.ip_proto,
                                            tcp_src=flow.src_port,
                                            tcp_dst=flow.dst_port)
                    ofp_helper.add_flow_rate_limit(datapath=datapath,
                                                   table_id=self.table_id,
                                                   priority=self.app_limit_priority,
                                                   match=match,
                                                   meter_id=meter_id,
                                                   idle_timeout=10)

                ofp_helper.mod_meter(datapath, bandwidth/len(flow_limited), meter_id)
                self._request_meter_config_stats(datapath)

    # meter
    def _request_meter_config_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPMeterConfigStatsRequest(datapath, 0, ofproto.OFPM_ALL)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPMeterConfigStatsReply, MAIN_DISPATCHER)
    def _meter_config_stats_reply_handler(self, ev):
        # Delete all meter in swtich initial
        if len(qos_config.meter) == 0:
            switch_list = get_switch(self.topology_api_app, None)
            for switch in switch_list:
                datapath = switch.dp
                parser = datapath.ofproto_parser
                body = ev.msg.body
                for stat in body:
                    rate = str(stat.bands[0].rate)
                    ofp_helper.del_meter(datapath, int(rate), int(stat.meter_id))
                qos_config.meter = {'-1': 'drop', '0': 'unlimit'}
                # Go into this function again and add meter to meter_list
                self._request_meter_config_stats(datapath)
                return

        # Update meters from switch
        qos_config.meter = {'-1': 'drop', '0': 'unlimit'}
        body = ev.msg.body
        for stat in body:
            rate = str(stat.bands[0].rate)
            qos_config.meter.update({stat.meter_id: rate})

    def add_meter(self, bandwidth, id):
        switch_list = get_switch(self.topology_api_app, None)
        for switch in switch_list:
            datapath = switch.dp
            parser = datapath.ofproto_parser
            ofp_helper.add_meter(datapath, bandwidth, id)
            self._request_meter_config_stats(datapath)

    def delete_meter(self, bandwidth, id):
        switch_list = get_switch(self.topology_api_app, None)
        for switch in switch_list:
            datapath = switch.dp
            parser = datapath.ofproto_parser
            ofp_helper.del_meter(datapath, bandwidth, id)
            self._request_meter_config_stats(datapath)

    # Get free meter id for app limitation
    def get_free_meterid(self):
        meter_list = qos_config.meter
        counter = 1
        while counter > 0:
            if meter_list.get(counter) is None:
                return counter
            else:
                counter += 1

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if not service_config.service_status['qos']:
            return


class QosControlController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QosControlController, self).__init__(req, link, data, **config)
        self.qos_control_spp = data[qos_instance_name]

    @route('qos', urls.get_qos_meter, methods=['GET'])
    def get_qos_meter(self, req, **kwargs):
        body = json.dumps(qos_config.meter)
        return Response(status=200, content_type='application/json', body=body)

    @route('qos', urls.put_qos_meter_add, methods=['PUT'])
    def put_qos_meter_add(self, req, **kwargs):
        qos_control = self.qos_control_spp

        content = req.body
        json_data = json.loads(content)
        bandwidth = int(json_data.get('bandwidth'))
        id = int(json_data.get('id'))

        qos_control.add_meter(bandwidth, id)
        return Response(status=202)

    @route('qos', urls.put_qos_meter_delete, methods=['PUT'])
    def put_qos_meter_delete(self, req, **kwargs):
        qos_control = self.qos_control_spp

        content = req.body
        json_data = json.loads(content)
        bandwidth = int(json_data.get('bandwidth'))
        id = int(json_data.get('id'))

        qos_control.delete_meter(bandwidth, id)
        return Response(status=202)

    @route('qos', urls.get_qos_topology, methods=['GET'])
    def get_qos_topology(self, req, **kwargs):
        qos_control = self.qos_control_spp
        hosts = get_host(qos_control, None)
        body = json.dumps([host.to_dict() for host in hosts])
        return Response(content_type='application/json', body=body)

    @route('flow_data', urls.get_flow_info, methods=['GET'])
    def get_flow_data(self, req, **kwargs):
        dic = []
        for key, value in forwarding_config.flow_list.iteritems():
            flow = {"src_mac": value.src_mac, "dst_mac": value.dst_mac,
                    "src_ip": value.src_ip, "dst_ip": value.dst_ip,
                    "src_port": value.src_port, "dst_port": value.dst_port,
                    "ip_proto": value.ip_proto, "rate": value.rate, "app": value.app}
            dic.append({key: flow})
        body = json.dumps(dic)
        return Response(content_type='application/json', body=body)

    @route('member_data', urls.get_member_info, methods=['GET'])
    def get_member_data(self, req, **kwargs):
        dic = []
        for key, value in forwarding_config.member_list.iteritems():
            member = {"hostname": value.hostname, "ip": value.ip,
                      "mac": value.mac, "datapath": str(value.datapath.id),
                      "port": value.port, "meter_id": value.meter_id}
            dic.append({key: member})
        body = json.dumps(dic)
        return Response(content_type='application/json', body=body)

    @route('app_data', urls.get_app_info, methods=['GET'])
    def get_app_data(self, req, **kwargs):
        dic = []
        for key, value in qos_config.app_list.iteritems():
            dic.append({key: value})
        body = json.dumps(dic)
        return Response(content_type='application/json', body=body)

    @route('set_ratelimit_for_member', urls.put_qos_rate_limit_member, methods=['PUT'])
    def set_flow_for_ratelimite_for_member(self, req, **kwargs):
        qos_control = self.qos_control_spp

        mac = str(kwargs['mac'])
        json_data = json.loads(req.body)
        bandwidth = str(json_data.get('bandwidth'))
        qos_control.rate_limit_for_member(mac, bandwidth)
        return Response(status=202)

    @route('set_ratelimit_for_app', urls.put_qos_rate_limit_app, methods=['PUT'])
    def set_flow_for_ratelimite_for_app(self, req, **kwargs):
        qos_control = self.qos_control_spp

        app = str(kwargs['app'])
        json_data = json.loads(req.body)
        bandwidth = int(json_data.get('bandwidth'))
        mac = str(json_data.get('mac'))
        qos_control.rate_limit_for_app(app, mac, bandwidth)
        return Response(status=202)

    @route('get_rate_for_app', urls.get_app_rate, methods=['GET'])
    def get_rate_in_app(self, req, **kwargs):
        app = str(kwargs['app'])
        dic = {}
        total_rate = 0
        for key, value in forwarding_config.flow_list.iteritems():
            if value.app == app and value.rate != 0:
                if dic.get(value.dst_ip) is None:
                    dic[value.dst_ip] = value.rate*8
                else:
                    dic[value.dst_ip] += value.rate*8
                total_rate += value.rate*8
        dic.update({'all': total_rate})
        body = json.dumps(dic)
        return Response(content_type='application/json', body=body)
