import random
import copy

# example configuration for DMPR daemon
exa_conf = """
    "id" : "ace80ef4-d284-11e6-bf26-cec0c932ce01",
    "rtn-msg-interval" : "30",
    "rtn-msg-interval-jitter" : "7",
    "rtn-msg-hold-time" : "90",
    "mcast-v4-tx-addr" : "224.0.1.1",
    "mcast-v6-tx-addr" : "ff05:0:0:0:0:0:0:2",
    "proto-transport-enable"  : [ "v4" ],
    "interfaces" : [
      { "name" : "wlan0", "addr-v4" : "10.0.0.1", "link-characteristics" : { "bandwidth" : "100000", "loss" : "0"  } },
      { "name" : "tetra0", "addr-v4" : "10.0.0.1", "link-characteristics" : { "bandwidth" : "10000",  "loss" : "0"  } }
    ],
    "networks" : [
       { "proto": "v4", "prefix" : "192.168.1.0", "prefix-len" : "24" },
       { "proto": "v4", "prefix" : "192.168.2.0", "prefix-len" : "24" },
       { "proto": "v4", "prefix" : "10.10.0.0",   "prefix-len" : "16" },
       { "proto": "v6", "prefix" : "fdcb:523:1111::", "prefix-len" : "48" },
       { "proto": "v6", "prefix" : "fd6a:6ad:b07f:ffff::", "prefix-len" : "64" }
    }
"""


class ConfigurationException(Exception): pass


class InternalException(Exception): pass


class DMPRConfigDefaults(object):
    rtn_msg_interval = "30"
    rtn_msg_interval_jitter = str(int(int(rtn_msg_interval) / 4))
    rtn_msg_hold_time = str(int(rtn_msg_interval) * 3)

    # default bandwidth for a given interface in bytes/second
    # bytes/second enabled dmpr deployed in low bandwidth environments
    # normally this value should be fetched from a interface information
    # or by active measurements.
    # Implementers SHOULD quantise values into a few classes to reduce the
    # DMPR routing packet size.
    # E.g. 1000, 5000, 10000, 100000, 1000000, 100000000, 100000000
    LINK_CHARACTERISITCS_BANDWIDTH = "5000"
    # default loss is in percent for a given path
    # Implementers SHOULD quantise values into a few classes to reduce the
    # DMPR routing packet size.
    # e.g. 0, 5, 10, 20, 40, 80
    LINK_CHARACTERISITCS_LOSS = "0"
    # default link cost in a hypothetical currency, the higher the more valuable
    # e.g. wifi can be 0, LTE can be 100, satelite uplink can be 1000
    LINK_CHARACTERISITCS_COST = "0"


class NoOpTracer(object):
    # Just a stub do nothing, just catch calls for
    # the case no trace instance is passed

    def __init__(self):
        pass

    def log(self, tracepoint, msg):
        pass


class DMPR(object):
    # TODO: change signature, log is required
    def __init__(self, log=None, tracer=None):
        assert (log)
        self._conf = None
        self._time = None
        self.log = log
        self.tracer = NoOpTracer() if tracer is None else tracer
        self._reset()

    def register_configuration(self, configuration):
        """ register and setup configuration. Raise
            an error when values are wrongly configured """
        assert (configuration)
        assert isinstance(configuration, dict)
        self.validate_config(configuration)

    def validate_config(self, configuration):
        """ convert external python dict configuration
            into internal configuration and check values """
        assert (configuration)
        self._conf = {}
        cmd = "rtn-msg-interval"
        self._conf[cmd] = configuration.get(cmd, DMPRConfigDefaults.rtn_msg_interval)
        cmd = "rtn-msg-interval-jitter"
        self._conf[cmd] = configuration.get(cmd, DMPRConfigDefaults.rtn_msg_interval_jitter)
        cmd = "rtn-msg-hold-time"
        self._conf[cmd] = configuration.get(cmd, DMPRConfigDefaults.rtn_msg_hold_time)
        if "id" not in configuration:
            msg = "configuration contains no id! A id must be unique, it can be \
                   randomly generated but for better performance and debugging \
                   capabilities this generated ID should be saved permanently \
                   (e.g. at a local file) to survive daemon restarts"
            raise ConfigurationException(msg)
        if not isinstance(configuration["id"], str):
            msg = "id must be a string!"
            raise ConfigurationException(msg)
        self._conf["id"] = configuration["id"]
        if not "interfaces" in configuration:
            msg = "No interface configurated, need at least one"
            raise ConfigurationException(msg)
        self._conf["interfaces"] = configuration["interfaces"]
        if not isinstance(self._conf["interfaces"], list):
            msg = "interfaces must be a list!"
            raise ConfigurationException(msg)
        if len(self._conf["interfaces"]) <= 0:
            msg = "at least one interface must be configured!"
            raise ConfigurationException(msg)
        for interface_data in self._conf["interfaces"]:
            if not isinstance(interface_data, dict):
                msg = "interface entry must be dict: {}".format(interface_data)
                raise ConfigurationException(msg)
            if "name" not in interface_data:
                msg = "interfaces entry must contain at least a \"name\""
                raise ConfigurationException(msg)
            if "addr-v4" not in interface_data:
                msg = "interfaces entry must contain at least a \"addr-v4\""
                raise ConfigurationException(msg)
            if "link-characteristics" not in interface_data:
                msg = "interfaces has no link characterstics, default some \"link-characteristics\""
                now = self._get_time(priv_data=self._get_time_priv_data)
                self.log.warning(msg, time=now)
                interface_data["link-characteristics"] = dict()
                interface_data["link-characteristics"]["bandwidth"] = DMPRConfigDefaults.LINK_CHARACTERISITCS_BANDWIDTH
                interface_data["link-characteristics"]["loss"] = DMPRConfigDefaults.LINK_CHARACTERISITCS_LOSS
        if "networks" in configuration:
            if not isinstance(configuration["networks"], list):
                msg = "networks must be a list!"
                raise ConfigurationException(msg)
            for network in configuration["networks"]:
                if not isinstance(network, dict):
                    msg = "interface entry must be dict: {}".format(network)
                    raise ConfigurationException(msg)
                if not "proto" in network:
                    msg = "network must contain proto key: {}".format(network)
                    raise ConfigurationException(msg)
                if not "prefix" in network:
                    msg = "network must contain prefix key: {}".format(network)
                    raise ConfigurationException(msg)
                if not "prefix-len" in network:
                    msg = "network must contain prefix-len key: {}".format(network)
                    raise ConfigurationException(msg)
            # seens fine, save it as it is
            self._conf["networks"] = configuration["networks"]
        if "mcast-v4-tx-addr" not in configuration:
            msg = "no mcast-v4-tx-addr configured!"
            raise ConfigurationException(msg)
        self._conf["mcast-v4-tx-addr"] = configuration["mcast-v4-tx-addr"]
        if "mcast-v6-tx-addr" not in configuration:
            msg = "no mcast-v6-tx-addr configured!"
            raise ConfigurationException(msg)
        self._conf["mcast-v6-tx-addr"] = configuration["mcast-v6-tx-addr"]

    def _check_outdated_route_entries(self):
        route_recalc_required = False
        # iterate over all interfaces
        for interface, v in self._rtd["interfaces"].items():
            dellist = []
            # iterate over all neighbors
            for router_id, vv in v["rx-msg-db"].items():
                now = self._get_time(priv_data=self._get_time_priv_data)
                if now - vv["rx-time"] > int(self._conf["rtn-msg-hold-time"]):
                    msg = "outdated entry from {} received at {}, interface: {} - drop it"
                    self.log.debug(msg.format(router_id, vv["rx-time"], interface),
                                   time=now)
                    dellist.append(router_id)
            for id_ in dellist:
                route_recalc_required = True
                del v["rx-msg-db"][id_]
        return route_recalc_required

    def conf_originator_addr_by_iface_v6(self, iface_name):
        for iface_data in self._conf["interfaces"]:
            if iface_data['name'] == iface_name:
                return iface_data['addr-v6']
        return None

    def conf_originator_addr_by_iface_v4(self, iface_name):
        for iface_data in self._conf["interfaces"]:
            if iface_data['name'] == iface_name:
                return iface_data['addr-v4']
        return None

    def conf_originator_addr_by_iface(self, proto, iface_name):
        if proto == "v4":
            return self.conf_originator_addr_by_iface_v4(iface_name)
        if proto == "v6":
            return self.conf_originator_addr_by_iface_v6(iface_name)
        raise InternalException("v4 or v6 not something else")

    def create_routing_msg(self, interface_name):
        packet = dict()
        packet['id'] = self._conf["id"]
        # add sequence number to packet ..
        packet['sequence-no'] = self._sequence_no(interface_name)
        # ... and increment number locally
        self._sequence_no_inc(interface_name)
        packet['networks'] = list()
        packet['originator-addr-v4'] = self.conf_originator_addr_by_iface("v4", interface_name)
        for network in self._conf["networks"]:
            if network["proto"] == "v4":
                ipstr = "{}/{}".format(network["prefix"], network["prefix-len"])
                packet['networks'].append({"v4-prefix": ipstr})
        packet['routingpaths'] = dict()
        if len(self.fib['high_bandwidth']) > 0 or len(self.fib['low_loss']) > 0:
            packet['routingpaths'] = self.fib.copy()
        return packet

    def tx_route_packet(self):
        # depending on local information the route
        # packets must be generated for each interface
        for interface_name in self._rtd["interfaces"]:
            msg = self.create_routing_msg(interface_name)
            self.log.info(msg)
            v4_mcast_addr = self._conf["mcast-v4-tx-addr"]
            self._packet_tx_func(interface_name, "v4", v4_mcast_addr, msg,
                                 priv_data=self._packet_tx_func_priv_data)

    def tick(self):
        """ this function is called every second, DMPR will
            implement his own timer/timeout related functionality
            based on this ticker. This is not the most efficient
            way to implement timers but it is suitable to run in
            a real and simulated environment where time is discret.
            The argument time is a float value in seconds which should
            not used in a absolute manner, depending on environment this
            can be a unix timestamp or starting at 0 in simulation
            environments """
        if not self._started:
            # start() is not called, ignore this call
            return
        route_recalc_required = self._check_outdated_route_entries()
        if route_recalc_required:
            self._recalculate_routing_table()

        now = self._get_time(priv_data=self._get_time_priv_data)
        self.tracer.log(self.tracer.TICK, {'now': now})
        if now >= self._next_tx_time:
            self.tx_route_packet()
            self._calc_next_tx_time()
            self.transmitted_now = True
        else:
            self.transmitted_now = False

    def stop(self):
        self._reset()
        now = self._get_time(priv_data=self._get_time_priv_data)
        self.log.warning("stop DMPR core", time=now)

    def _reset(self):
        self.started = False
        self._routing_table = None
        self._next_tx_time = None

    def start(self):
        now = self._get_time(priv_data=self._get_time_priv_data)
        self.log.info("start DMPR core", time=now)
        assert (self._get_time)
        assert (self._routing_table_update_func)
        assert (self._packet_tx_func)
        assert (self._conf)
        assert (self._routing_table == None)
        self._init_runtime_data()
        self._calc_next_tx_time()
        self._started = True

    def restart(self):
        self.stop()
        self.start()

    def _init_runtime_data(self):
        self._rtd = dict()
        # init interface specific container data
        self._rtd["interfaces"] = dict()
        for interface in self._conf["interfaces"]:
            self._rtd["interfaces"][interface["name"]] = dict()
            self._rtd["interfaces"][interface["name"]]["sequence-no-tx"] = 0
            self._rtd["interfaces"][interface["name"]]["rx-msg-db"] = dict()
        self.fib = dict()
        self.fib['high_bandwidth'] = dict()
        self.fib['low_loss'] = dict()

    def _sequence_no(self, interface_name):
        return self._rtd["interfaces"][interface_name]["sequence-no-tx"]

    def _sequence_no_inc(self, interface_name):
        self._rtd["interfaces"][interface_name]["sequence-no-tx"] += 1

    def _calc_next_tx_time(self):
        interval = int(self._conf["rtn-msg-interval"])
        if self._next_tx_time == None:
            # we start to the first time or after a
            # restart, so do not wait interval seconds, thisself._conf["id"]
            # is just silly, we want to join the network as early
            # as possible. But due to global synchronisation effects
            # we are kind and jitter at least some seconds
            interval = 0
        jitter = self._conf["rtn-msg-interval-jitter"]
        waittime = interval + random.randint(0, int(jitter))
        now = self._get_time(priv_data=self._get_time_priv_data)
        self._next_tx_time = now + waittime
        self.log.debug("schedule next transmission for {} seconds".format(self._next_tx_time), time=now)

    def _is_valid_interface(self, interface_name):
        found = False
        for interface in self._conf["interfaces"]:
            if interface_name == interface["name"]:
                found = True
        return found

    def _validate_rx_msg(self, msg, interface_name):
        ok = self._is_valid_interface(interface_name)
        if not ok:
            emsg = "{} is not a configured, thus valid interface name, "
            emsg += "ignore packet for now"
            now = self._get_time(priv_data=self._get_time_priv_data)
            self.log.error(emsg.format(interface_name), time=now)
            return False
        if msg['id'] == self._conf['id']:
            emsg = "receive a message from ourself! id:{} == id:{}, ".format(msg['id'], self._conf['id'])
            emsg += " This means a) configration error (same id, or look problem"
            now = self._get_time(priv_data=self._get_time_priv_data)
            self.log.error(emsg, time=now)
            return False
        return True

    # FIXME: search log for update here
    def _cmp_dicts(self, dict1, dict2):
        if dict1 == None or dict2 == None: return False
        if type(dict1) is not dict or type(dict2) is not dict: return False
        shared_keys = set(dict2.keys()) & set(dict2.keys())
        if not len(shared_keys) == len(dict1.keys()) and len(shared_keys) == len(dict2.keys()):
            return False
        eq = True
        for key in dict1.keys():
            if type(dict1[key]) is dict:
                if key not in dict2:
                    return False
                else:
                    eq = eq and self._cmp_dicts(dict1[key], dict2[key])
            else:
                if key not in dict2:
                    return False
                else:
                    eq = eq and (dict1[key] == dict2[key])
        return eq

    def _cmp_packets(self, packet1, packet2):
        p1 = copy.deepcopy(packet1)
        p2 = copy.deepcopy(packet2)
        # some data may differ, but the content is identical,
        # zeroize them here out
        p1['sequence-no'] = 0
        p2['sequence-no'] = 0
        return self._cmp_dicts(p1, p2)

    def msg_rx(self, interface_name, msg):
        """ receive routing packet in json encoded
             data format """
        rxmsg = "rx route packet from {}, interface:{}, seq-no:{}"
        self.log.info(rxmsg.format(msg['id'], interface_name, msg['sequence-no']))
        ok = self._validate_rx_msg(msg, interface_name)
        if not ok:
            now = self._get_time(priv_data=self._get_time_priv_data)
            self.log.warning("packet corrupt, dropping it", time=now)
            return
        route_recalc_required = self._rx_save_routing_data(msg, interface_name)
        if route_recalc_required:
            self._recalculate_routing_table()

    def _rx_save_routing_data(self, msg, interface_name):
        route_recalc_required = True
        sender_id = msg["id"]
        if not sender_id in self._rtd["interfaces"][interface_name]["rx-msg-db"]:
            # new entry (never seen before) or outdated comes
            # back again
            self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id] = dict()
        else:
            # existing entry from neighbor
            last_msg = self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id]["msg"]
            seq_no_last = last_msg['sequence-no']
            seq_no_new = msg['sequence-no']
            if seq_no_new <= seq_no_last:
                # print("receive duplicate or outdated route packet -> ignore it")
                route_recalc_required = False
                return route_recalc_required
            data_equal = self._cmp_packets(last_msg, msg)
            if data_equal:
                # packet is identical, we must save the last packet (think update sequence no)
                # but a route recalculation is not required
                route_recalc_required = False
        now = self._get_time(priv_data=self._get_time_priv_data)
        self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id]['rx-time'] = now
        self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id]['msg'] = msg
        self.log.info(self._rtd["interfaces"])
        return route_recalc_required

    def next_hop_ip_addr(self, proto, router_id, iface_name):
        """ return the IPv4/IPv6 address of the sender of an routing message """
        if iface_name not in self._rtd["interfaces"]:
            raise InternalException("interface not configured: {}".format(iface_name))
        if router_id not in self._rtd["interfaces"][iface_name]['rx-msg-db']:
            self.log.warning("cannot calculate next_hop_addr because router id is not in "
                             " databse (anymore!)? id:{}".format(router_id))
            return None
        msg = self._rtd["interfaces"][iface_name]['rx-msg-db'][router_id]['msg']
        if proto == 'v4':
            return msg['originator-addr-v4']
        if proto == 'v6':
            return msg['originator-addr-v6']
        raise InternalException("only v4 or v6 supported: {}".format(proto))

    def _recalculate_routing_table(self):
        now = self._get_time(priv_data=self._get_time_priv_data)
        self.log.info("recalculate routing table", time=now)
        # see _routing_table_update() this is how the routing
        # table should look like and saved under
        # self._routing_table
        loss_flag = True
        bandwidth_flag = True
        self._routing_table = dict()
        neigh_routing_paths = dict()
        self.fib = dict()
        self.fib['low_loss'] = dict()
        self.fib['high_bandwidth'] = dict()
        self.fib['path_characteristics'] = dict()
        neigh_routing_paths = self._calc_neigh_routing_paths(neigh_routing_paths)
        if loss_flag == True:
            self._calc_fib_low_loss(neigh_routing_paths)
            self._calc_loss_routingtable()
        if bandwidth_flag == True:
            self._calc_fib_high_bandwidth(neigh_routing_paths)
            self._calc_bw_routingtable()
        self.log.debug(self.fib)
        self.log.debug(self._routing_table)
        # routing table calculated, now inform our "parent"
        # about the new routing table
        self._routing_table_update()

    def _calc_neigh_routing_paths(self, neigh_routing_paths):
        neigh_routing_paths['neighs'] = dict()
        neigh_routing_paths['othernode_paths'] = dict()
        neigh_routing_paths['othernode_paths']['high_bandwidth'] = dict()
        neigh_routing_paths['othernode_paths']['low_loss'] = dict()
        for interface_name, interface_data in self._rtd["interfaces"].items():
            for sender_name, sender_data_raw in interface_data["rx-msg-db"].items():
                sender_data = dict()
                sender_data = sender_data_raw.copy()
                neigh_routing_paths = self._add_all_neighs(interface_name, interface_data,
                                                           sender_name, sender_data_raw,
                                                           neigh_routing_paths)
                if len(sender_data['msg']['routingpaths']) > 0:
                    neigh_routing_paths = self._add_all_othernodes_loss(sender_name, sender_data,
                                                                        neigh_routing_paths)
                    neigh_routing_paths = self._add_all_othernodes_bw(sender_name, sender_data,
                                                                      neigh_routing_paths)
        self.log.debug(neigh_routing_paths)
        return neigh_routing_paths

    def _add_all_neighs(self, interface_name, interface_data, sender_name, sender_data, neigh_routing_paths):
        found_neigh = False
        if len(neigh_routing_paths['neighs']) > 0:
            for neigh_name, neigh_data in neigh_routing_paths['neighs'].items():
                if neigh_name == sender_name:
                    path_found = False
                    for neigh_path in neigh_data['paths']["{}>{}".
                            format(self._conf["id"], neigh_name)]:
                        if neigh_path == interface_name:
                            path_found = True
                            break
                    if path_found == False:
                        neigh_data['paths']["{}>{}".
                            format(self._conf["id"], neigh_name)].append(interface_name)
                    found_neigh = True
                    break
            if found_neigh == False:
                neigh_routing_paths = self._add_neigh_entries(interface_name, sender_name,
                                                              sender_data, neigh_routing_paths)
        else:
            neigh_routing_paths = self._add_neigh_entries(interface_name, sender_name,
                                                          sender_data, neigh_routing_paths)
        return neigh_routing_paths

    def _add_neigh_entries(self, interface_name, sender_name, sender_data, neigh_routing_paths):
        neigh_routing_paths['neighs'][sender_name] = {'next-hop': sender_name,
                                                      'networks': sender_data['msg']['networks'],
                                                      'paths': {"{}>{}".
                                                                    format(self._conf["id"], sender_name):
                                                                    [interface_name]}
                                                      }
        return neigh_routing_paths

    def _add_all_othernodes_bw(self, sender_name, sender_data, neigh_routing_paths):
        othernode_bw = dict()
        othernode_bw = neigh_routing_paths['othernode_paths']['high_bandwidth'].copy()
        if not sender_name in othernode_bw:
            othernode_bw[sender_name] = dict()
            othernode_bw[sender_name]['path_characteristics'] = dict()
        else:
            self.log.info('updating high bandwidth other nodes from the existing neighbour')
        othernode_bw[sender_name] = sender_data['msg']['routingpaths']['high_bandwidth'].copy()
        othernode_bw[sender_name]['path_characteristics'] = sender_data['msg']['routingpaths'][
            'path_characteristics'].copy()
        neigh_routing_paths['othernode_paths']['high_bandwidth'] = othernode_bw.copy()
        return neigh_routing_paths

    def _add_all_othernodes_loss(self, sender_name, sender_data, neigh_routing_paths):
        othernode_loss = dict()
        othernode_loss = neigh_routing_paths['othernode_paths']['low_loss'].copy()
        if not sender_name in othernode_loss:
            othernode_loss[sender_name] = dict()
            othernode_loss[sender_name]['path_characteristics'] = dict()
        else:
            self.log.info('updating low loss other nodes from the existing neighbour')
        othernode_loss[sender_name] = sender_data['msg']['routingpaths']['low_loss'].copy()
        othernode_loss[sender_name]['path_characteristics'] = sender_data['msg']['routingpaths'][
            'path_characteristics'].copy()
        neigh_routing_paths['othernode_paths']['low_loss'] = othernode_loss.copy()
        return neigh_routing_paths

    def _calc_fib_low_loss(self, neigh_routing_paths):
        weigh_loss = dict()
        compressedloss = dict()
        for neigh_name, neigh_data in neigh_routing_paths['neighs'].items():
            weigh_loss = self._loss_path_compression(neigh_data)
            compressedloss = self.add_loss_entry(neigh_name, neigh_data,
                                                 weigh_loss, compressedloss)
        self.fib['low_loss'] = compressedloss.copy()
        if len(neigh_routing_paths['othernode_paths']['low_loss']) > 0:
            self._calc_shortestloss_path(neigh_routing_paths)
        self._map_path_characteristics_loss(neigh_routing_paths)
        for i in range(2):
            self._add_self_to_neigh_losspathnumber()
        self._add_lossweight_to_dest()

    def _calc_fib_high_bandwidth(self, neigh_routing_paths):
        weigh_bandwidth = dict()
        compressedBW = dict()
        for neigh_name, neigh_data in neigh_routing_paths['neighs'].items():
            weigh_bandwidth = self._bandwidth_path_compression(neigh_data)
            compressedBW = self.add_bandwidth_entry(neigh_name, neigh_data,
                                                    weigh_bandwidth, compressedBW)
        self.fib['high_bandwidth'] = compressedBW.copy()
        if len(neigh_routing_paths['othernode_paths']['high_bandwidth']) > 0:
            self._calc_widestBW_path(neigh_routing_paths)
        self._map_path_characteristics_BW(neigh_routing_paths)
        for i in range(2):
            self._add_self_to_neigh_bandwidthpathnumber()
        self._add_bandwidthweight_to_dest()

    def _loss_path_compression(self, neigh_data):
        loss_dict = dict()
        for neigh_path_key, neigh_paths_name in neigh_data['paths'].items():
            for neigh_path_name in neigh_paths_name:
                for interface_name in self._conf['interfaces']:
                    if interface_name['name'] == neigh_path_name:
                        if len(loss_dict) > 0:
                            for path_name, path_weight in loss_dict.items():
                                if interface_name['link-characteristics']['loss'] < path_weight:
                                    loss_dict = dict()
                                    loss_dict[interface_name['name']] = interface_name['link-characteristics']['loss']
                        else:
                            loss_dict[interface_name['name']] = interface_name['link-characteristics']['loss']
                        break
        return loss_dict

    def _bandwidth_path_compression(self, neigh_data):
        bandwidth_dict = dict()
        for neigh_path_key, neigh_paths_name in neigh_data['paths'].items():
            for neigh_path_name in neigh_paths_name:
                for interface_name in self._conf['interfaces']:
                    if interface_name['name'] == neigh_path_name:
                        if len(bandwidth_dict) > 0:
                            for path_name, path_weight in bandwidth_dict.items():
                                if interface_name['link-characteristics']['bandwidth'] > path_weight:
                                    bandwidth_dict = dict()
                                    bandwidth_dict[interface_name['name']] = interface_name['link-characteristics'][
                                        'bandwidth']
                        else:
                            bandwidth_dict[interface_name['name']] = interface_name['link-characteristics']['bandwidth']
                        break
        return bandwidth_dict

    def add_loss_entry(self, neigh_name, neigh_data, weigh_loss, compressedloss):
        route = "{}>{}".format(self._conf["id"], neigh_name)
        compressedloss[neigh_name] = {'next-hop': neigh_data['next-hop'],
                                      'networks': neigh_data['networks']
                                      }
        for path_name, path_weight in weigh_loss.items():
            compressedloss[neigh_name]['weight'] = path_weight
            compressedloss[neigh_name]['paths'] = dict()
            compressedloss[neigh_name]['paths'][route] = path_name
        return compressedloss

    def add_bandwidth_entry(self, neigh_name, neigh_data, weigh_bandwidth, compressedBW):
        route = "{}>{}".format(self._conf["id"], neigh_name)
        compressedBW[neigh_name] = {'next-hop': neigh_data['next-hop'],
                                    'networks': neigh_data['networks']
                                    }
        for path_name, path_weight in weigh_bandwidth.items():
            compressedBW[neigh_name]['weight'] = path_weight
            compressedBW[neigh_name]['paths'] = dict()
            compressedBW[neigh_name]['paths'][route] = path_name
        return compressedBW

    def _calc_shortestloss_path(self, neigh_routing_paths):
        path_weight = dict()
        for node_name, node_data in neigh_routing_paths['othernode_paths']['low_loss'].items():
            for dest_name, dest_data in node_data.items():
                if dest_name != 'path_characteristics':
                    if dest_name == self._conf["id"]:
                        self.log.info('ignore self routing')
                    else:
                        weight_update = int(dest_data['weight']) + int(self.fib['low_loss'][node_name]['weight'])
                        loop_found = False
                        for path_name, path_value in dest_data['paths'].items():
                            if path_name[0] == self._conf["id"] or path_name[2] == self._conf["id"]:
                                loop_found = True
                                self.log.info('self_id in the path so avoiding looping')
                                break
                        if loop_found == False:
                            self.log.info('No loop will occur in this path')
                            self.add_shortestloss_path(weight_update, node_name, dest_name, dest_data)

    def add_shortestloss_path(self, weight_update, node_name, dest_name, dest_data):
        if not dest_name in self.fib['low_loss']:
            self.log.info('it is a new entry to destination')
            self.fib['low_loss'][dest_name] = dict()
            self._map_loss_values(node_name, weight_update, dest_name, dest_data)
        else:
            self.log.info('updating existing destination entry in fib')
            if weight_update < self.fib['low_loss'][dest_name]['weight']:
                self._map_loss_values(node_name, weight_update, dest_name, dest_data)

    def _map_loss_values(self, node_name, weight_update, dest_name, dest_data):
        data = self.fib['low_loss'][dest_name]
        data['networks'] = list()
        data['paths'] = dict()
        data['weight'] = weight_update
        data['next-hop'] = node_name
        data['networks'] = dest_data['networks'].copy()
        data['paths'] = dest_data['paths'].copy()

    def _calc_widestBW_path(self, neigh_routing_paths):
        path_weight = dict()
        for node_name, node_data in neigh_routing_paths['othernode_paths']['high_bandwidth'].items():
            for dest_name, dest_data in node_data.items():
                if dest_name != 'path_characteristics':
                    if dest_name == self._conf["id"]:
                        self.log.info('ignore self routing')
                    else:
                        weight_update = int(dest_data['weight']) + int(self.fib['high_bandwidth'][node_name]['weight'])
                        loop_found = False
                        for path_name, path_value in dest_data['paths'].items():
                            if path_name[0] == self._conf["id"] or path_name[2] == self._conf["id"]:
                                loop_found = True
                                self.log.info('self_id in the path so avoiding looping')
                                break
                        if loop_found == False:
                            self.log.info('No loop will occur in this path')
                            self.add_widestBW_path(weight_update, node_name, dest_name, dest_data)

    def add_widestBW_path(self, weight_update, node_name, dest_name, dest_data):
        if not dest_name in self.fib['high_bandwidth']:
            self.log.info('it is a new entry to destination')
            self.fib['high_bandwidth'][dest_name] = dict()
            self._map_BW_values(node_name, weight_update, dest_name, dest_data)
        else:
            if weight_update < self.fib['high_bandwidth'][dest_name]['weight']:
                self.log.info('updating existing destination entry in fib')
                self._map_BW_values(node_name, weight_update, dest_name, dest_data)

    def _map_BW_values(self, node_name, weight_update, dest_name, dest_data):
        data = self.fib['high_bandwidth'][dest_name]
        data['networks'] = list()
        data['paths'] = dict()
        data['next-hop'] = node_name
        data['weight'] = weight_update
        data['networks'] = dest_data['networks'].copy()
        data['paths'] = dest_data['paths'].copy()

    def _map_path_characteristics_loss(self, neigh_routing_paths):
        path_num = 1
        for dest_name, dest_data in self.fib['low_loss'].items():
            next_hop = dest_data['next-hop']
            path_num_found = False
            if dest_name != next_hop:
                self.log.info('This is not neighbour destination-loss')
                for path_dir, path_name in dest_data['paths'].items():
                    for path_number, path_data in neigh_routing_paths['othernode_paths']['low_loss'][next_hop][
                        'path_characteristics'].items():
                        if path_name == path_number:
                            path_num_found = True
                            path_num_new = self._map_path_number(path_data, path_num)
                            break
                    if path_num_found == True:
                        dest_data['paths'][path_dir] = path_num_new
            if dest_name == next_hop:
                self.log.info('This is neighbour destination-loss')
                for path_dir, path_name in dest_data['paths'].items():
                    for interface in self._conf['interfaces']:
                        if interface['name'] == path_name:
                            path_num_found = True
                            path_data = dict()
                            path_data['loss'] = interface['link-characteristics']['loss']
                            path_data['bandwidth'] = interface['link-characteristics']['bandwidth']
                            path_num_new = self._map_path_number(path_data, path_num)
                            break
                    if path_num_found == True:
                        dest_data['paths'][path_dir] = path_num_new

    def _map_path_characteristics_BW(self, neigh_routing_paths):
        path_num = 1
        for dest_name, dest_data in self.fib['high_bandwidth'].items():
            next_hop = dest_data['next-hop']
            path_num_found = False
            if dest_name != next_hop:
                self.log.info('This is not neighbour destination-BW')
                for path_dir, path_name in dest_data['paths'].items():
                    for path_number, path_data in neigh_routing_paths['othernode_paths']['high_bandwidth'][next_hop][
                        'path_characteristics'].items():
                        if path_name == path_number:
                            path_num_found = True
                            path_num_new = self._map_path_number(path_data, path_num)
                            break
                    if path_num_found == True:
                        dest_data['paths'][path_dir] = path_num_new
            if dest_name == next_hop:
                self.log.info('This is neighbour destination-BW')
                for path_dir, path_name in dest_data['paths'].items():
                    for interface in self._conf['interfaces']:
                        if interface['name'] == path_name:
                            path_num_found = True
                            path_data = dict()
                            path_data['loss'] = interface['link-characteristics']['loss']
                            path_data['bandwidth'] = interface['link-characteristics']['bandwidth']
                            path_num_new = self._map_path_number(path_data, path_num)
                            break
                    if path_num_found == True:
                        dest_data['paths'][path_dir] = path_num_new

    def _map_path_number(self, path_data, path_num):
        path_char_found = False
        for fib_path_name, fib_path_data in self.fib['path_characteristics'].items():
            if (path_data['loss'] == fib_path_data['loss']) and (path_data['bandwidth'] == fib_path_data['bandwidth']):
                self.log.info('This is already existing path cahracteristic')
                path_num_new = fib_path_name
                path_char_found = True
                break
        if path_char_found == False:
            while True:
                if not str(path_num) in self.fib['path_characteristics']:
                    path_num_new = str(path_num)
                    self.log.info('This path number is unique')
                    break
                else:
                    path_num += 1
            self.fib['path_characteristics'][path_num_new] = path_data
        return path_num_new

    def _add_self_to_neigh_losspathnumber(self):
        for dest_name, dest_data in self.fib['low_loss'].items():
            next_hop = dest_data['next-hop']
            if dest_name != next_hop:
                for path_dir, path_name in self.fib['low_loss'][next_hop]['paths'].items():
                    self.fib['low_loss'][dest_name]['paths'][path_dir] = path_name

    def _add_self_to_neigh_bandwidthpathnumber(self):
        for dest_name, dest_data in self.fib['high_bandwidth'].items():
            next_hop = dest_data['next-hop']
            if dest_name != next_hop:
                for path_dir, path_name in self.fib['high_bandwidth'][next_hop]['paths'].items():
                    self.fib['high_bandwidth'][dest_name]['paths'][path_dir] = path_name

    def _add_lossweight_to_dest(self):
        for dest_name, dest_data in self.fib['low_loss'].items():
            self.fib['low_loss'][dest_name]['weight'] = 0
            for path_dir, path_name in dest_data['paths'].items():
                for path_name_fib, path_data_fib in self.fib['path_characteristics'].items():
                    if path_name == path_name_fib:
                        self.fib['low_loss'][dest_name]['weight'] = self.fib['low_loss'][dest_name]['weight'] + \
                                                                    path_data_fib['loss']
                        break

    def _add_bandwidthweight_to_dest(self):
        for dest_name, dest_data in self.fib['high_bandwidth'].items():
            self.fib['high_bandwidth'][dest_name]['weight'] = 0
            for path_dir, path_name in dest_data['paths'].items():
                for path_name_fib, path_data_fib in self.fib['path_characteristics'].items():
                    if path_name == path_name_fib:
                        self.fib['high_bandwidth'][dest_name]['weight'] = self.fib['high_bandwidth'][dest_name][
                                                                              'weight'] + path_data_fib['bandwidth']
                        break

    def _calc_loss_routingtable(self):
        self._routing_table['lowest-loss'] = list()
        for dest_name, dest_data in self.fib['low_loss'].items():
            for network in dest_data['networks']:
                loss_entry = dict()
                for prefix_type, prefix_ip in network.items():
                    loss_entry['proto'] = "v4"
                    ip_pref_len = prefix_ip.split("/")
                    loss_entry['prefix'] = ip_pref_len[0]
                    loss_entry['prefix-len'] = ip_pref_len[1]
                search_key = '{}>{}'.format(self._conf["id"], dest_data['next-hop'])
                for path_dir, path_name in dest_data['paths'].items():
                    if path_dir == search_key:
                        for fib_path_name, fib_path_data in self.fib['path_characteristics'].items():
                            if fib_path_name == path_name:
                                path_found = False
                                for interface in self._conf['interfaces']:
                                    path_char = dict()
                                    path_char = interface['link-characteristics']
                                    if path_char['loss'] == fib_path_data['loss'] and path_char['bandwidth'] == \
                                            fib_path_data['bandwidth']:
                                        path_found = True
                                        loss_entry['interface'] = interface['name']
                                        break
                                if path_found == True:
                                    break
                        break
                loss_entry['next-hop'] = self.next_hop_ip_addr(loss_entry['proto'], dest_data['next-hop'],
                                                               loss_entry['interface'])
                self._routing_table['lowest-loss'].append(loss_entry)

    def _calc_bw_routingtable(self):
        self._routing_table['highest-bandwidth'] = list()
        for dest_name, dest_data in self.fib['high_bandwidth'].items():
            for network in dest_data['networks']:
                bw_entry = dict()
                for prefix_type, prefix_ip in network.items():
                    bw_entry['proto'] = "v4"
                    ip_pref_len = prefix_ip.split("/")
                    bw_entry['prefix'] = ip_pref_len[0]
                    bw_entry['prefix-len'] = ip_pref_len[1]
                search_key = '{}>{}'.format(self._conf["id"], dest_data['next-hop'])
                path_found = False
                for path_dir, path_name in dest_data['paths'].items():
                    if path_dir == search_key:
                        for fib_path_name, fib_path_data in self.fib['path_characteristics'].items():
                            if fib_path_name == path_name:
                                path_found = False
                                for interface in self._conf['interfaces']:
                                    path_char = dict()
                                    path_char = interface['link-characteristics']
                                    if path_char['loss'] == fib_path_data['loss'] and path_char['bandwidth'] == \
                                            fib_path_data['bandwidth']:
                                        path_found = True
                                        bw_entry['interface'] = interface['name']
                                        break
                                if path_found == True:
                                    break
                        break
                if path_found:
                    bw_entry['next-hop'] = self.next_hop_ip_addr(bw_entry['proto'], dest_data['next-hop'],
                                                                 bw_entry['interface'])
                    self._routing_table['highest-bandwidth'].append(bw_entry)

    def register_get_time_cb(self, function, priv_data=None):
        self._get_time = function
        self._get_time_priv_data = priv_data

    def register_routing_table_update_cb(self, function, priv_data=None):
        self._routing_table_update_func = function
        self._routing_table_update_func_priv_data = priv_data

    def register_msg_tx_cb(self, function, priv_data=None):
        """ when a DMPR packet must be transmitted
        the surrounding framework must register this
        function. The prototype for the function should look like:
        func(interface_name, proto, dst_mcast_addr, packet)
        """
        self._packet_tx_func = function
        self._packet_tx_func_priv_data = priv_data

    def _routing_table_update(self):
        """ return the calculated routing tables in the following form:
             {
             "lowest-loss" : [
                { "proto" : "v4", "prefix" : "10.10.0.0", "prefix-len" : "24", "next-hop" : "192.168.1.1", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.11.0.0", "prefix-len" : "24", "next-hop" : "192.168.1.2", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.12.0.0", "prefix-len" : "24", "next-hop" : "192.168.1.1", "interface" : "tetra0" },
             ]
             "highest-bandwidth" : [
                { "proto" : "v4", "prefix" : "10.10.0.0", "prefix-len" : "24", "next-hop" : "192.168.1.1", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.11.0.0", "prefix-len" : "24", "next-hop" : "192.168.1.2", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.12.0.0", "prefix-len" : "24", "next-hop" : "192.168.1.1", "interface" : "tetra0" },
             ]
             }
        """
        self._routing_table_update_func(self._routing_table,
                                        priv_data=self._routing_table_update_func_priv_data)

    def _packet_tx(self, msg):
        self._packet_tx_func(msg)
