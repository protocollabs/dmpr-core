import random
import uuid
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


class DMPR(object):

    def __init__(self, log=None):
        assert(log)
        self._conf = None
        self._time = None
        self.log = log
        self.stop(init=True)


    def register_configuration(self, configuration):
        """ register and setup configuration. Raise
            an error when values are wrongly configured """
        assert(configuration)
        assert isinstance(configuration, dict)
        self.process_conf(configuration)


    def process_conf(self, configuration):
        """ convert external python dict configuration
            into internal configuration and check values """
        assert(configuration)
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
                self.log.warning(msg, time=self._get_time())
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
                if self._get_time() - vv["rx-time"] > int(self._conf["rtn-msg-hold-time"]):
                    msg = "outdated entry from {} received at {}, interface: {} - drop it"
                    self.log.debug(msg.format(router_id, vv["rx-time"], interface),
                                   time=self._get_time())
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
                packet['networks'].append({ "v4-prefix" : ipstr })
        packet['routingpaths'] = dict()
        if len(self.fib['high_bandwidth'])>0 or len(self.fib['low_loss'])>0:
           packet['routingpaths']=self.fib.copy()
        return packet


    def tx_route_packet(self):
        # depending on local information the route
        # packets must be generated for each interface
        for interface_name in self._rtd["interfaces"]:
            msg = self.create_routing_msg(interface_name)
            self.log.info(msg)
            v4_mcast_addr = self._conf["mcast-v4-tx-addr"]
            self._packet_tx_func(interface_name, "v4", v4_mcast_addr, msg)



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

        if self._get_time() >= self._next_tx_time:
            self.tx_route_packet()
            self._calc_next_tx_time()
            self.transmitted_now = True
        else:
            self.transmitted_now = False


    def stop(self, init=False):
        self._started = False
        if not init:
            # this function is also called in the
            # constructor, so do not print stop when
            # we never started
            self.log.warning("stop DMPR core", time=self._get_time())
        self._routing_table = None
        self._next_tx_time = None


    def start(self):
        self.log.info("start DMPR core", time=self._get_time())
        assert(self._get_time)
        assert(self._routing_table_update_func)
        assert(self._packet_tx_func)
        assert(self._conf)
        assert(self._routing_table == None)
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
        self._next_tx_time = self._get_time() + waittime
        self.log.debug("schedule next transmission for {} seconds".format(self._next_tx_time), time=self._get_time())


    def _is_valid_interface(self, interface_name):
        found = False
        for interface in self._conf["interfaces"]:
            if interface_name == interface["name"]:
                found = True
        return found


    def _validate_rx_msg(self, msg, interface_name):
        ok = self._is_valid_interface(interface_name)
        if not ok:
            emsg  = "{} is not a configured, thus valid interface name, "
            emsg += "ignore packet for now"
            self.log.error(emsg.format(interface_name), time=self._get_time())
        return ok


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
        print(msg)
        """ receive routing packet in json encoded
             data format """
        rxmsg = "rx route packet from {}, interface:{}, seq-no:{}"
        self.log.info(rxmsg.format(msg['id'], interface_name, msg['sequence-no']))
        ok = self._validate_rx_msg(msg, interface_name)
        if not ok:
            self.log.warning("packet corrupt, dropping it", time=self._get_time())
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
            seq_no_new  = msg['sequence-no']
            if seq_no_new <= seq_no_last:
                print("receive duplicate or outdated route packet -> ignore it")
                route_recalc_required = False
                return route_recalc_required
            data_equal = self._cmp_packets(last_msg, msg)
            if data_equal:
                # packet is identical, we must save the last packet (think update sequence no)
                # but a route recalculation is not required
                route_recalc_required = False
        self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id]['rx-time'] = self._get_time()
        self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id]['msg'] = msg
        self.log.info(self._rtd["interfaces"])
        return route_recalc_required


    def next_hop_addr(self, proto, router_id, iface_name):
        """ return the IPv4/IPv6 address of the sender of an routing message """
        if iface_name not in self._rtd["interfaces"]:
            raise InternalException("interface not configured: {}".format(iface_name))
        if router_id not in self._rtd["interfaces"][iface_name]:
            self.log.warning("cannot calculate next_hop_addr because router id is not in "
                             " databse (anymore!)? id:{}".format(router_id))
            return None
        msg = self._rtd["interfaces"][iface_name][router_id]['msg']
        if proto == 'v4':
            return msg['originator-addr-v4']
        if proto == 'v6':
            return msg['originator-addr-v6']
        raise InternalException("only v4 or v6 supported: {}".format(proto))


    def _recalculate_routing_table(self):
        self.log.info("recalculate routing table", time=self._get_time())
        # see _routing_table_update() this is how the routing
        # table should look like and saved under
        # self._routing_table
        loss_flag=True
        bandwidth_flag=True
        self._routing_table=dict()
        #self._routing_table['lowest-loss']=list
        self.neigh_routing_paths = dict()
        self.neigh_routing_paths['neighs']=dict()
        self.neigh_routing_paths['othernode_paths']=dict()
        self.neigh_routing_paths['othernode_paths']['high_bandwidth']=dict()
        self.neigh_routing_paths['othernode_paths']['low_loss']=dict()
        self.compressedloss=dict()
        self.compressedBW=dict()
        self.fib = dict()
        self.fib['low_loss'] = dict()
        self.fib['high_bandwidth'] = dict()
        self.fib['path_characteristics'] = dict()
        self._calc_neigh_routing_paths()
        if loss_flag==True:
           self._calc_fib_low_loss()
           self._calc_loss_routingtable()
        if bandwidth_flag==True:
           self._calc_fib_high_bandwidth()
           self._calc_bw_routingtable()
        self.log.debug(self.fib)
        self.log.debug(self._routing_table)


    def _calc_neigh_routing_paths(self):
        for key_i,value_i in self._rtd["interfaces"].items():
            for key_s,value_s_real in value_i["rx-msg-db"].items():
                value_s=dict()
                value_s=value_s_real.copy()
                self._add_all_neighs(key_i,value_i,key_s,value_s_real)
                if len(value_s['msg']['routingpaths'])>0:
                   self._add_all_othernodes(key_s,value_s,key_i)
        self.log.debug(self.neigh_routing_paths)


    def _add_all_neighs(self,key_i,value_i,key_s,value_s):
        found_neigh = False
        if len(self.neigh_routing_paths['neighs']) > 0:
           for key_r,value_r in self.neigh_routing_paths['neighs'].items():
               if key_r == key_s:
                  path_found = False
                  for valuevalue_r in value_r['paths']["{}>{}".format(self._conf["id"],key_r)]:
                      if valuevalue_r == key_i:
                         path_found = True
                         break
                  if path_found == False:
                     value_r['paths']["{}>{}".format(self._conf["id"],key_r)].append(key_i)
                  found_neigh = True
                  break
           if found_neigh == False:
              self._add_neigh_entries(key_s, key_i, value_s)
        else:
            self._add_neigh_entries(key_s, key_i, value_s)


    def _add_neigh_entries(self, key_s, key_i, value_s):
        self.neigh_routing_paths['neighs'][key_s] ={'next-hop':key_s,
                                                'networks':value_s['msg']['networks'],
                                                'paths':{"{}>{}".format(self._conf["id"],key_s):[key_i]}
                                               }


    def _add_all_othernodes(self,key_s,value_s,key_i):
        if not key_s in self.neigh_routing_paths['othernode_paths']['high_bandwidth']:
           self.neigh_routing_paths['othernode_paths']['high_bandwidth'][key_s] = dict()
           self.neigh_routing_paths['othernode_paths']['high_bandwidth'][key_s]['path_characteristics']=dict()
        else:
             self.log.info('updating high bandwidth other nodes from the existing neighbour')
        self.neigh_routing_paths['othernode_paths']['high_bandwidth'][key_s]=value_s['msg']['routingpaths']['high_bandwidth'].copy()
        self.neigh_routing_paths['othernode_paths']['high_bandwidth'][key_s]['path_characteristics']=value_s['msg']['routingpaths']['path_characteristics'].copy()
        if not key_s in self.neigh_routing_paths['othernode_paths']['low_loss']:
           self.neigh_routing_paths['othernode_paths']['low_loss'][key_s] = dict()
           self.neigh_routing_paths['othernode_paths']['low_loss'][key_s]['path_characteristics']=dict()
        else:
             self.log.info('updating low loss other nodes from the existing neighbour')
        self.neigh_routing_paths['othernode_paths']['low_loss'][key_s]=value_s['msg']['routingpaths']['low_loss'].copy()
        self.neigh_routing_paths['othernode_paths']['low_loss'][key_s]['path_characteristics']=value_s['msg']['routingpaths']['path_characteristics'].copy()


    def _calc_fib_low_loss(self):
        weigh_loss = dict()
        for key_n, value_n in self.neigh_routing_paths['neighs'].items():
            weigh_loss = self._loss_path_compression(key_n, value_n)
            self.add_loss_entry(key_n,value_n,weigh_loss)
        self.add_fib_lowloss_neighs()
        if len(self.neigh_routing_paths['othernode_paths']['low_loss']) > 0:
           self._calc_shortestloss_path()
        self._map_path_characteristics_loss()
        for i in range(2):
            self._add_self_to_neigh_losspath()
        self._add_lossweight_to_dest()


    def _calc_fib_high_bandwidth(self):
        weigh_bandwidth = dict()
        for key_n, value_n in self.neigh_routing_paths['neighs'].items():
            weigh_bandwidth = self._bandwidth_path_compression(key_n, value_n)
            self.add_bandwidth_entry(key_n,value_n,weigh_bandwidth)
        self.add_fib_highBW_neighs()
        if len(self.neigh_routing_paths['othernode_paths']['high_bandwidth']) > 0:
           self._calc_widestBW_path()
        self._map_path_characteristics_BW()
        for i in range(2):
            self._add_self_to_neigh_bandwidthpath()
        self._add_bandwidthweight_to_dest()


    def _loss_path_compression(self,key_n,value_n):
         loss_dict = dict()
         for key,value in value_n['paths'].items():
             for valuevalue in value:
                 for key_path in self._conf['interfaces']:
                     if key_path['name']==valuevalue:
                        if len(loss_dict)>0:
                           for key_l,value_l in loss_dict.items():
                               if key_path['link-characteristics']['loss']<value_l:
                                  loss_dict=dict()
                                  loss_dict[key_path['name']]=key_path['link-characteristics']['loss']
                        else:
                           loss_dict[key_path['name']]=key_path['link-characteristics']['loss']
                        break
         return loss_dict


    def _bandwidth_path_compression(self,key_n,value_n):
         bandwidth_dict = dict()
         for key,value in value_n['paths'].items():
             for valuevalue in value:
                 for key_path in self._conf['interfaces']:
                     if key_path['name']==valuevalue:
                        if len(bandwidth_dict)>0:
                           for key_l,value_l in bandwidth_dict.items():
                               if key_path['link-characteristics']['bandwidth']>value_l:
                                  bandwidth_dict=dict()
                                  bandwidth_dict[key_path['name']]=key_path['link-characteristics']['bandwidth']
                        else:
                           bandwidth_dict[key_path['name']]=key_path['link-characteristics']['bandwidth']
                        break
         return bandwidth_dict


    def add_loss_entry(self,key_n,value_n,weigh_loss):
        route="{}>{}".format(self._conf["id"],key_n)
        self.compressedloss[key_n]={'next-hop':value_n['next-hop'],
                                     'networks':value_n['networks']
                                     }
        for key_w,value_w in weigh_loss.items():
            self.compressedloss[key_n]['weight']=value_w
            self.compressedloss[key_n]['paths']=dict()
            self.compressedloss[key_n]['paths'][route]=key_w


    def add_bandwidth_entry(self,key_n,value_n,weigh_bandwidth):
        route="{}>{}".format(self._conf["id"],key_n)
        self.compressedBW[key_n]={'next-hop':value_n['next-hop'],
                                  'networks':value_n['networks']
                                 }
        for key_w,value_w in weigh_bandwidth.items():
            self.compressedBW[key_n]['weight']=value_w
            self.compressedBW[key_n]['paths']=dict()
            self.compressedBW[key_n]['paths'][route]=key_w


    def add_fib_lowloss_neighs(self):
        if len(self.fib['low_loss'])>0:
           found_dest=False
           for key_node,value_node in self.compressedloss.items():
               for key_dest,value_dest in self.fib['low_loss'].items():
                   if key_dest==key_node:
                      value_dest=dict()
                      value_dest=value_node.copy()
                      found_dest=True
                      break
               if found_dest==False:
                  self.fib['low_loss'][key_node]=value_node.copy()
        else:
             self.fib['low_loss']=self.compressedloss.copy()


    def add_fib_highBW_neighs(self):
        if len(self.fib['high_bandwidth'])>0:
           found_dest=False
           for key_node,value_node in self.compressedloss.items():
               for key_dest,value_dest in self.fib['high_bandwidth'].items():
                   if key_dest==key_node:
                      value_dest=dict()
                      value_dest=value_node.copy()
                      found_dest=True
                      break
               if found_dest==False:
                  self.fib['high_bandwidth'][key_node]=value_node.copy()
        else:
             self.fib['high_bandwidth']=self.compressedBW.copy()


    def _calc_shortestloss_path(self):
        path_weight=dict()
        for key_neigh,value_neigh in self.neigh_routing_paths['othernode_paths']['low_loss'].items():
            for key_dest,value_dest in value_neigh.items():
                if key_dest != 'path_characteristics':
                   if key_dest==self._conf["id"]:
                      self.log.info('ignore self routing')
                   else:
                        weight_update=int(value_dest['weight'])+int(self.fib['low_loss'][key_neigh]['weight'])
                        loop_found=False
                        for key_path,value_path in value_dest['paths'].items():
                            if key_path[0]==self._conf["id"] or key_path[2]==self._conf["id"]:
                                loop_found=True
                                self.log.info('self_id in the path so avoiding looping')
                                break
                        if loop_found==False:
                            self.log.info('No loop will occur in this path')
                            self.add_shortestloss_path(weight_update,key_neigh,key_dest,value_dest)


    def add_shortestloss_path(self,weight_update,key_neigh,key_dest,value_dest):
        if not key_dest in self.fib['low_loss']:
           self.log.info('it is a new entry to destination')
           self.fib['low_loss'][key_dest]=dict()
           self._map_loss_values(key_neigh,weight_update,key_dest,value_dest)
        else:
             self.log.info('updating existing destination entry in fib')
             if weight_update<self.fib['low_loss'][key_dest]['weight']:
                self._map_loss_values(key_neigh,weight_update,key_dest,value_dest)


    def _map_loss_values(self,key_neigh,weight_update,key_dest,value_dest):
        self.fib['low_loss'][key_dest]['networks']=list()
        self.fib['low_loss'][key_dest]['paths']=dict()
        self.fib['low_loss'][key_dest]['weight']=weight_update
        self.fib['low_loss'][key_dest]['next-hop']=key_neigh
        self.fib['low_loss'][key_dest]['networks']=value_dest['networks'].copy()
        self.fib['low_loss'][key_dest]['paths']=value_dest['paths'].copy()


    def _calc_widestBW_path(self):
        path_weight=dict()
        for key_neigh,value_neigh in self.neigh_routing_paths['othernode_paths']['high_bandwidth'].items():
            for key_dest,value_dest in value_neigh.items():
                if key_dest != 'path_characteristics':
                   if key_dest==self._conf["id"]:
                      self.log.info('ignore self routing')
                   else:
                        weight_update=int(value_dest['weight'])+int(self.fib['high_bandwidth'][key_neigh]['weight'])
                        loop_found=False
                        for key_path,value_path in value_dest['paths'].items():
                            if key_path[0]==self._conf["id"] or key_path[2]==self._conf["id"]:
                               loop_found=True
                               self.log.info('self_id in the path so avoiding looping')
                               break
                        if loop_found==False:
                           self.log.info('No loop will occur in this path')
                           self.add_widestBW_path(weight_update,key_neigh,key_dest,value_dest)


    def add_widestBW_path(self,weight_update,key_neigh,key_dest,value_dest):
        if not key_dest in self.fib['high_bandwidth']:
           self.log.info('it is a new entry to destination')
           self.fib['high_bandwidth'][key_dest]=dict()
           self._map_BW_values(key_neigh,weight_update,value_dest,key_dest)
        else:
             if weight_update<self.fib['high_bandwidth'][key_dest]['weight']:
                self.log.info('updating existing destination entry in fib')
                self._map_BW_values(key_neigh,weight_update,value_dest,key_dest)


    def _map_BW_values(self,key_neigh,weight_update,value_dest,key_dest):
        data = self.fib['high_bandwidth'][key_dest]
        data['networks']=list()
        data['paths']=dict()
        data['next-hop']=key_neigh
        data['weight']=weight_update
        data['networks']=value_dest['networks'].copy()
        data['paths']=value_dest['paths'].copy()


    def _map_path_characteristics_loss(self):
        path_num=1
        for key_dest,value_dest in self.fib['low_loss'].items():
            next_hop=value_dest['next-hop']
            path_num_found=False
            if key_dest!=next_hop:
               self.log.info('This is not neighbour destination-loss')
               for key_path,value_path in value_dest['paths'].items():
                   for key_char,value_char in self.neigh_routing_paths['othernode_paths']['low_loss'][next_hop]['path_characteristics'].items():
                       if value_path==key_char:
                          path_num_found=True
                          path_num_new=self._map_path_number(value_char,path_num)
                          break
                   if path_num_found==True:
                      value_dest['paths'][key_path]=path_num_new
            if key_dest==next_hop:
               self.log.info('This is neighbour destination-loss')
               for key_path,value_path in value_dest['paths'].items():
                   for p in self._conf['interfaces']:
                       if p['name']==value_path:
                          path_num_found=True
                          value_char=dict()
                          value_char['loss']=p['link-characteristics']['loss']
                          value_char['bandwidth']=p['link-characteristics']['bandwidth']
                          path_num_new=self._map_path_number(value_char,path_num)
                          break
                   if path_num_found==True:
                      value_dest['paths'][key_path]=path_num_new


    def _map_path_characteristics_BW(self):
        path_num=1
        for key_dest,value_dest in self.fib['high_bandwidth'].items():
            next_hop=value_dest['next-hop']
            path_num_found=False
            if key_dest!=next_hop:
               self.log.info('This is not neighbour destination-BW')
               for key_path,value_path in value_dest['paths'].items():
                   for key_char,value_char in self.neigh_routing_paths['othernode_paths']['high_bandwidth'][next_hop]['path_characteristics'].items():
                       if value_path==key_char:
                          path_num_found=True
                          path_num_new=self._map_path_number(value_char,path_num)
                          break
                   if path_num_found==True:
                      value_dest['paths'][key_path]=path_num_new
            if key_dest==next_hop:
                 self.log.info('This is neighbour destination-BW')
                 for key_path,value_path in value_dest['paths'].items():
                     for p in self._conf['interfaces']:
                         if p['name']==value_path:
                            path_num_found=True
                            value_char=dict()
                            value_char['loss']=p['link-characteristics']['loss']
                            value_char['bandwidth']=p['link-characteristics']['bandwidth']
                            path_num_new=self._map_path_number(value_char,path_num)
                            break
                     if path_num_found==True:
                        value_dest['paths'][key_path]=path_num_new


    def _map_path_number(self,value_char,path_num):
        path_char_found=False
        for key_fib,value_fib in self.fib['path_characteristics'].items():
            if (value_char['loss']==value_fib['loss']) and (value_char['bandwidth']==value_fib['bandwidth']):
               self.log.info('This is already existing path cahracteristic')
               path_num_new=key_fib
               path_char_found=True
               break
        if path_char_found==False:
           while True:
                 if not str(path_num) in self.fib['path_characteristics']:
                    path_num_new=str(path_num)
                    self.log.info('This path number is unique')
                    break
                 else:
                      path_num+=1
           self.fib['path_characteristics'][path_num_new]=value_char
        return path_num_new


    def _add_self_to_neigh_losspath(self):
        for key_dest,value_dest in self.fib['low_loss'].items():
            next_hop=value_dest['next-hop']
            if key_dest!=next_hop:
               for key_i,value_i in self.fib['low_loss'][next_hop]['paths'].items():
                   self.fib['low_loss'][key_dest]['paths'][key_i]=value_i


    def _add_self_to_neigh_bandwidthpath(self):
        for key_dest,value_dest in self.fib['high_bandwidth'].items():
            next_hop=value_dest['next-hop']
            if key_dest!=next_hop:
               for key_i,value_i in self.fib['high_bandwidth'][next_hop]['paths'].items():
                   self.fib['high_bandwidth'][key_dest]['paths'][key_i]=value_i


    def _add_lossweight_to_dest(self):
        for key_dest,value_dest in self.fib['low_loss'].items():
            self.fib['low_loss'][key_dest]['weight']=0
            for key_path,value_path in value_dest['paths'].items():
                for key_char,value_char in self.fib['path_characteristics'].items():
                    if value_path==key_char:
                       self.fib['low_loss'][key_dest]['weight']=self.fib['low_loss'][key_dest]['weight']+value_char['loss']
                       break


    def _add_bandwidthweight_to_dest(self):
        for key_dest,value_dest in self.fib['high_bandwidth'].items():
            self.fib['high_bandwidth'][key_dest]['weight']=0
            for key_path,value_path in value_dest['paths'].items():
                for key_char,value_char in self.fib['path_characteristics'].items():
                    if value_path==key_char:
                       self.fib['high_bandwidth'][key_dest]['weight']=self.fib['high_bandwidth'][key_dest]['weight']+value_char['bandwidth']
                       break


    def _calc_loss_routingtable(self):
        self._routing_table['lowest-loss']=list()
        for key_dest,value_dest in self.fib['low_loss'].items():
            for i in value_dest['networks']:
               loss_entry=dict()
               for key_prefix,value_prefix in i.items():
                   loss_entry['proto'] = "v4"
                   ip_pref_len = value_prefix.split("/")
                   loss_entry['prefix'] = ip_pref_len[0]
                   loss_entry['prefix-len'] = ip_pref_len[1]
                   loss_entry['next-hop'] = value_dest['next-hop'] 
               search_key='{}>{}'.format(self._conf["id"],loss_entry['next-hop'])
               for key_i,value_i in value_dest['paths'].items():
                   if key_i==search_key:
                      for key_fib,value_fib in self.fib['path_characteristics'].items():
                          if key_fib==value_i:
                             path_found=False
                             for p in self._conf['interfaces']:
                                 q=dict()
                                 q=p['link-characteristics']
                                 if q['loss']==value_fib['loss'] and q['bandwidth']==value_fib['bandwidth']:
                                    path_found=True
                                    loss_entry['interface']=p['name']
                                    break
                             if path_found==True:
                                break
                      break
               self._routing_table['lowest-loss'].append(loss_entry)


    def _calc_bw_routingtable(self):
        self._routing_table['highest-bandwidth']=list()
        for key_dest,value_dest in self.fib['high_bandwidth'].items():
            for i in value_dest['networks']:
               loss_entry=dict()
               for key_prefix,value_prefix in i.items():
                   loss_entry['proto'] = "v4"
                   ip_pref_len = value_prefix.split("/")
                   loss_entry['prefix'] = ip_pref_len[0]
                   loss_entry['prefix-len'] = ip_pref_len[1]
                   loss_entry['next-hop'] = value_dest['next-hop']    
               search_key='{}>{}'.format(self._conf["id"],loss_entry['next-hop'])
               for key_i,value_i in value_dest['paths'].items():
                   if key_i==search_key:
                      for key_fib,value_fib in self.fib['path_characteristics'].items():
                          if key_fib==value_i:
                             path_found=False
                             for p in self._conf['interfaces']:
                                 q=dict()
                                 q=p['link-characteristics']
                                 if q['loss']==value_fib['loss'] and q['bandwidth']==value_fib['bandwidth']:
                                    path_found=True
                                    loss_entry['interface']=p['name']
                                    break
                             if path_found==True:
                                break
                      break
               self._routing_table['highest-bandwidth'].append(loss_entry)


    def register_get_time_cb(self, function):
        self._get_time = function


    def register_routing_table_update_cb(self, function):
        self._routing_table_update_func = function


    def register_msg_tx_cb(self, function):
        """ when a DMPR packet must be transmitted
        the surrounding framework must register this
        function. The prototype for the function should look like:
        func(interface_name, proto, dst_mcast_addr, packet)
        """
        self._packet_tx_func = function


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
        self._routing_table_update_func(self._routing_table)


    def _packet_tx(self, msg):
        self._packet_tx_func(msg)

