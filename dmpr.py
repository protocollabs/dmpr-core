import random
import uuid


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
                if self._get_time() - vv["rx-time"] > self._conf["rtn_msg_hold_time"]:
                    msg = "outdated entry from {} received at {}, interface: {} - drop it"
                    self._log(msg.format(router_id, vv["rx-time"], interface), time=self._get_time())
                    dellist.append(router_id)
            for id_ in dellist:
                route_recalc_required = True
                del v[id_]
        return route_recalc_required


    def create_routing_msg(self, interface_name):
        packet = dict()
        packet['id'] = self._conf["id"]
        # add sequence number to packet ..
        packet['sequence-no'] = self._sequence_no(interface_name)
        # ... and increment number locally
        self._sequence_no_inc(interface_name)
        packet['networks'] = list()
        for network in self._conf["networks"]:
            if network["proto"] == "v4":
                ipstr = "{}/{}".format(network["prefix"], network["prefix-len"])
                packet['networks'].append({ "v4-prefix" : ipstr })
        return packet


    def tx_route_packet(self):
        # depending on local information the route
        # packets must be generated for each interface
        for interface_name in self._rtd["interfaces"]:
            msg = self.create_routing_msg(interface_name)
            v4_mcast_addr = self._conf["mcast-v4-tx-addr"]
            self._packet_tx_func(interface_name, "v4", v4_mcast_addr, msg)



    def tick(self, time):
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
        self.set_time(time)
        route_recalc_required = self._check_outdated_route_entries()
        if route_recalc_required:
            self._recalculate_routing_table()

        if self._get_time() >= self._next_tx_time:
            self.tx_route_packet()
            self._calc_next_tx_time()
            self.transmitted_now = True
        else:
            self.transmitted_now = False


    def _get_time(self):
        return self._time


    def set_time(self, time):
        self._time = time


    def stop(self, init=False):
        self._started = False
        if not init:
            # this function is also called in the
            # constructor, so do not print stop when
            # we never started
            self.log("stop DMPR core", time=self._get_time())
        self._routing_table = None
        self._next_tx_time = None


    def start(self, time):
        self.log.info("start DMPR core", time=self._get_time())
        assert(time != None)
        self.set_time(time)
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


    def _sequence_no(self, interface_name):
        return self._rtd["interfaces"][interface_name]["sequence-no-tx"]


    def _sequence_no_inc(self, interface_name):
        self._rtd["interfaces"][interface_name]["sequence-no-tx"] += 1


    def _calc_next_tx_time(self):
        interval = int(self._conf["rtn-msg-interval"])
        if self._next_tx_time == None:
            # we start to the first time or after a
            # restart, so do not wait interval seconds, this
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
                eq = eq and compare_dictionaries(dict1[key],dict2[key])
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


    def packet_rx(self, msg, interface_name):
        """ receive routing packet in json encoded
             data format """
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
            last_msg = self._rtd["interfaces"][interface_name]["rx-msg-db"][sender_id]["pkt"]
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

        # for now recalculate route table at every received packet, later we
        # will only recalculate when data has changed
        return route_recalc_required

    def _recalculate_routing_table(self):
        self.log.info("recalculate routing table", time=self._get_time())
        # see _routing_table_update() this is how the routing
        # table should look like and saved under
        # self._routing_table



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
                { "proto" : "v4", "prefix" : "10.10.0.0", "prefix-len" : 24, "next-hop" : "192.168.1.1", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.11.0.0", "prefix-len" : 24, "next-hop" : "192.168.1.2", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.12.0.0", "prefix-len" : 24, "next-hop" : "192.168.1.1", "interface" : "tetra0" },
             ]
             "highest-bandwidth" : [
                { "proto" : "v4", "prefix" : "10.10.0.0", "prefix-len" : 24, "next-hop" : "192.168.1.1", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.11.0.0", "prefix-len" : 24, "next-hop" : "192.168.1.2", "interface" : "wifi0" },
                { "proto" : "v4", "prefix" : "10.12.0.0", "prefix-len" : 24, "next-hop" : "192.168.1.1", "interface" : "tetra0" },
             ]
             }
        """
        self._routing_table_update_func(self._routing_table)

    def _packet_tx(self, msg):
        self._packet_tx_func(msg)

