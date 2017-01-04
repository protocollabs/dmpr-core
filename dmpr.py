import uuid

# example configuration for DMPR daemon
exa_conf = """
    "id" : "ace80ef4-d284-11e6-bf26-cec0c932ce01",
    "rtn_msg_interval" : "30",
    "rtn_msg_interval_jitter" : "7",
    "rtn_msg_hold_time" : "90",
    "interfaces" : [
      {"name" : "wlan0",  "link-characteristics" : { "bandwidth" : "100000", "loss" : "0"  } },
      {"name" : "tetra0", "link-characteristics" : { "bandwidth" : "10000",  "loss" : "0"  } }
    ],
    "networks" : [
       { "proto": "v4", "prefix" : "192.168.1.0", "prefix_len" : "24" },
       { "proto": "v4", "prefix" : "192.168.2.0", "prefix_len" : "24" },
       { "proto": "v4", "prefix" : "10.10.0.0",   "prefix_len" : "16" },
       { "proto": "v6", "prefix" : "fdcb:523:1111::", "prefix_len" : "48" },
       { "proto": "v6", "prefix" : "fd6a:6ad:b07f:ffff::", "prefix_len" : "64" }
    }
"""

class ConfigurationException(Exception): pass

class DMPRConfigDefaults(object):
    rtn_msg_interval = "30"
    rtn_msg_interval_jitter = str(int(RTN_MSG_INTERVAL / 4))
    rtn_msg_hold_time = str(RTN_MSG_INTERVAL * 3)

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

    @staticmethod
    def get(name):
        return getattr(self, name)


def id_generator:
    return str(uuid.uuid1())

class DMPR(object):

    def __init__(self, log):
        self.conf = None
        self.log = log

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
        self.conf = {}
        cmd = "rtn_msg_interval"
        self.conf[cmd] = configuration.get(cmd, DMPRConfigDefaults.get(cmd))
        cmd = "rtn_msg_interval_jitter"
        self.conf[cmd] = configuration.get(cmd, DMPRConfigDefaults.get(cmd))
        cmd = "rtn_msg_hold_time"
        self.conf[cmd] = configuration.get(cmd, DMPRConfigDefaults.get(cmd))
        if "id" not in configuration:
            msg = "configuration contains no id! A id must be unique, it can be
                   randomly generated but for better performance and debugging
                   capabilities this generated ID should be saved permanently
                   (e.g. at a local file) to survive daemon restarts"
            raise ConfigurationException(msg)
        if not isinstance(self.conf[cmd], str):
            msg = "id must be a string!"
            raise ConfigurationException(msg)
        if not "interfaces" in configuration:
            msg = "No interface configurated, need at least one"
            raise ConfigurationException(msg)
        self.conf["interfaces"] = configuration["interfaces"]
        if not isinstance(self.conf["interfaces"], list):
            msg = "interfaces must be a list!"
            raise ConfigurationException(msg)
        for interface_data in self.conf["interfaces"]:
            if not isinstance(interface_data, dict):
                msg = "interface entry must be dict: {}".format(interface_data)
                raise ConfigurationException(msg)
            if "name" not in interface_data:
                msg = "interfaces entry must contain at least a \"name\""
                raise ConfigurationException(msg)
            if "link-characteristics" not in interface_data:
                msg = "interfaces has no link characterstics, default some \"link-characteristics\""
                self.log.warning(msg)
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
                if not "prefix_len" in network:
                    msg = "network must contain prefix_len key: {}".format(network)
                    raise ConfigurationException(msg)
            # seens fine, save it as it is
            self.conf["networks"] = configuration["networks"]

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
        pass
        

    def stop(self):
        self.log("stop DMPR core")
        self.routing_table = None
        pass

    def start(self):
        self.log("start DMPR core")
        assert(self._routing_table_update_func)
        assert(self._packet_tx_func)
        pass

    def restart(self):
        self.stop()
        self.start()

    def _is_valid_interface(self, interface_name):
        if no interface_name in self.conf["interfaces"]:
            return False
        return True

    def packet_rx(self, packet_payload, interface_name):
        """ receive routing packet in json encoded
             data format """
        ok = self._is_valid_interface(interface_name)
        if not ok:
            msg  = "{} is not a configured, thus valid interface name, "
            msg += "ignore packet for now"
            self.log.error(msg.format(interface_name))
            return
        pass

    def register_routing_table_update(self, function):
        self._routing_table_update_func = function

    def register_packet_tx(self, function):
        """ when a DMPR packet must be transmitted
             the surrounding framework must register this
             function """
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
        self._routing_table_update_func(self.routing_table)

    def _packet_tx(self, packet_payload):
        self._packet_tx_func(packet_payload)

