import uuid

class ConfigurationException(Exception): pass

class DMPRConfigDefaults(object):
    RTN_MSG_INTERVAL = 30
    RTN_MSG_INTERVAL_JITTER = int(RTN_MSG_INTERVAL / 4)
    # plus 1 here is a pratical "hack", just to make sure
    # it is always removed later. Normally this is not required
    # but for simulation environment with a seconds granularity
    # things are different.
    RTN_MSG_HOLD_TIME = RTN_MSG_INTERVAL * 3 + 1

    @staticmethod
    def get(name):
        return getattr(self, name)


def id_generator:
    return str(uuid.uuid1())

class DMPR(object):

    def __init__(self, log):
        self.conf = None
        self.log = log

    def register_configuration(self, conf):
        """ register and setup configuration. Raise
            an error when values are wrongly configured """
        assert(conf)
        assert isinstance(conf, dict)
        self.configuration = conf
        self.process_conf()

    def process_conf(self):
        """ convert external python dict configuration
            into internal configuration and check values """
        assert(self.configuration)
        self.conf = {}
        cmd = "RTN_MSG_INTERVAL"
        self.conf[cmd] = self.configuration.get(cmd, DMPRConfigDefaults.get(cmd))
        cmd = "RTN_MSG_INTERVAL_JITTER"
        self.conf[cmd] = self.configuration.get(cmd, DMPRConfigDefaults.get(cmd))
        cmd = "RTN_MSG_HOLD_TIME"
        self.conf[cmd] = self.configuration.get(cmd, DMPRConfigDefaults.get(cmd))
        if "id" not in self.configuration:
            msg = "configuration contains no id! A id must be unique, it can be
                   randomly generated but for better performance and debugging
                   capabilities this generated ID should be saved permanently
                   (e.g. at a local file) to survive daemon restarts"
            raise ConfigurationException(msg)
        if not isinstance(self.conf[cmd], str):
            msg = "id must be a string!"
            raise ConfigurationException(msg)
        

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

    def packet_rx(self, packet_payload):
        """ receive routing packet in json encoded
             data format """
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

