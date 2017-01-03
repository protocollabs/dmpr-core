

class DMPR(object):

    def __init__(self, log):
        self.log = log

    def conf(self, conf):
        self.conf = conf

    def process_conf(self):
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

