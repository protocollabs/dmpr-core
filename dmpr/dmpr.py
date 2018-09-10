"""
The core of dmpr. This module holds the states and uses callbacks to
communicate with a daemon or the simulator.
"""
import collections
import logging
import random

from .config import DefaultConfiguration
from .exceptions import ConfigurationException, InvalidMessage, \
    InvalidPartialUpdate
from .message import Message
from .path import LinkAttributes, Path
from .policies import AbstractPolicy

logger = logging.getLogger(__name__)

FULL_MODE_ANALYSE_HISTORY = 10
FULL_MODE_TRIGGER_THRESH = 100
FULL_MODE_TIME = 1000


class NoOpTracer(object):
    def log(self, tracepoint, msg, time):
        pass


class DMPRState(object):
    """
    Encapsulate the state of the core, easy to reset and does not pollute the
    namespace of the DMPR class.
    """

    def __init__(self):
        self.seq_no = 0

        # routing data state
        self.update_required = False

        # Message handling state
        self.next_tx_time = None
        self.next_full_update = 0
        self.last_full_msg = {}

        self.request_full_update = [True]
        self.full_request_queue = collections.deque(
            maxlen=FULL_MODE_ANALYSE_HISTORY)
        self.full_only_mode = False


class DMPR(object):
    """
    The core class. Before starting the core, you must register a configuration
    with DMPR.register_configuration and at least one policy with
    DMPR.register_policy. Also to use it in any meaningful way the callbacks
    register_msg_tx_cb and register_routing_table_update_cb should be added.
    """

    def __init__(self, log=logger, tracer=NoOpTracer()):
        self.tracer = tracer
        self._logger = log
        self.log = logger

        self._started = False
        self._conf = None
        self.id = None
        self._get_time = self._dummy_cb
        self._routing_table_update_func = self._dummy_cb
        self._packet_tx_func = self._dummy_cb

        self.policies = []

        self._reset()

    #######################################
    #  runtime and configuration helpers  #
    #######################################

    def _reset(self):
        self.msg_db = {}
        self.routing_data = {}
        self.node_data = {}
        self.routing_table = {}
        self.networks = {
            'current': {},
            'retracted': {}
        }
        self.reflections = {}
        self.state = DMPRState()
        self.state.next_full_update = 0

    def stop(self):
        self._started = False
        self.log.info("stopping DMPR core")

    def start(self):
        if self._started:
            return

        if self._conf is None:
            msg = "Please register a configuration before starting"
            raise ConfigurationException(msg)
        self.log = self._logger.getChild(self.id)

        self.log.info("starting DMPR core")
        self._reset()

        for interface in self._conf['interfaces']:
            self.msg_db[self._conf['interfaces'][interface]['name']] = dict()

        self._calc_next_tx_time()
        self._started = True

    def restart(self):
        self.stop()
        self.start()

    def register_policy(self, policy: AbstractPolicy):
        if policy not in self.policies:
            self.policies.append(policy)

    def remove_policy(self, policy: AbstractPolicy):
        if policy in self.policies:
            self.policies.remove(policy)

    def register_configuration(self, configuration: dict):
        """
        register and setup configuration. Raise
        an error when values are wrongly configured
        restarts dmpr if it was running
        """
        self._conf = DefaultConfiguration.validate_config(configuration)

        self.trace('config.new', self._conf)

        self.id = self._conf['id']

        if self._started:
            self.log.info('configuration changed, restarting')
            self.restart()

    def register_get_time_cb(self, func: callable):
        """
        Register a callback for the given time, this functions
        must not need any arguments
        """
        self._get_time = func

    def register_routing_table_update_cb(self, func: callable):
        """
        Register a callback for route updates, the signature should be:
        function(routing_table: dict)
        """
        self._routing_table_update_func = func

    def register_msg_tx_cb(self, func: callable):
        """
        Register a callback for sending messages, the signature should be:
        function(interface: str, ipversion: str, mcast_addr: str, msg: dict)
        """
        self._packet_tx_func = func

    ##################
    #  dmpr rx path  #
    ##################

    def msg_rx(self, interface_name: str, msg: dict):
        """
        receive routing packet, save it in the message
        database and trigger all recalculations
        """

        # print("RX from {} msg {}\n".format(interface_name, msg))

        self.trace('rx.msg', msg)

        if interface_name not in self._conf['interfaces']:
            emsg = "interface {} is not configured, ignoring message"
            self.log.warning(emsg.format(interface_name))
            return

        if 'id' not in msg:
            return

        new_neighbor = msg['id'] not in self.msg_db[interface_name]
        try:
            if new_neighbor:
                interface = self._conf['interfaces'][interface_name]
                message = Message(msg, interface, self.id, self.now())
                self.msg_db[interface_name][msg['id']] = message
                self.state.update_required = True
            else:
                message = self.msg_db[interface_name][msg['id']]
                self.state.update_required |= message.apply_new_msg(msg,
                                                                    self.now())
        except InvalidMessage as e:
            self.log.debug("rx invalid message: {}".format(e))
            return
        except InvalidPartialUpdate:
            self.state.request_full_update.append(msg['id'])
            return

        self.trace('rx.msg.valid', msg)

        if 'request-full' in msg:
            self._process_full_requests(msg)

    def _process_full_requests(self, msg: dict):
        """
        Check the received request-full field for our id or True and
        schedule a full update if necessary
        """
        request = msg['request-full']
        if (isinstance(request, list) and self.id in request) or \
                (isinstance(request, bool) and request):
            self.state.next_full_update = 0
            self.state.full_request_queue.append(self.now())

    #######################
    #  Route Calculation  #
    #######################

    def recalculate_routing_data(self):
        self.trace('routes.recalc.before', {
            'routing-data': self.routing_data,
            'networks': self.networks,
            'routing-table': self.routing_table,
        })

        self.routing_data = {}
        self.node_data = {}

        for policy in self.policies:
            self._compute_routing_data(policy)
            self._compute_routing_table(policy)

        self._routing_table_update()

        self.trace('routes.recalc.after', {
            'routing-data': self.routing_data,
            'networks': self.networks,
            'routing-table': self.routing_table,
        })

    def _compute_routing_data(self, policy: AbstractPolicy):
        """
        compute new routing data based on all messages
        in the message database
        """

        routing_data = {}

        paths, networks, reflections = self._parse_msg_db(policy)
        self.reflections = reflections

        # for every node where there is a path to
        for node, node_paths in paths.items():
            node_paths = sorted(node_paths, key=policy.path_cmp_key)
            best_path = node_paths[0]

            routing_data[node] = {
                'path': best_path
            }
            if node not in networks:
                self.log.warning("No node data for target")
                continue

            # Merge all data of this node advertised by the different neighbors
            node_networks = self._merge_networks(networks[node])

            if not node_networks:
                continue

            node_entry = self.node_data.setdefault(node, {})
            node_networks_entry = node_entry.setdefault('networks', {})
            node_networks_entry.update(self._update_network_data(node_networks))

        self.routing_data[policy.name] = routing_data

    def _compute_routing_table(self, policy: AbstractPolicy):
        """
        compute a new routing table based on the routing data
        """
        routing_table = []

        routing_data = self.routing_data[policy.name]

        # Compute a routing table entry for every networf of every node
        for node, node_data in self.node_data.items():
            for network in node_data['networks']:
                if network in self.networks['retracted']:
                    # retracted network
                    continue
                if node not in routing_data:
                    continue

                path = routing_data[node]['path']

                if '.' in network:
                    version = 4
                else:
                    version = 6
                prefix, prefix_len = network.split('/')

                try:
                    next_hop_ip = self._node_to_ip(
                        path.next_hop_interface,
                        path.next_hop, version)
                except KeyError:
                    msg = "node {node} advertises IPv{version} network but " \
                          "has no IPv{version} address"
                    self.log.warning(msg.format(node=node,
                                                version=version))
                    continue

                routing_table.append({
                    'proto': 'v{}'.format(version),
                    'prefix': prefix,
                    'prefix-len': prefix_len,
                    'next-hop': next_hop_ip,
                    'interface': path.next_hop_interface,
                })

        self.routing_table[policy.name] = routing_table

    def _parse_msg_db(self, policy: AbstractPolicy) -> tuple:
        """
        parse the message database, for each reachable node
        accumulate all available nodes and paths in a list
        """
        paths = {}
        networks = {}
        reflections = {}

        # For reflections and networks, we only save the data of the newest
        # message, for paths we want to include all available paths
        newest_seq_no = {}
        for interface in self.msg_db:
            asymm_detection = self._conf['interfaces'][interface][
                'asymm-detection']

            for neighbor, msg in self.msg_db[interface].items():
                # Check for a reflected sequence number from our node.
                # Currently does not evaluate the actual sequence number
                # as we depend on the hold timer to remove unstable, but
                # sometimes symmetric links
                reflected_seq = (self.id in msg.reflected) and \
                                ('seq' in msg.reflected[self.id])
                if asymm_detection and not reflected_seq:
                    continue

                # Add the neighbor as path and node to our lists
                neighbor_paths = paths.setdefault(neighbor, [])
                path = self._get_neighbor_path(interface, neighbor)
                neighbor_paths.append(path)

                if msg.seq > newest_seq_no.get(neighbor, float('-inf')):
                    networks[neighbor] = [msg.networks]
                    if msg.reflect:
                        reflections[neighbor] = msg.reflect
                    newest_seq_no[neighbor] = msg.seq

                # Add all paths and nodes advertised by this neighbor
                # to our list
                routing_data = msg.routing_data.get(policy.name, {})
                for node, node_data in routing_data.items():
                    node_paths = paths.setdefault(node, [])
                    node_paths.append(node_data['path'])

                for node, node_data in msg.node_data.items():
                    node_networks = networks.setdefault(node, [])
                    node_networks.append(node_data['networks'])

        return paths, networks, reflections

    def _get_neighbor_path(self, interface_name: str, neighbor: str) -> Path:
        """
        Get the path to a direct neighbor
        """
        interface = self._conf['interfaces'][interface_name]
        path = Path(path=neighbor,
                    attributes=LinkAttributes(),
                    next_hop=neighbor,
                    next_hop_interface=interface_name)


        path.append(self.id, interface_name,
                    interface['link-attributes'])

        path.apply_attributes(LinkAttributes())
        return path

    @staticmethod
    def _merge_networks(networks: list) -> dict:
        """
        Merges a list of networks, retracted status overwrites not retracted
        """
        result = {}
        for item in networks:
            for network, network_data in item.items():
                if network_data is None:
                    network_data = {}
                if network not in result:
                    result[network] = network_data.copy()

                elif network_data.get('retracted', False):
                    result[network]['retracted'] = True

        return result

    def _update_network_data(self, networks: dict) -> dict:
        """
        Apply network retraction policy according to the following table:
in current | in retracted | msg retracted |
     0     |       0      |       0       | save in current, forward
     0     |       0      |       1       | ignore, don't forward
     0     |       1      |       0       | forward retracted
     0     |       1      |       1       | forward retracted
     1     |       0      |       0       | forward
     1     |       0      |       1       | del current, save in retracted, forward retracted
     1     |       1      |       0       | n/a
     1     |       1      |       1       | n/a

        networks in retracted and current will get deleted after a
        hold time, this hold time MUST be greater than the worst case
        propagation time for the retracted flag.

        This allows for network retraction by a node. The retracted
        status spreads through the network, overriding on all nodes
        while getting ignored on nodes which did not now this network
        previously.
        """
        result = {}

        current = self.networks['current']
        retracted = self.networks['retracted']

        for network, network_data in networks.items():
            msg_retracted = network_data.get('retracted', False)

            if msg_retracted:
                if network in retracted:
                    # network_data = copy.deepcopy(network_data)
                    network_data.update({'retracted': True})

                elif network in current:
                    del current[network]
                    retracted[network] = self.now()

                else:
                    continue

            else:
                if network in retracted:
                    # network_data = copy.deepcopy(network_data)
                    network_data.update({'retracted': True})

                else:
                    current[network] = self.now()

            result[network] = network_data

        return result

    ####################
    #  periodic ticks  #
    ####################

    def tick(self):
        """
        this function is called every second, DMPR will
        implement his own timer/timeout related functionality
        based on this ticker. This is not the most efficient
        way to implement timers but it is suitable to run in
        a real and simulated environment where time is discret.
        The argument time is a float value in seconds which should
        not used in a absolute manner, depending on environment this
        can be a unix timestamp or starting at 0 in simulation
        environments
        """
        if not self._started:
            # start() is not called, ignore this call
            return
        self.trace('tick', self.now())

        self._process_full_mode_queue()
        self.state.update_required |= self._clean_msg_db()
        self.state.update_required |= self._clean_networks()
        if self.state.update_required:
            self.state.update_required = False
            self.recalculate_routing_data()

        if self.now() >= self.state.next_tx_time:
            self.tx_route_packet()
            self._calc_next_tx_time()

    def _clean_msg_db(self) -> bool:
        """
        Iterates over all msg_db entries and purges all timed out entries
        """
        obsolete = []
        now = self.now()
        hold_time = self._conf['rtn-msg-hold-time']

        for interface in self.msg_db:
            for neighbor, msg in self.msg_db[interface].items():
                if (int(msg.rx_time) + int(hold_time)) < int(now):
                    obsolete.append((interface, neighbor))

        if obsolete:
            self.trace('tick.obsolete.msg', obsolete)
            for interface, neighbor in obsolete:
                del self.msg_db[interface][neighbor]
            return True

        return False

    def _clean_networks(self) -> bool:
        """
        Iterates over all known networks and removes the timed out ones
        """
        update = False
        obsolete = []
        now = self.now()
        retracted_hold_time = self._conf['retracted-prefix-hold-time']
        hold_time = self._conf['rtn-msg-hold-time']

        for network, retracted in self.networks['retracted'].items():
            if retracted + retracted_hold_time < now:
                obsolete.append(network)

        if obsolete:
            self.trace('tick.obsolete.prefix', obsolete)
            for network in obsolete:
                del self.networks['retracted'][network]
            update = True

        obsolete = []
        for network, current in self.networks['current'].items():
            if (int(current) + int(hold_time)) < now:
                obsolete.append(network)

        if obsolete:
            for network in obsolete:
                del self.networks['current'][network]
            update = True

        return update

    def _process_full_mode_queue(self):
        if self.state.full_only_mode:
            if self.now() > self.state.full_only_mode + FULL_MODE_TIME:
                self.state.full_only_mode = False
            else:
                return

        if len(self.state.full_request_queue) != FULL_MODE_ANALYSE_HISTORY:
            return
        avg = sum(self.state.full_request_queue) / FULL_MODE_ANALYSE_HISTORY
        if avg > self.now() - FULL_MODE_TRIGGER_THRESH:
            self.state.full_only_mode = self.now()

    #####################
    #  message tx path  #
    #####################

    def tx_route_packet(self):
        """
        Generate a new routing packet and call the msg_tx_cb callback
        """
        self._inc_seq_no()
        for interface in self._conf['interfaces']:
            msg = self._create_routing_msg(interface)
            self.trace('tx.msg', msg)

            for v in (4, 6):
                key = 'mcast-v{}-tx-addr'.format(v)
                mcast_addr = self._conf.get(key, False)
                if mcast_addr:
                    self._packet_tx_func(interface, 'v{}'.format(v), mcast_addr,
                                         msg)

    def _create_routing_msg(self, interface_name: str) -> dict:
        full_only = self.state.full_only_mode and \
                    self._conf['enable-full-only-mode']

        if self.state.next_full_update <= 0 or full_only:
            self.state.next_full_update = self._conf['max-full-update-interval']
            return self._create_full_routing_msg(interface_name)

        else:
            self.state.next_full_update -= 1
            return self._create_partial_routing_msg(interface_name)

    def _create_full_routing_msg(self, interface_name: str) -> dict:
        """
        Create a new full update packet
        """
        packet = {
            'id': self.id,
            'seq': self.state.seq_no,
            'type': 'full',
        }

        interface = self._conf['interfaces'][interface_name]
        if 'addr-v4' in interface:
            packet['addr-v4'] = interface['addr-v4']
        if 'addr-v6' in interface:
            packet['addr-v6'] = interface['addr-v6']

        if self._conf['networks']:
            packet['networks'] = self._prepare_networks()

        # The new base message for partial updates
        next_base = packet.copy()

        if self.routing_data:
            routing_data = {}
            node_data = {}
            link_attributes = LinkAttributes()

            # We need to separate the routing data for the new base message
            # because we need to be able to compare two entries, which is
            # easier to do when the path is not a string but a Path instance
            next_base_routing_data = {}

            for policy in self.routing_data:
                for node in self.routing_data[policy]:
                    path = self.routing_data[policy][node]['path']
                    path.apply_attributes(link_attributes)
                    routing_data.setdefault(policy, {})[node] = {
                        'path': str(path),
                    }
                    next_base_routing_data.setdefault(policy, {})[node] = {
                        'path': path,
                    }

                    if node not in node_data:
                        node_data[node] = self.node_data[node]

            packet.update({
                'routing-data': routing_data,
                'node-data': node_data,
                'link-attributes': link_attributes,
            })
            next_base.update({
                'routing-data': next_base_routing_data,
                'node-data': node_data,
            })

        self.state.last_full_msg = next_base

        request_full = self._prepare_full_requests()
        if request_full:
            packet['request-full'] = request_full

        reflect = self._get_reflect_requests(interface_name)
        if reflect:
            packet['reflect'] = reflect

        if self.reflections:
            packet['reflected'] = self.reflections

        return packet

    def _create_partial_routing_msg(self, interface_name: str) -> dict:
        """
        Create a partial update based on the last full message
        """
        packet = {
            'id': self.id,
            'seq': self.state.seq_no,
            'type': 'partial',
        }

        base_msg = self.state.last_full_msg
        packet['partial-base'] = base_msg['seq']

        # Add changed interface address data
        interface = self._conf['interfaces'][interface_name]
        for addr in ('addr-v4', 'addr-v6'):
            if addr in interface:
                if addr in base_msg:
                    if interface[addr] != base_msg[addr]:
                        packet[addr] = interface[addr]
                else:
                    packet[addr] = interface[addr]
            else:
                if addr in base_msg:
                    packet[addr] = None

        # Add own networks if they changed
        networks = self._prepare_networks()
        if base_msg['networks'] != networks:
            packet['networks'] = networks

        # Add all changed paths, on a policy-node basis
        link_attributes = LinkAttributes()
        routing_data = {}
        base_routing_data = base_msg.get('routing-data', {})
        # Check for new or updated routes
        for policy in self.routing_data:
            base_msg_policy = base_routing_data.get(policy, {})
            for node, node_data in self.routing_data[policy].items():
                if node not in base_msg_policy or \
                                base_msg_policy[node] != node_data:
                    path = node_data['path']
                    path.apply_attributes(link_attributes)
                    routing_data.setdefault(policy, {})[node] = {
                        'path': str(path)
                    }
        # Check for deleted routes
        for policy in base_routing_data:
            for node in base_routing_data[policy]:
                if node not in self.routing_data.get(policy, {}):
                    routing_data.setdefault(policy, {})[node] = None
        # Save routing data in packet
        if routing_data:
            packet['routing-data'] = routing_data
            packet['link-attributes'] = link_attributes

        # Add all changed nodes. This includes new nodes we send in this update,
        # old nodes that were sent and changed as well as deleted nodes when
        # we delete the path in this update
        required_nodes = {node for policy in routing_data for node in
                          routing_data[policy] if
                          routing_data[policy][node] is not None}
        node_data = {}
        base_node_data = base_msg.get('node-data', {})
        # Check for new nodes
        for node in required_nodes:
            if node not in base_node_data or \
                            base_node_data[node] != self.node_data.get(node):
                node_data[node] = self.node_data[node]
        # Check for updated nodes or deleted nodes
        for node in base_node_data:
            if node not in self.node_data:
                node_data[node] = None
            elif base_node_data[node] != self.node_data[node]:
                node_data[node] = self.node_data[node]
        # Save node data in packet
        if node_data:
            packet['node-data'] = node_data

        request_full = self._prepare_full_requests()
        if request_full:
            packet['request-full'] = request_full

        # Add all changed reflections
        reflections = {}
        base_reflections = base_msg.get('reflected', {})
        # Check for new or changed reflections
        for node in self.reflections:
            if node not in base_reflections or \
                            base_reflections[node] != self.reflections[node]:
                reflections[node] = self.reflections[node]
        # Check for deleted reflections
        for node in base_reflections:
            if node not in self.reflections:
                reflections[node] = None
        # Save reflections in packet
        if reflections:
            packet['reflected'] = reflections

        reflect = self._get_reflect_requests(interface_name)
        if reflect:
            packet['reflect'] = reflect

        return packet

    def _prepare_networks(self) -> dict:
        """
        Translate the configured networks for this router into
        the message format
        """
        result = {}
        networks = self._conf['networks']
        for network in networks:
            retracted = None
            if networks[network]:
                retracted = {'retracted': True}
            result[network] = retracted
        return result

    def _prepare_full_requests(self):
        """
        Translate the list of nodes we want to request a
        full update from into the message format
        """
        if True in self.state.request_full_update:
            result = True
        else:
            result = list(set(self.state.request_full_update))
        self.state.request_full_update = []
        return result

    def _get_reflect_requests(self, interface_name: str) -> dict:
        reflect = {}

        if self._conf['interfaces'][interface_name]['asymm-detection']:
            reflect['seq'] = self.state.seq_no

        return reflect

    def _inc_seq_no(self):
        self.state.seq_no += 1

    def _calc_next_tx_time(self):
        """
        Set the next transmit time
        """
        interval = int(self._conf["rtn-msg-interval"])
        if self.state.next_tx_time is None:
            # first time transmitting, just wait jitter to join network faster
            interval = 0

        jitter = int(self._conf["rtn-msg-interval-jitter"])
        wait_time = interval + random.random() * jitter
        now = self.now()
        self.state.next_tx_time = now + wait_time
        self.log.debug("schedule next transmission for {} seconds".format(
            self.state.next_tx_time))

    ###############
    #  Callbacks  #
    ###############

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
        # print("->>>>>>>>>>>>> {}".format(self.routing_table))
        self._routing_table_update_func(self.routing_table)

    ###########
    #  utils  #
    ###########

    def _node_to_ip(self, interface: str, node: str, version: int) -> str:
        key = 'addr_v{}'.format(version)
        addr = getattr(self.msg_db[interface][node], key)
        if not addr:
            raise KeyError("Address does not exist")
        return addr

    def now(self) -> int:
        return self._get_time()

    def trace(self, tracepoint, msg):
        self.tracer.log(tracepoint, msg, time=self.now())

    def _dummy_cb(self, *args, **kwargs):
        pass
