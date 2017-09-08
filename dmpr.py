import ipaddress
import random
import copy
import functools

from datetime import datetime

# example configuration for DMPR daemon
exa_conf = """
    "id" : "ace80ef4-d284-11e6-bf26-cec0c932ce01",
    "rtn-msg-interval" : "30",
    "rtn-msg-interval-jitter" : "7",
    "rtn-msg-hold-time" : "90",
    "max-full-update-interval": "10"
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


@functools.lru_cache(maxsize=1024)
def normalize_network(network):
    return str(ipaddress.ip_network(network, strict=False))


def dict_reverse_lookup(d: dict, value):
    return list(d.keys())[list(d.values()).index(value)]


class ConfigurationException(Exception):
    pass


class InternalException(Exception):
    pass


class DMPRConfigDefaults(object):
    rtn_msg_interval = 30
    rtn_msg_interval_jitter = rtn_msg_interval / 4
    rtn_msg_hold_time = rtn_msg_interval * 3
    retracted_prefix_hold_time = rtn_msg_interval * 12  # TODO TBD
    max_full_update_interval = 0  # 0 => disables partial updates

    DEFAULT_CONFIG = {
        'rtn-msg-interval': rtn_msg_hold_time,
        'rtn-msg-interval-jitter': rtn_msg_interval_jitter,
        'rtn-msg-hold-time': rtn_msg_hold_time,
        'retracted-prefix-hold-time': retracted_prefix_hold_time,
        'max-full-update-interval': max_full_update_interval,
    }

    # default bandwidth for a given interface in bytes/second
    # bytes/second enabled dmpr deployed in low bandwidth environments
    # normally this value should be fetched from a interface information
    # or by active measurements.
    # Implementers SHOULD quantise values into a few classes to reduce the
    # DMPR routing packet size.
    # E.g. 1000, 5000, 10000, 100000, 1000000, 100000000, 100000000
    LINK_CHARACTERISITCS_BANDWIDTH = 5000
    # default loss is in percent for a given path
    # Implementers SHOULD quantise values into a few classes to reduce the
    # DMPR routing packet size.
    # e.g. 0, 5, 10, 20, 40, 80
    LINK_CHARACTERISITCS_LOSS = 0
    # default link cost in a hypothetical currency, the higher the more valuable
    # e.g. wifi can be 0, LTE can be 100, satelite uplink can be 1000
    LINK_CHARACTERISITCS_COST = 0

    DEFAULT_ATTRIBUTES = {
        'bandwidth': LINK_CHARACTERISITCS_BANDWIDTH,
        'loss': LINK_CHARACTERISITCS_LOSS,
        'cost': LINK_CHARACTERISITCS_COST,
    }


class NoOpTracer:
    def log(self, tracepoint, msg, time):
        pass


class NoOpLogger:
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    def __init__(self, loglevel=INFO):
        self.loglevel = loglevel
        self.debug = functools.partial(self.log, sev=self.DEBUG)
        self.info = functools.partial(self.log, sev=self.INFO)
        self.warning = functools.partial(self.log, sev=self.WARNING)
        self.error = functools.partial(self.log, sev=self.ERROR)
        self.critical = functools.partial(self.log, sev=self.CRITICAL)

    def log(self, msg, sev, time=lambda: datetime.now().isoformat()):
        pass


class Path:
    """Auxiliary class to handle paths, appending and their link
        attributes """

    def __init__(self, path: str, attributes: dict,
                 next_hop: str, next_hop_interface: str):
        path = path.split('>')
        if len(path) % 2 != 1:
            raise InternalException("Invalid path: {}".format(path))

        self.links = []
        self.nodes = []
        for i, element in enumerate(path):
            if i % 2 == 0:
                # This is a node
                self.nodes.append(element)
            else:
                # This is a link
                if not (element.startswith('[') and element.endswith(']')):
                    msg = "Invalid path: {}, link format error: {}"
                    raise InternalException(msg.format(path, element))
                self.links.append(element.strip('[]'))

        self.attributes = attributes
        self.next_hop = next_hop
        self.next_hop_interface = next_hop_interface
        self._global_attributes = {}
        self.policy_cache = {}

    @staticmethod
    def _next_id(attributes: dict) -> str:
        return str(int(max(attributes, key=int, default=0)) + 1)

    def append(self, node: str, new_next_hop_interface: str, attributes: dict):
        """Append a node with link attributes to the front of the path"""
        self.next_hop_interface = new_next_hop_interface
        self.next_hop = self.nodes[0]

        attribute_id = self._next_id(self.attributes)
        self.links.insert(0, attribute_id)
        self.nodes.insert(0, node)
        self.attributes[attribute_id] = attributes
        self.policy_cache = {}

    def apply_attributes(self, attributes: dict):
        """append all necessary attributes to global attributes dictionary"""
        for link in self.links:
            attr = self.attributes[link]
            if attr not in attributes.values():
                attribute_id = self._next_id(attributes)
                attributes[attribute_id] = attr

        self._global_attributes = attributes

    def __str__(self) -> str:
        """Returns path as string, requires an up-to-date
            global attribute dictionary"""
        nodes = self.nodes[:]
        links = self.links[:]
        result = nodes.pop()
        while nodes:
            next_link = links.pop()
            next_node = nodes.pop()

            attr = self.attributes[next_link]
            try:
                link_id = dict_reverse_lookup(self._global_attributes, attr)
            except IndexError:
                raise InternalException("path.__str__ called before all"
                                        "attributes were applied")

            result = "{}>[{}]>{}".format(next_node, link_id, result)

        return result

    def __eq__(self, other):
        if not isinstance(other, Path):
            raise ValueError("cannot compare path to {}".format(type(other)))

        if self.nodes != other.nodes:
            return False
        if (self.next_hop != other.next_hop or
                    self.next_hop_interface != other.next_hop_interface):
            return False

        for self_link, other_link in zip(self.links, other.links):
            if self.attributes[self_link] != other.attributes[other_link]:
                return False

        return True


class BaseMessage:
    def __init__(self):
        self.id = None
        self.seq = float('-inf')
        self.addr_v4 = None
        self.addr_v6 = None

        self.networks = {}
        self.routing_data = {}
        self.node_data = {}

    def apply_base_data(self, msg):
        self.id = msg.id
        self.seq = msg.seq
        self.addr_v4 = msg.addr_v4
        self.addr_v6 = msg.addr_v6

        self.networks = msg.networks
        self.routing_data = msg.routing_data
        self.node_data = msg.node_data


class InvalidMessage(Exception):
    pass


class InvalidPartialUpdate(Exception):
    pass


class Message(BaseMessage):
    def __init__(self, msg: dict, interface: dict, router_id: str, rx_time):
        super(Message, self).__init__()
        self._base = BaseMessage()

        self.rx_time = rx_time
        self.router_id = router_id
        self.interface = interface
        self.apply_new_msg(msg, rx_time)

    def apply_new_msg(self, msg: dict, rx_time) -> bool:
        self._validate_msg(msg)

        self.rx_time = rx_time

        if msg['type'] == 'full':
            return self._apply_full(msg)
        elif msg['type'] == 'partial':
            return self._apply_partial(msg)

    def _validate_msg(self, msg: dict):
        # TODO raise partial error, check addr not when partial
        # Check for essential fields
        for i in ('id', 'seq', 'type'):
            if i not in msg:
                raise InvalidMessage("a message needs field {}".format(i))

        if msg['id'] == self.router_id:
            raise InvalidMessage("Message from self")

        if msg['seq'] <= self.seq:
            raise InvalidMessage("Old sequence number")

        if msg['type'] == 'full':
            # Check for at least one address
            if not any(('addr-v4' in msg, 'addr-v6' in msg)):
                raise InvalidMessage("Need one of add addr-v4 and addr-v6 in "
                                     "message")

        # Partial messages need a base
        elif msg['type'] == 'partial':
            if 'partial-base' not in msg:
                raise InvalidMessage("Need a partial-base in partial updates")
            if msg['partial-base'] != self._base.seq:
                raise InvalidPartialUpdate("Wrong base message sequence number")

        # If routing-data exists and there is at least one policy with paths
        # then there must be link-attributes
        # Also every policy value must be a dict
        routing_data = msg.get('routing-data', {})
        if routing_data and any(routing_data.values()):
            if not msg.get('link-attributes'):
                raise InvalidMessage("Need link-attributes for routing-data")
            for i in routing_data.values():
                if not isinstance(i, dict):
                    raise InvalidMessage("routing-data policies must be dict")

        for i in ('routing-data', 'node-data', 'link-attributes'):
            if i in msg:
                if not isinstance(msg[i], dict):
                    raise InvalidMessage("{} must be dict".format(i))

    def _apply_full(self, msg: dict) -> bool:
        update = False
        self.seq = msg['seq']
        self.addr_v4 = msg.get('addr-v4', None)
        self.addr_v6 = msg.get('addr-v6', None)

        update |= self._save_networks(msg)

        msg_routing_data = msg.get('routing-data', {})
        msg_link_attributes = msg.get('link-attributes', {})
        msg_node_data = msg.get('node-data', {})
        new_routing_data = {}
        for policy in msg_routing_data:
            new_routing_data[policy] = {}
            for node in msg_routing_data[policy]:
                path = self._get_path(msg_routing_data[policy][node]['path'],
                                      msg_link_attributes)
                if not path:
                    # Loop detection
                    continue

                new_routing_data[policy][node] = {
                    'path': path,
                }

                if node not in msg_node_data:
                    # TODO error
                    print("ERROR: node node_data for target {}".format(node))
                    continue

        if self.routing_data != new_routing_data:
            update = True
            self.routing_data = new_routing_data

        if self.node_data != msg_node_data:
            update = True
            self.node_data = msg_node_data

        self._base = BaseMessage()
        self._base.apply_base_data(self)

        return update

    def _apply_partial(self, msg: dict) -> bool:
        self.seq = msg['seq']
        self.addr_v4 = msg.get('addr_v4', self._base.addr_v4)
        self.addr_v6 = msg.get('addr_v6', self._base.addr_v6)

        if 'networks' in msg:
            self.networks = msg.get('networks', {})
        else:
            self.networks = self._base.networks

        self.routing_data = copy.deepcopy(self._base.routing_data)
        routing_data = msg.get('routing-data', {})
        for policy in routing_data:
            for node in routing_data[policy]:
                if routing_data[policy][node] is None:
                    if node in self.routing_data[policy]:
                        del self.routing_data[policy][node]
                else:
                    path = self._get_path(routing_data[policy][node]['path'],
                                          msg.get('link-attributes', {}))
                    if not path:
                        # Routing loop
                        continue
                    self.routing_data[policy][node] = {
                        'path': path
                    }

        self.node_data = copy.deepcopy(self._base.node_data)
        node_data = msg.get('node-data', {})
        for node in node_data:
            if node == self.router_id:
                continue
            if node_data[node] is None:
                if node in self.node_data:
                    del self.node_data[node]
            else:
                self.node_data[node] = node_data[node]

        return True  # FIXME add support for update detection

    def _save_networks(self, msg: dict) -> bool:
        networks = msg.get('networks')
        if networks != self.networks:
            self.networks = networks
            return True
        return False

    def _get_path(self, path: str, link_attributes: dict) -> Path:
        path = Path(path=path,
                    attributes=link_attributes,
                    next_hop='',
                    next_hop_interface=self.interface['name'])

        if self.router_id in path.nodes:
            return False

        path.append(self.router_id,
                    self.interface['name'],
                    self.interface['link-attributes'])

        return path


class AbstractPolicy:
    """ A policy implements all routing decisions by
        providing comparison methods for interfaces
        and paths"""
    name = NotImplemented

    def __init__(self):
        if self.name == NotImplemented:
            raise NotImplementedError("The policy needs a name")

    @staticmethod
    def with_path_cache(func):
        @functools.wraps(func)
        def wrapper(self, path):
            if self.name in path.policy_cache:
                return path.policy_cache[self.name]

            metric = func(self, path)
            path.policy_cache[self.name] = metric
            return metric

        return wrapper

    def path_cmp_key(self, path: Path):
        """ returns a sort key e.g. for the `sorted` function"""
        raise NotImplementedError("A policy must override this method")


class SimpleLossPolicy(AbstractPolicy):
    """ Route via the lowest-loss path"""
    name = 'lowest-loss'

    @staticmethod
    def _acc_loss(path: Path) -> int:
        loss = 0
        for link in path.links:
            loss += path.attributes[link]['loss']
        return loss

    @AbstractPolicy.with_path_cache
    def path_cmp_key(self, path: Path) -> int:
        return self._acc_loss(path)


class SimpleBandwidthPolicy(AbstractPolicy):
    """ Route via the highest-bandwidth path"""
    name = 'highest-bandwidth'

    @staticmethod
    def _acc_bw(path: Path) -> int:
        return min(path.attributes[link]['bandwidth'] for link in path.links)

    @AbstractPolicy.with_path_cache
    def path_cmp_key(self, path: Path):
        # the minimum bandwidth of the path while slightly preferring
        # shorter paths
        return - self._acc_bw(path) * 0.99 ** len(path.links)


class DMPRState:
    def __init__(self):
        # Router state
        self.seq_no = 0

        # routing data state
        self.update_required = False

        # Message handling state
        self.next_tx_time = None
        self.request_full_update = [True]
        self.next_full_update = 0
        self.last_full_msg = {}


class DMPR(object):
    def __init__(self, log=NoOpLogger(), tracer=NoOpTracer()):
        self.log = log
        self.tracer = tracer

        self._started = False
        self._conf = None
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

        self.log.info("starting DMPR core")
        self._reset()

        for interface in self._conf['interfaces']:
            self.msg_db[self._conf['interfaces'][interface]['name']] = dict()

        self._calc_next_tx_time()
        self._started = True

    def restart(self):
        self.stop()
        self.start()

    def register_policy(self, policy):
        if policy not in self.policies:
            self.policies.append(policy)

    def remove_policy(self, policy):
        if policy in self.policies:
            self.policies.remove(policy)

    def register_configuration(self, configuration: dict):
        """ register and setup configuration. Raise
            an error when values are wrongly configured
            restarts dmpr if it was running"""
        self._conf = self._validate_config(configuration)

        self.trace('config.new', self._conf)

        if self._started:
            self.log.info('configuration changed, restarting')
            self.restart()

    @staticmethod
    def _validate_config(configuration: dict) -> dict:
        """ convert external python dict configuration into internal
            configuration, check and set default values """
        if not isinstance(configuration, dict):
            raise ConfigurationException("configuration must be dict-like")

        config = copy.deepcopy(DMPRConfigDefaults.DEFAULT_CONFIG)

        config.update(configuration)

        if "id" not in config:
            msg = "configuration contains no id! A id must be unique, it can be \
                   randomly generated but for better performance and debugging \
                   capabilities this generated ID should be saved permanently \
                   (e.g. at a local file) to survive daemon restarts"
            raise ConfigurationException(msg)

        if not isinstance(config["id"], str):
            msg = "id must be a string!"
            raise ConfigurationException(msg)

        interfaces = config.get('interfaces', False)
        if not isinstance(interfaces, list):
            msg = "No interface configured, a list of at least on is required"
            raise ConfigurationException(msg)

        converted_interfaces = {}
        config['interfaces'] = converted_interfaces
        for interface_data in interfaces:
            if not isinstance(interface_data, dict):
                msg = "interface entry must be dict: {}".format(
                    interface_data)
                raise ConfigurationException(msg)
            if "name" not in interface_data:
                msg = "interfaces entry must contain at least a \"name\""
                raise ConfigurationException(msg)
            if "addr-v4" not in interface_data:
                msg = "interfaces entry must contain at least a \"addr-v4\""
                raise ConfigurationException(msg)
            converted_interfaces[interface_data['name']] = interface_data

            orig_attr = interface_data.setdefault('link-attributes', {})
            attributes = copy.deepcopy(DMPRConfigDefaults.DEFAULT_ATTRIBUTES)
            attributes.update(orig_attr)
            interface_data['link-attributes'] = attributes

        networks = config.get('networks', False)
        if networks:
            converted_networks = {}
            config['networks'] = converted_networks

            if not isinstance(networks, list):
                msg = "networks must be a list!"
                raise ConfigurationException(msg)

            for network in configuration["networks"]:
                if not isinstance(network, dict):
                    msg = "interface entry must be dict: {}".format(network)
                    raise ConfigurationException(msg)
                if "proto" not in network:
                    msg = "network must contain proto key: {}".format(
                        network)
                    raise ConfigurationException(msg)
                if "prefix" not in network:
                    msg = "network must contain prefix key: {}".format(
                        network)
                    raise ConfigurationException(msg)
                if "prefix-len" not in network:
                    msg = "network must contain prefix-len key: {}".format(
                        network)
                    raise ConfigurationException(msg)

                addr = '{}/{}'.format(network['prefix'], network['prefix-len'])
                converted_networks[normalize_network(addr)] = False

        if "mcast-v4-tx-addr" not in config:
            msg = "no mcast-v4-tx-addr configured!"
            raise ConfigurationException(msg)

        if "mcast-v6-tx-addr" not in config:
            msg = "no mcast-v6-tx-addr configured!"
            raise ConfigurationException(msg)

        return config

    def register_get_time_cb(self, function):
        """ Register a callback for the given time, this functions
            must not need any arguments"""
        self._get_time = function

    def register_routing_table_update_cb(self, function):
        """ Register a callback for route updates, the signature should be:
            function(routing_table: dict)"""
        self._routing_table_update_func = function

    def register_msg_tx_cb(self, function):
        """ Register a callback for sending messages, the signature should be:
            function(interface: str, ipversion: str, mcast_addr: str, msg: dict)
        """
        self._packet_tx_func = function

    ##################
    #  dmpr rx path  #
    ##################

    def msg_rx(self, interface_name: str, msg: dict):
        """receive routing packet, triggers all recalculations"""

        self.trace('rx.msg', msg)

        if interface_name not in self._conf['interfaces']:
            emsg = "interface {} is not configured, ignoring message"
            self.log.warning(emsg.format(interface_name))
            return

        if 'id' not in msg:
            return

        new_neighbour = msg['id'] not in self.msg_db[interface_name]
        try:
            if new_neighbour:
                interface = self._conf['interfaces'][interface_name]
                message = Message(msg, interface, self._conf['id'], self.now())
                self.msg_db[interface_name][msg['id']] = message
                self.state.update_required = True
                # TODO request full when partial
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

        if 'request-full' in msg:
            self._process_full_requests(msg)

        if 'reflector' in msg:
            pass  # TODO update reflector data, for later

        if 'reflections' in msg:
            pass  # TODO process reflections, for later

    def _process_full_requests(self, msg: dict):
        request = msg['request-full']
        if (isinstance(request, list) and self._conf['id'] in request) or \
                (isinstance(request, bool) and request):
            self.state.next_full_update = 0

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

    def _compute_routing_data(self, policy):
        """Update the internal databases with the routing information
                    of this policy"""

        routing_data = {}
        self.routing_data[policy.name] = routing_data

        paths, networks = self._parse_msg_db(policy)

        for node, node_paths in paths.items():
            node_paths = sorted(node_paths, key=policy.path_cmp_key)
            best_path = node_paths[0]

            routing_data[node] = {
                'path': best_path
            }
            if node not in networks:
                self.log.warning("No node data for target")
                continue
            node_networks = self._merge_networks(networks[node])

            if not node_networks:
                continue

            node_entry = self.node_data.setdefault(node, {})
            node_networks_entry = node_entry.setdefault('networks', {})
            node_networks_entry.update(self._update_network_data(node_networks))

    def _compute_routing_table(self, policy):
        routing_table = []
        self.routing_table[policy.name] = routing_table

        routing_data = self.routing_data[policy.name]

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
                    self.log.error(msg.format(node=node,
                                              version=version))
                    continue

                routing_table.append({
                    'proto': 'v{}'.format(version),
                    'prefix': prefix,
                    'prefix-len': prefix_len,
                    'next-hop': next_hop_ip,
                    'interface': path.next_hop_interface,
                })

    def _parse_msg_db(self, policy: AbstractPolicy) -> tuple:
        paths = {}
        networks = {}
        for interface in self.msg_db:
            for neighbour, msg in self.msg_db[interface].items():
                neighbour_paths = paths.setdefault(neighbour, [])
                path = self._get_neighbour_path(interface, neighbour)
                neighbour_paths.append(path)

                neighbour_networks = networks.setdefault(neighbour, [])
                neighbour_networks.append(msg.networks)

                routing_data = msg.routing_data.get(policy.name, {})
                for node, node_data in routing_data.items():
                    node_paths = paths.setdefault(node, [])
                    node_paths.append(node_data['path'])

                for node, node_data in msg.node_data.items():
                    node_networks = networks.setdefault(node, [])
                    node_networks.append(node_data['networks'])

        return paths, networks

    def _get_neighbour_path(self, interface_name: str, neighbour: str):
        interface = self._conf['interfaces'][interface_name]
        path = Path(path=neighbour,
                    attributes={},
                    next_hop=neighbour,
                    next_hop_interface=interface_name)

        path.append(self._conf['id'], interface_name,
                    interface['link-attributes'])
        return path

    @staticmethod
    def _merge_networks(networks: list) -> dict:
        """ Merges all networks, retracted status overwrites not retracted"""
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
        """ Apply network retraction policy according to the following table:
in current | in retracted | msg retracted |
     0     |       0      |       0       | save in current, forward
     0     |       0      |       1       | ignore, don't forward
     0     |       1      |       0       | forward retracted
     0     |       1      |       1       | forward retracted
     1     |       0      |       0       | forward
     1     |       0      |       1       | del current, save in retracted, forward retracted
     1     |       1      |       0       | n/a
     1     |       1      |       1       | n/a

            networks in retracted will get deleted after a hold time, this hold
            time MUST be greater than the worst case propagation time for the
            retracted flag"""
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
        self.trace('tick', self.now())

        self.state.update_required |= self._clean_msg_db()
        self.state.update_required |= self._clean_networks()
        if self.state.update_required:
            self.state.update_required = False
            self.recalculate_routing_data()

        if self.now() >= self.state.next_tx_time:
            self.tx_route_packet()
            self._calc_next_tx_time()

    def _clean_msg_db(self) -> bool:
        """ Iterates over all msg_db entries and purges all obsolete entries"""
        obsolete = []
        now = self.now()
        hold_time = self._conf['rtn-msg-hold-time']

        for interface in self.msg_db:
            for neighbour, msg in self.msg_db[interface].items():
                if msg.rx_time + hold_time < now:
                    obsolete.append((interface, neighbour))

        if obsolete:
            self.trace('tick.obsolete.msg', obsolete)
            for interface, neighbour in obsolete:
                del self.msg_db[interface][neighbour]
            return True

        return False

    def _clean_networks(self) -> bool:
        """ Iterates over all retracted networks and
            purges all obsolete entries"""
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
            if current + hold_time < now:
                obsolete.append(network)

        if obsolete:
            for network in obsolete:
                del self.networks['current'][network]
            update = True

        return update

    #####################
    #  message tx path  #
    #####################

    def tx_route_packet(self):
        # depending on local information the route
        # packets must be generated for each interface
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
        if self.state.next_full_update <= 0:
            self.state.next_full_update = self._conf['max-full-update-interval']
            return self._create_full_routing_msg(interface_name)
        else:
            self.state.next_full_update -= 1
            return self._create_partial_routing_msg(interface_name)

    def _create_full_routing_msg(self, interface_name: str) -> dict:
        packet = {
            'id': self._conf['id'],
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
            link_attributes = {}

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

        return packet

    def _create_partial_routing_msg(self, interface_name: str) -> dict:
        """ create a partial update based on the last full message"""
        packet = {
            'id': self._conf['id'],
            'seq': self.state.seq_no,
            'type': 'partial',
        }

        base_msg = self.state.last_full_msg
        packet['partial-base'] = base_msg['seq']

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

        networks = self._prepare_networks()
        if not self._eq_dicts(base_msg['networks'], networks):
            packet['networks'] = networks

        link_attributes = {}
        routing_data = {}
        base_routing_data = base_msg.get('routing-data', {})
        # Check for new or updated routes
        for policy in self.routing_data:
            base_msg_policy = base_routing_data.get(policy, {})
            for node, node_data in self.routing_data[policy].items():
                if node not in base_msg_policy or not self._eq_dicts(
                        base_msg_policy[node], node_data):
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

        return packet

    def _prepare_networks(self) -> dict:
        result = {}
        networks = self._conf['networks']
        for network in networks:
            retracted = None
            if networks[network]:
                retracted = {'retracted': True}
            result[network] = retracted
        return result

    def _prepare_full_requests(self):
        if True in self.state.request_full_update:
            result = True
        else:
            result = list(set(self.state.request_full_update))
        self.state.request_full_update = []
        return result

    def _inc_seq_no(self):
        self.state.seq_no += 1

    def _calc_next_tx_time(self):
        interval = self._conf["rtn-msg-interval"]
        if self.state.next_tx_time is None:
            # first time transmitting, just wait jitter to join network faster
            interval = 0

        jitter = self._conf["rtn-msg-interval-jitter"]
        wait_time = interval + random.random() * jitter
        now = self.now()
        self.state.next_tx_time = now + wait_time
        self.log.debug("schedule next transmission for {} seconds".format(
            self.state.next_tx_time), time=now)

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

    @classmethod
    def _eq_dicts(cls, dict1, dict2):
        return dict1 == dict2
        if dict1 is None or dict2 is None:
            return False

        if not isinstance(dict1, dict) or not isinstance(dict2, dict):
            return False

        if set(dict1.keys()) != set(dict2.keys()):
            return False

        for key, value in dict1.items():
            if isinstance(value, dict):
                if not cls._eq_dicts(dict1[key], dict2[key]):
                    return False
            else:
                if dict1[key] != dict2[key]:
                    return False

        return True
