import copy

from .exceptions import InvalidMessage, InvalidPartialUpdate
from .path import Path


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
                    # We have no node_data for this node, apparently it does not
                    # advertise any networks
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

        return True  # TODO add support for update detection

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
