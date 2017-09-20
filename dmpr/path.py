from .exceptions import InternalException


def dict_reverse_lookup(d: dict, value):
    return list(d.keys())[list(d.values()).index(value)]


class LinkAttributes(dict):
    """
    This class is here mainly for caching reasons. The link attributes are
    the same for each Path in a packet. Therefore we can use one instance of
    this class per Packet and don't need to copy it every time. This also
    caches the next available id.
    """

    def __init__(self, attributes=None):
        if attributes is None:
            attributes = {}
        super(LinkAttributes, self).__init__(attributes)
        self.current_id = int(max(attributes, key=int, default=0))

    def get_next_id(self):
        self.current_id += 1
        return str(self.current_id)


class Path(object):
    """
    Auxiliary class to handle paths, appending and their link attributes
    """

    __slots__ = (
        'links',
        'nodes',
        'attributes',
        'next_hop',
        'next_hop_interface',
        '_global_attributes',
        'policy_cache',
    )

    def __init__(self, path: str, attributes: LinkAttributes,
                 next_hop: str, next_hop_interface: str):
        """
        Create a new path from the string representation.

        also saves the next hop and the responsible interface
        """
        path = path.split('>')
        if len(path) % 2 != 1:
            raise InternalException("Invalid path: {}".format(path))

        self.links = [i.strip('[]') for i in path[1::2]]
        self.nodes = [i for i in path[::2]]

        self.attributes = attributes
        self.next_hop = next_hop
        self.next_hop_interface = next_hop_interface
        self._global_attributes = {}
        self.policy_cache = {}

    def append(self, node: str, new_next_hop_interface: str, attributes: dict):
        """
        Append a node with link attributes to the front of the path
        """
        self.next_hop_interface = new_next_hop_interface
        self.next_hop = self.nodes[0]

        attribute_id = self.attributes.get_next_id()
        self.links.insert(0, attribute_id)
        self.nodes.insert(0, node)
        self.attributes[attribute_id] = attributes
        self.policy_cache = {}

    def apply_attributes(self, attributes: LinkAttributes):
        """
        Append all necessary attributes to the global attributes dictionary
        """
        for link in self.links:
            attr = self.attributes[link]
            if attr not in attributes.values():
                attributes[attributes.get_next_id()] = attr

        self._global_attributes = attributes

    def __str__(self) -> str:
        """
        Returns path as string, requires an up-to-date
        global attribute dictionary
        """
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

    def __eq__(self, other) -> bool:
        """
        Two paths are equal if they share the same nodes
        over links with the same attributes
        """
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
