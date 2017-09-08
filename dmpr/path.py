from .exceptions import InternalException


def dict_reverse_lookup(d: dict, value):
    return list(d.keys())[list(d.values()).index(value)]


class Path(object):
    """
    Auxiliary class to handle paths, appending and their link attributes
    """

    def __init__(self, path: str, attributes: dict,
                 next_hop: str, next_hop_interface: str):
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

    @staticmethod
    def _next_id(attributes: dict) -> str:
        return str(int(max(attributes, key=int, default=0)) + 1)

    def append(self, node: str, new_next_hop_interface: str, attributes: dict):
        """
        Append a node with link attributes to the front of the path
        """
        self.next_hop_interface = new_next_hop_interface
        self.next_hop = self.nodes[0]

        attribute_id = self._next_id(self.attributes)
        self.links.insert(0, attribute_id)
        self.nodes.insert(0, node)
        self.attributes[attribute_id] = attributes
        self.policy_cache = {}

    def apply_attributes(self, attributes: dict):
        """
        Append all necessary attributes to the global attributes dictionary
        """
        for link in self.links:
            attr = self.attributes[link]
            if attr not in attributes.values():
                attribute_id = self._next_id(attributes)
                attributes[attribute_id] = attr

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

    def __eq__(self, other):
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
