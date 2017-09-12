from dmpr import DMPR

from dmpr.path import Path, LinkAttributes


class TestPath:
    @staticmethod
    def get_path():
        return Path(path='A>[1]>B>[2]>C',
                    attributes=LinkAttributes({
                        '1': {'loss': 10},
                        '2': {'loss': 20}
                    }),
                    next_hop='B',
                    next_hop_interface='wlan0')

    def test_correct_splitting(self):
        path = self.get_path()
        assert path.links == ['1', '2']
        assert path.nodes == ['A', 'B', 'C']
        assert path.next_hop_interface == 'wlan0'

    def test_correct_appending(self):
        path = self.get_path()
        path.append('D', 'tetra', {'loss': 30})
        assert path.next_hop_interface == 'tetra'
        assert path.links[0] == '3'
        assert path.attributes['3']['loss'] == 30

    def test_correct_applying_to_new(self):
        path = self.get_path()
        attributes = LinkAttributes()
        path.apply_attributes(attributes)
        assert {'loss': 20} in attributes.values()
        assert {'loss': 10} in attributes.values()

    def test_correct_applying_to_others(self):
        path = self.get_path()
        attributes = LinkAttributes({'1': {'loss': 30}})
        path.apply_attributes(attributes)
        assert {'loss': 20} in attributes.values()
        assert {'loss': 10} in attributes.values()
        assert attributes['1'] == {'loss': 30}

    def test_str(self):
        path = self.get_path()
        attributes = LinkAttributes()
        path.apply_attributes(attributes)

        expected = "A>[{}]>B>[{}]>C"
        loss_10 = list(attributes.keys())[
            list(attributes.values()).index({'loss': 10})]
        loss_20 = list(attributes.keys())[
            list(attributes.values()).index({'loss': 20})]
        expected = expected.format(loss_10, loss_20)

        assert str(path) == expected

    def test_eq(self):
        path1 = self.get_path()
        path2 = self.get_path()
        path3 = self.get_path()
        path4 = self.get_path()
        path5 = self.get_path()
        path6 = self.get_path()
        path7 = self.get_path()

        path3.append('X', 'wlan', {'loss': 2})
        path4.append('X', 'tetra', {'loss': 2})
        path5.append('X', 'wlan', {'loss': 3})
        path6.append('Y', 'wlan', {'loss': 2})
        path7.append('X', 'wlan', {'loss': 2})

        assert path1 is not path2
        assert path2 is not path3
        assert path1 is not path3
        assert path3 is not path4
        assert path3 is not path7

        assert path1 == path2
        assert path1 != path3
        assert path1 == path1
        assert path3 == path3
        assert path3 != path4
        assert path3 != path5
        assert path3 != path6
        assert path3 == path7


class TestMergeNetworks:
    def test_simple(self):
        networks = [{'1': {}, '2': {}, '3': {'retracted': True}}]
        expected = {'1': {}, '2': {}, '3': {'retracted': True}}
        result = DMPR._merge_networks(networks)
        assert expected == result

    def test_overwrite(self):
        networks = [{'1': {}, '2': {}, '3': {'retracted': True}},
                    {'1': {}, '2': {}, '3': {'retracted': False}}]
        expected = {'1': {}, '2': {}, '3': {'retracted': True}}
        result = DMPR._merge_networks(networks)
        assert expected == result

    def test_multi_overwrite(self):
        networks = [{'1': {}, '2': {}, '3': {'retracted': True}},
                    {'1': {}, '2': {}, '3': {'retracted': False}},
                    {'1': {}, '2': {'retracted': True}, '3': {}}]
        expected = {'1': {}, '2': {'retracted': True}, '3': {'retracted': True}}
        result = DMPR._merge_networks(networks)
        assert expected == result


def test_init_dmpr():
    dmpr = DMPR(log=True)
