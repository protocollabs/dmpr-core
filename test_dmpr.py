from dmpr import DMPR


class TestAuxMethods:
    @staticmethod
    def get_dict():
        return {
            1: {1: 1, 2: 2},
            2: {1: 1, 2: 2},
            3: {1: (1, 2)},
            4: "test",
            5: [2, 3]
        }

    def test_cmp_dict_simple(self):
        f = DMPR._cmp_dicts

        assert not f(None, None)
        assert f({}, {})
        assert f({1: 1}, {1: 1})
        assert not f({1: 1}, {2: 1})
        assert not f({1: 1}, {1: 2})

        assert f({1: {1: 1}}, {1: {1: 1}})
        assert not f({1: {1: 1}}, {1: {1: 2}})
        assert not f({1: {1: 1}}, {1: {2: 1}})

    def test_cmp_dict_deep(self):
        f = DMPR._cmp_dicts
        dict1 = self.get_dict()
        dict2 = self.get_dict()

        assert f(dict1, dict1)
        assert f(dict1, dict2)
        dict2[3][1] = (1, 2)
        assert f(dict1, dict2)
        dict2[3][1] = (2, 3)
        assert not f(dict1, dict2)

    def test_cmp_dict_deep_mutable(self):
        f = DMPR._cmp_dicts
        dict1 = self.get_dict()
        dict2 = self.get_dict()

        dict1[5] = [self.get_dict()]
        dict2[5] = [self.get_dict()]
        assert f(dict1, dict2)
        dict2[5][0][4] = "error"
        assert not f(dict1, dict2)
        dict2[5][0] = None
        assert not f(dict1, dict2)


def test_init_dmpr():
    dmpr = DMPR(log=True)
