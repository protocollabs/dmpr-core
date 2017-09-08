# example configuration for DMPR daemon
exa_conf = {
    "id": "ace80ef4-d284-11e6-bf26-cec0c932ce01",
    "rtn-msg-interval": "30",
    "rtn-msg-interval-jitter": "7",
    "rtn-msg-hold-time": "90",
    "max-full-update-interval": "10",
    "mcast-v4-tx-addr": "224.0.1.1",
    "mcast-v6-tx-addr": "ff05:0:0:0:0:0:0:2",
    "proto-transport-enable": ["v4"],
    "interfaces": [
        {
            "name": "wlan0", "addr-v4": "10.0.0.1",
            "link-characteristics": {"bandwidth": "100000", "loss": "0"}
        },
        {
            "name": "tetra0", "addr-v4": "10.0.0.1",
            "link-characteristics": {"bandwidth": "10000", "loss": "0"}
        }
    ],
    "networks": [
        {"proto": "v4", "prefix": "192.168.1.0", "prefix-len": "24"},
        {"proto": "v4", "prefix": "192.168.2.0", "prefix-len": "24"},
        {"proto": "v4", "prefix": "10.10.0.0", "prefix-len": "16"},
        {"proto": "v6", "prefix": "fdcb:523:1111::", "prefix-len": "48"},
        {"proto": "v6", "prefix": "fd6a:6ad:b07f:ffff::", "prefix-len": "64"}
    ],
}


class DefaultConfiguration(object):
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
