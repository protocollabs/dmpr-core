"""
This module defines the default configuration of DMPR.

This is how a configuration looks like. Note that keys for which there is a
default config are not required.
{
    "id": "ace80ef4-d284-11e6-bf26-cec0c932ce01",
    "rtn-msg-interval": 30,
    "rtn-msg-interval-jitter": 7,
    "rtn-msg-hold-time": 90,
    "max-full-update-interval": 10,
    "enable-full-only-mode": False,
    "mcast-v4-tx-addr": "224.0.1.1",
    "mcast-v6-tx-addr": "ff05:0:0:0:0:0:0:2",
    "proto-transport-enable": ["v4"],
    "interfaces": [
        {
            "name": "wlan0", "addr-v4": "10.0.0.1", "asymm-detection": False,
            "link-attributes": {"bandwidth": 100000, "loss": 0}
        },
        {
            "name": "tetra0", "addr-v4": "10.0.0.1", "asymm-detection": True,
            "link-attributes": {"bandwidth": 10000, "loss": 0}
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
"""

import copy
import functools
import ipaddress

from core.dmpr.exceptions import ConfigurationException


@functools.lru_cache(maxsize=1024)
def normalize_network(network):
    return str(ipaddress.ip_network(network, strict=False))


class DefaultConfiguration(object):
    rtn_msg_interval = 30
    rtn_msg_interval_jitter = rtn_msg_interval / 4
    rtn_msg_hold_time = rtn_msg_interval * 3
    retracted_prefix_hold_time = rtn_msg_interval * 12  # TODO TBD
    max_full_update_interval = 0  # 0 => disables partial updates
    enable_full_only_mode = False

    DEFAULT_CONFIG = {
        'rtn-msg-interval': rtn_msg_interval,
        'rtn-msg-interval-jitter': rtn_msg_interval_jitter,
        'rtn-msg-hold-time': rtn_msg_hold_time,
        'retracted-prefix-hold-time': retracted_prefix_hold_time,
        'max-full-update-interval': max_full_update_interval,
        'enable-full-only-mode': enable_full_only_mode,
    }

    # default bandwidth for a given interface in bytes/second
    # bytes/second enabled dmpr deployed in low bandwidth environments
    # normally this value should be fetched from a interface information
    # or by active measurements.
    # Implementers SHOULD quantise values into a few classes to reduce the
    # DMPR routing packet size.
    # E.g. 1000, 5000, 10000, 100000, 1000000, 100000000, 100000000
    LINK_CHARACTERISTICS_BANDWIDTH = 5000
    # default loss is in percent for a given path
    # Implementers SHOULD quantise values into a few classes to reduce the
    # DMPR routing packet size.
    # e.g. 0, 5, 10, 20, 40, 80
    LINK_CHARACTERISTICS_LOSS = 0
    # default link cost in a hypothetical currency, the higher the more valuable
    # e.g. wifi can be 0, LTE can be 100, satelite uplink can be 1000
    LINK_CHARACTERISTICS_COST = 0

    DEFAULT_ATTRIBUTES = {
        'bandwidth': LINK_CHARACTERISTICS_BANDWIDTH,
        'loss': LINK_CHARACTERISTICS_LOSS,
        'cost': LINK_CHARACTERISTICS_COST,
    }

    @staticmethod
    def validate_config(configuration: dict) -> dict:
        """
        convert external python dict configuration into internal
        configuration, check and set default values
        """
        if not isinstance(configuration, dict):
            raise ConfigurationException("configuration must be dict-like")

        config = copy.deepcopy(DefaultConfiguration.DEFAULT_CONFIG)

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
            if "asymm-detection" not in interface_data:
                interface_data["asymm-detection"] = False
            converted_interfaces[interface_data['name']] = interface_data

            orig_attr = interface_data.setdefault('link-attributes', {})
            attributes = copy.deepcopy(DefaultConfiguration.DEFAULT_ATTRIBUTES)
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
