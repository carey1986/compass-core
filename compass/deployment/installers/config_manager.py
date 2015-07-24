# Copyright 2014 Huawei Technologies Co. Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

__author__ = "Grace Yu (grace.yu@huawei.com)"


"""Module to manage and access cluster, hosts and adapter config.
"""
from collections import defaultdict
from copy import deepcopy
import logging


from compass.deployment.utils import constants as const

class AdapterInfo(object):
    def __init__(self, adapter_info):
        self.adapter_info = adapter_info

class ClusterInfo(object):
    def __init__(self, cluster_info):
        self.cluster_info = cluster_info
        self.id = self.cluster_info.get(const.ID)
        self.name = self.cluster_info.get(const.NAME)
        self.os_version = self.cluster_info.get(const.OS_VERSION)
        self.flavor = self.cluster_info.get(const.FLAVOR, {})
        self.os_config = self.cluster_info.get(const.OS_CONFIG, {})
        self.package_config = self.cluster_info.get(const.PK_CONFIG, {})
        self.deployed_os_config = self.cluster_info.get(const.DEPLOYED_OS_CONFIG, {})
        self.deployed_package_config = self.cluster_info.get(const.DEPLOYED_PK_CONFIG, {})
        self.network_mapping = self.package_config.get(const.NETWORK_MAPPING, {})

    @property
    def base_info(self):
        return { const.ID: self.id,
                 const.NAME: self.name,
                 const.OS_VERSION: self.os_version }

class HostInfo(object):
    def __init__(self, host_info, cluster_info):
        self.host_info = host_info
        self.cluster_info = cluster_info
        self.id = self.host_info.get(const.ID)
        self.name = self.host_info.get(const.NAME)
        self.mac = self.host_info.get(const.MAC_ADDR)
        self.hostname = self.host_info.get(const.HOSTNAME)
        self.networks = self.host_info.get(const.NETWORKS, {})
        self.os_config = self.host_info.get(const.OS_CONFIG)
        self.package_config = self.host_info.get(const.PK_CONFIG, {})
        self.roles = self.host_info.get(const.ROLES, [])
        self.ipmi = deepcopy(self.host_info.get(const.IPMI, {}))
        self.reinstall_os_flag = self.host_info.get(const.REINSTALL_OS_FLAG)

        if const.DNS in host_info:
            self.dns = host_info[const.DNS]
        else:
            self.dns = '.'.join((self.hostname, self.domain))

        package_config = self.get_host_package_config(host_id)
        if const.NETWORK_MAPPING not in package_config:
            network_mapping = self.get_cluster_network_mapping()
        else:
            network_mapping = package_config[const.NETWORK_MAPPING]

        return network_mapping

    @property
    def baseinfo(self):
        return  { const.REINSTALL_OS_FLAG: self.reinstall_os_flag,
                  const.MAC_ADDR: self.mac,
                  const.NAME: self.name,
                  const.HOSTNAME: self.hostname,
                  const.NETWORKS: deepcopy(self.networks) }

class BaseConfigManager(object):
    def __init__(self, adapter_info={}, cluster_info={}, hosts_info={}):
        assert(adapter_info and isinstance(adapter_info, dict))
        assert(cluster_info and isinstance(adapter_info, dict))
        assert(hosts_info and isinstance(adapter_info, dict))

        self.adapter_info = AdapterInfo(adapter_info)
        self.cluster_info = ClusterInfo(cluster_info)
        self.hosts_info = [(k, HostInfo(v, self.cluster_info)) for k, v in hosts_info.iteritems()]

    #*************************** cluster method start ****************************
    def get_cluster_id(self):
        return self.cluster_info.id

    def get_clustername(self):
        return self.cluster_info.name

    def get_os_version(self):
        return self.cluster_info.os_version

    def get_cluster_os_config(self):
        return self.cluster_info.os_config

    def get_cluster_baseinfo(self):
        return self.cluster_info.base_info

    def get_cluster_flavor_name(self):
        return self.cluster_info.flavor.get(const.FLAVOR_NAME)

    def get_cluster_flavor_roles(self):
        return self.cluster_info.flavor.get(const.ROLES, [])

    def get_cluster_flavor_template(self):
        return self.cluster_info.flavor.get(const.TMPL)

    def get_cluster_package_config(self):
        return self.cluster_info.package_config

    def get_cluster_network_mapping(self):
        mapping = self.cluster_info.network_mapping
        logging.info("Network mapping in the config is '%s'!", mapping)
        return mapping

    def get_cluster_deployed_os_config(self):
        return self.cluster_info.deployed_os_config

    def get_cluster_deployed_package_config(self):
        return self.cluster_info.deployed_package_config

    def get_cluster_roles_mapping(self):
        deploy_config = self.cluster_info.deployed_package_config
        mapping = deploy_config.get(const.ROLES_MAPPING)
        if not mapping:
            mapping = self._get_cluster_roles_mapping()

            # cache mapping info
            deploy_config[const.ROLES_MAPPING] = mapping

        return mapping

    def _get_cluster_roles_mapping(self):
        """The ouput format will be as below, for example:

        {
            "controller": [{
                "hostname": "xxx",
                "management": {
                    "interface": "eth0",
                    "ip": "192.168.1.10",
                    "netmask": "255.255.255.0",
                    "subnet": "192.168.1.0/24",
                    "is_mgmt": True,
                    "is_promiscuous": False
                },
                ...
            }],
                ...
        }
        """
        mapping = defaultdict(list)
        for host_id in self.hosts_info.keys():
            roles_mapping = self.get_host_roles_mapping(host_id)
            for role, value in roles_mapping.items():
                mapping[role].append(value)

        return mapping

    #*************************** cluster method end ****************************

    #*************************** host method start ****************************
    def validate_host(self, host_id):
        if host_id not in self.hosts_info:
            raise RuntimeError("host_id %s is invalid" % host_id)

    def validate_nic(self, host_id, interface):
        self.validate_host(host_id)
        if interface not in self.hosts_info[host_id]:
            raise RuntimeError("host %s's interface %s is invalid name" % (host_id, interface))

    def get_host_id_list(self):
        return self.hosts_info.keys()

    def get_hosts_id_list_for_os_installation(self):
        """Get info of hosts which need to install/reinstall OS."""
        return [id for id, info in self.hosts_info if info.reinstall_os_flag]

    def get_server_credentials(self):
        cluster_os_config = self.get_cluster_os_config()
        if not cluster_os_config:
            logging.info("cluster os_config is None!")
            return ()

        username = cluster_os_config[const.SERVER_CREDS][const.USERNAME]
        password = cluster_os_config[const.SERVER_CREDS][const.PASSWORD]
        return (username, password)

    def _get_host_info(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info.get(host_id)

    def get_host_baseinfo(self, host_id):
        self.validate_host(host_id)
        host_info = self.hosts_info[host_id]
        return host_info.baseinfo

    def get_host_fullname(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info[host_id].name

    def get_host_dns(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info[host_id].dns

    def get_host_mac_address(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info[host_id].mac

    def get_hostname(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info[host_id].hostname

    def get_host_networks(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info[host_id].networks

    def get_host_interfaces(self, host_id):
        # get interface names
        return self.get_host_networks(host_id).keys()

    def get_host_interface_config(self, host_id, interface):
        self.validate_nic(host_id, interface)
        return self.get_host_networks(host_id).get(interface, {})

    def get_host_interface_ip(self, host_id, interface):
        return self.get_host_interface_config(host_id, interface).get(const.IP_ADDR)

    def get_host_interface_netmask(self, host_id, interface):
        return self.get_host_interface_config(host_id, interface).get(const.NETMASK)

    def get_host_interface_subnet(self, host_id, interface):
        return self.get_host_interface_config(host_id, interface).get(const.SUBNET)

    def is_interface_promiscuous(self, host_id, interface):
        return self.get_host_interface_config(host_id, interface).get(const.PROMISCUOUS_FLAG)

    def is_interface_mgmt(self, host_id, interface):
        return self.get_host_interface_config(host_id, interface).get(const.MGMT_NIC_FLAG)

    def get_host_os_config(self, host_id):
        self.validate_host(host_id)
        return self.hosts_info[host_id].os_config

    def get_host_domain(self, host_id):
        os_config = self.get_host_os_config(host_id)
        os_general_config = os_config.setdefault(const.OS_CONFIG_GENERAL, {})
        domain = os_general_config.setdefault(const.DOMAIN, None)
        if domain is None:
            global_config = self.get_cluster_os_config()
            global_general = global_config.setdefault(const.OS_CONFIG_GENERAL,
                                                      {})
            domain = global_general.setdefault(const.DOMAIN, None)

        return domain

    def get_host_network_mapping(self, host_id):
        package_config = self.get_host_package_config(host_id)
        if const.NETWORK_MAPPING not in package_config:
            network_mapping = self.get_cluster_network_mapping()
        else:
            network_mapping = package_config[const.NETWORK_MAPPING]

        return network_mapping

    def get_host_package_config(self, host_id):
        return self.__get_host_item(host_id, const.PK_CONFIG, {})

    def get_host_deployed_os_config(self, host_id):
        host_info = self._get_host_info(host_id)
        return host_info.setdefault(const.DEPLOYED_OS_CONFIG, {})

    def get_host_deployed_package_config(self, host_id):
        host_info = self._get_host_info(host_id)
        return host_info.setdefault(const.DEPLOYED_PK_CONFIG, {})

    def get_host_roles(self, host_id):
        return self.__get_host_item(host_id, const.ROLES, [])

    def get_all_hosts_roles(self, hosts_id_list=None):
        roles = []
        if hosts_id_list is None:
            hosts_id_list = self.get_host_id_list()

        for host_id in hosts_id_list:
            host_roles = self.get_host_roles(host_id)
            roles.extend([role for role in host_roles if role not in roles])

        return roles

    def get_host_roles_mapping(self, host_id):
        deployed_pk_config = self.get_host_package_config(host_id)

        if const.ROLES_MAPPING not in deployed_pk_config:
            roles_mapping = self._get_host_roles_mapping(host_id)
            deployed_pk_config[const.ROLES_MAPPING] = roles_mapping
        else:
            roles_mapping = deployed_pk_config[const.ROLES_MAPPING]

        return deepcopy(roles_mapping)

    def get_host_ipmi_info(self, host_id):
        ipmi_info = self.__get_host_item(host_id, const.IPMI, {})

        if not ipmi_info:
            return (None, None, None)

        ipmi_ip = ipmi_info[const.IP_ADDR]
        ipmi_user = ipmi_info[const.IPMI_CREDS][const.USERNAME]
        ipmi_pass = ipmi_info[const.IPMI_CREDS][const.PASSWORD]

        return (ipmi_ip, ipmi_user, ipmi_pass)

    def get_adapter_name(self):
        return self.__get_adapter_item(const.NAME, None)

    def get_dist_system_name(self):
        return self.__get_adapter_item(const.NAME, None)

    def get_adapter_health_check_cmd(self):
        return self.__get_adapter_item(const.HEALTH_CHECK_CMD)

    def get_os_installer_settings(self):
        installer_info = self.__get_adapter_item(const.OS_INSTALLER, {})
        return installer_info.setdefault(const.INSTALLER_SETTINGS, {})

    def get_pk_installer_settings(self):
        installer_info = self.__get_adapter_item(const.PK_INSTALLER, {})
        return installer_info.setdefault(const.INSTALLER_SETTINGS, {})

    def get_os_config_metadata(self):
        metadata = self.__get_adapter_item(const.METADATA, {})
        return metadata.setdefault(const.OS_CONFIG, {})

    def get_pk_config_meatadata(self):
        metadata = self.__get_adapter_item(const.METADATA, {})
        return metadata.setdefault(const.PK_CONFIG, {})

    def get_adapter_all_flavors(self):
        return self.__get_adapter_item(const.FLAVORS, [])

    def get_adapter_flavor(self, flavor_name):
        flavors = self.__get_adapter_item(const.FLAVORS, [])
        for flavor in flavors:
            if flavor[const.FLAVOR_NAME] == flavor_name:
                return flavor

        return None

    def _get_host_roles_mapping(self, host_id):
        """The format will be the same as cluster roles mapping."""
        network_mapping = self.get_host_network_mapping(host_id)
        if not network_mapping:
            return {}

        hostname = self.get_hostname(host_id)
        roles = self.get_host_roles(host_id)
        interfaces = self.get_host_interfaces(host_id)

        mapping = {}
        net_info = {const.HOSTNAME: hostname}
        for k, v in network_mapping:
            nic = v[const.NIC]
            if nic in interfaces:
                net_info[k] = self.get_host_interface_config(host_id, nic)
                net_info[k][const.NIC] = nic

        for role in roles:
            role = role.replace("-", "_")
            mapping[role] = net_info

        return mapping
