import typing
from ansible.errors import AnsibleError
import ipaddress
import re


class NmAnsibleNetworkAddressFact():
    """ NmAnsibleNetworkAddressFact クラスは、
    Ansible Fact の "ansible_network" に含まれる "addresses" のエントリに対するデータモデルです。

        ```
        "ipv4": {
            "address": "192.168.100.100",
            "broadcast": "192.168.100.255",
            "netmask": "255.255.255.0",
            "network": "192.168.100.0",
            "prefix": "24"
        },
        "ipv6": [
            {
                "address": "2001:db8::71f::146",
                "prefix": "64",
                "scope": "global"
            },
            {
                "address": "fe80::1111:1111:0:0",
                "prefix": "64",
                "scope": "link"
            }
        ]
        ```
    """

    def __init__(self, address_fact: dict) -> None:
        # required
        self._address = ipaddress.ip_address(address_fact['address'])
        self._prefix = int(address_fact['prefix'])
        # optional
        self._broadcast = None
        self._netmask = None
        self._network = None
        if address_fact.get('broadcast'):
            self._broadcast = ipaddress.ip_address(address_fact['broadcast'])
        if address_fact.get('netmask'):
            self._netmask = ipaddress.ip_address(address_fact['netmask'])
        if address_fact.get('network'):
            self._network = ipaddress.ip_address(address_fact['network'])

    @property
    def address(self) -> ipaddress._IPAddressBase:
        return self._address
    
    @property
    def broadcast(self) -> ipaddress._IPAddressBase:
        if self._broadcast:
            return self._broadcast
        else:
            return self.network_cidr.broadcast_address

    @property
    def netmask(self) -> ipaddress._IPAddressBase:
        if self._netmask:
            return self._netmask
        else:
            return self.network_cidr.netmask

    @property
    def network(self) -> ipaddress._IPAddressBase:
        if self._network:
            return self._network
        else:
            return self.network_cidr.network_address

    @property
    def prefix(self) -> int:
        return self._prefix
    
    @property
    def version(self) -> int:
        return self._address.version

    @property
    def network_cidr(self) -> ipaddress._BaseNetwork:
        return ipaddress.ip_network(f'{str(self.address)}/{self._prefix}',
                                    strict=False)

    def serialize(self) -> dict:
        return {
            'address': str(self.address),
            'broadcast': str(self.broadcast),
            'netmask': str(self.netmask),
            'network': str(self.network),
            'prefix': str(self.prefix)
        }


class NmAnsibleNetworkInterfaceFact():
    """ NmAnsibleNetworkInterfaceFact クラスは、
    Ansible Fact の "ansible_interfaces" に含まれるインターフェース一つに対するデータモデルです。
    ただし、エラー抑制のために必要な箇所のみプロパティ実装されています。
    """

    def __init__(self, address_fact: dict) -> None:
        self._rawdata = address_fact
        self._device = address_fact['device']
        self._macaddress = address_fact['macaddress']
        self._ipv4 = address_fact.get('ipv4')
        self._ipv4_secondaries = address_fact.get('ipv4_secondaries')
        self._ipv6 = address_fact.get('ipv6')
        self._ipv6_secondaries = address_fact.get('ipv6_secondaries')
        self._type = address_fact['type']
        self._active = address_fact['active']

    @property
    def device(self) -> str:
        return self._device

    @property
    def macaddress(self) -> str:
        return self._macaddress

    @property
    def ipv4(self) -> list[NmAnsibleNetworkAddressFact]:
        if not self._ipv4:
            return []
        if isinstance(self._ipv4, list):
            return [NmAnsibleNetworkAddressFact(a) for a in self._ipv4]
        else:
            return [NmAnsibleNetworkAddressFact(self._ipv4)]

    @property
    def ipv4_secondaries(self) -> list[NmAnsibleNetworkAddressFact]:
        return [NmAnsibleNetworkAddressFact(a) for a in self._ipv4_secondaries] if self._ipv4_secondaries else []

    @property
    def ipv6(self) -> list[NmAnsibleNetworkAddressFact]:
        if not self._ipv6:
            return []
        if isinstance(self._ipv6, list):
            return [NmAnsibleNetworkAddressFact(a) for a in self._ipv6]
        else:
            return [NmAnsibleNetworkAddressFact(self._ipv6)]

    @property
    def ipv6_secondaries(self) -> list[NmAnsibleNetworkAddressFact]:
        return [NmAnsibleNetworkAddressFact(a) for a in self._ipv6_secondaries] if self._ipv6_secondaries else []
    
    @property
    def type(self) -> str:
        return self._type
    
    @property
    def active(self) -> bool:
        return self._active
    
    @property
    def all_ip_addresses(self) -> list[NmAnsibleNetworkAddressFact]:
        return [*self.ipv4,
                *self.ipv6,
                *self.ipv4_secondaries,
                *self.ipv6_secondaries]


class NmNetworkRouteEntry():
    """ NmNetworkRouteEntry クラスは、
    "netspec_settings"の中の "routes" 及び "extra_routes" に対するデータモデルです。
    """

    def __init__(self, route: dict) -> None:
        try:
            self._to = ipaddress.ip_network(route['to'], strict=True)
            self._via = route['via']
        except KeyError:
            raise AnsibleError(
                f'Invalid attribute, "to" or "via" is not exist in a network route "{route}".')
        except ValueError:
            raise AnsibleError(
                f'Invalid attribute, "to" is not valid in a network route "{route}".')
        if route.get('metric') is not None:
            self._metric = int(route['metric'])
        else:
            self._metric = None

    @property
    def to(self) -> ipaddress._BaseNetwork:
        """ to は、ルートの宛先ネットワークを表します。
        これはipaddress._BaseNetwork クラスのインスタンスです。
        """
        return self._to
    
    @property
    def via(self) -> typing.Union[str, int]:
        """ via は、ルートの経由先Gatewayを表します。
        この値は、文字列または整数値です。
        文字列の場合、IPアドレスとして解釈されます。
        整数値の場合、対象インターフェースのIPアドレスが所属するネットワークアドレスを元にGatewayアドレスが算出されます。
        正の整数値の場合、ネットワークアドレスからのオフセットアドレスとして解釈されます。
        負の整数値の場合、ブロードキャストアドレスからのオフセットアドレスとして解釈されます。
        """
        return self._via

    @property
    def metric(self) -> typing.Optional[int]:
        """ metric は、ルートのメトリックを表します。
        数値で表現されます。この値は必須ではありません。
        """
        return self._metric

    @property
    def network_class(self) -> int:
        """ このプロパティは他の値から自動で算出されます。
        この経路がIPv4の場合は4、IPv6の場合は6を返します。
        """
        if isinstance(self._to, ipaddress.IPv4Network):
            return 4
        elif isinstance(self._to, ipaddress.IPv6Network):
            return 6
        else:
            raise AnsibleError(
                f'Invalid attribute, "to" is unknown in network version "{self._to}".')

    def serialize(self) -> dict:
        """ このインスタンスを生成元のfactと同じデータ構造に変換します。
        """
        data = {
            'to': str(self._to),
            'via': self.via,
        }
        if self._metric is not None:
            data['metric'] = str(self._metric)
        return data

    def resolve_gateway(self, address_fact: NmAnsibleNetworkAddressFact) -> ipaddress._BaseAddress:
        if isinstance(self._via, int):
            if self._via >= 0:
                gw = address_fact.network_cidr.network_address + self._via
            else:
                gw = address_fact.network_cidr.broadcast_address + self._via
        else:
            gw = ipaddress.ip_address(self._via)
        return gw


class NmNetworkResolvedRouteEntry(NmNetworkRouteEntry):
    """ NmNetworkResolvedRouteEntry クラスは、
    "netspec_settings"の中の "routes" 及び "extra_routes" に対するデータモデルです。
    """
    def __init__(self, route: dict, address_fact: NmAnsibleNetworkAddressFact) -> None:
        super().__init__(route)
        self._binded_address = address_fact
        self._gateway = self.resolve_gateway(address_fact)

    @property
    def binded_address(self) -> NmAnsibleNetworkAddressFact:
        """ binded_address は、このルートがバインドされたアドレス情報です。
        """
        return self._binded_address

    # override
    @property
    def via(self) -> typing.Union[str, int]:
        return str(self.gateway)

    @property
    def gateway(self) -> ipaddress._BaseAddress:
        """ gateway は、このルートの経由先Gatewayです。
        """
        return self._gateway
    
    def serialize(self) -> dict:
        """ このインスタンスを生成元のfactと同じデータ構造に変換します。
        """
        data = super().serialize()
        data['gateway'] = str(self._gateway)
        data['gateway_resolved'] = True
        data['protocol_version'] = self.gateway.version
        return data


class NmNetworkMatchRule():
    """ NmNetworkMatchRule クラスは、
    "netspec_settings"の中の "match" に対するデータモデルです。
    インターフェースが持つアドレスとNetworkSettingEntryのマッチングを行うための情報です。
    "type"の値によりマッチ方法が異なり、実際の実装は"type"に応じた拡張クラスで行われます。
    """

    def __init__(self, name, rule) -> None:
        """ コンストラクタです。引数にネットワーク名とルールを取ることに注意してください。
        """
        self._type = rule.get('type', 'cidr')
        self._value = rule.get('value')
        if self._value is None:
            raise AnsibleError(
                f'Invalid attribute, "value" is not exist in a network match rule "{name}".')
        if self._type not in self.__class__.available_rule_types:
            raise AnsibleError(
                f'Invalid attribute, "type" is not acceptable in a network match rule "{name}". '
                f'Only "{self.__class__.available_rule_types}" are available.')

    @property
    def type(self) -> str:
        """ type は、ルールの種類を表します。
        有効な値は、"cidr" と "regex" です。
        """
        return self._type

    @property
    def value(self) -> str:
        """ value は、ルールの値を表します。
        "type"の値により解釈が異なります。
        """
        return self._value

    def is_matched(self, address: ipaddress._IPAddressBase) -> bool:
        """ このルールが特定のアドレスにマッチするかどうかを判定します。 """
        raise NotImplementedError()

    def serialize(self) -> dict:
        """ このインスタンスを生成元のfactと同じデータ構造に変換します。 """
        return {
            'type': self._type,
            'value': self._value
        }

    # Static section
    available_rule_types = ['cidr', 'regex']

    @classmethod
    def make_instance(cls, name: str, rule: dict) -> 'NmNetworkMatchRule':
        """ これはクラスメソッドです。"type"の値に応じた拡張クラスのインスタンスを生成するクラスファクトリ関数です。 """
        t = rule.get('type')
        if t == 'cidr':
            return NmNetworkMatchRuleByCIDR(name=name, rule=rule)
        elif t == 'regex':
            return NmNetworkMatchRuleByRegex(name=name, rule=rule)
        else:
            raise AnsibleError(
                f'Invalid attribute, "type" is not acceptable in a network match rule. '
                f'Only "{cls.available_rule_types}" are available.')


class NmNetworkMatchRuleByCIDR(NmNetworkMatchRule):
    """ NmNetworkMatchRuleByCIDR クラスは、
    NmNetworkMatchRule クラスの拡張クラスであり、 "type" が "cidr" の場合の実装です。
    ネットワークアドレスに所属するかどうかでマッチングを行います。
    """

    def __init__(self, name: str, rule: dict) -> None:
        super().__init__(name, rule)
        self._typed_value = ipaddress.ip_network(self._value)

    @property
    def typed_value(self) -> ipaddress._BaseNetwork:
        """ この拡張クラス固有のデータ型に変換された "value" の値を返します。 """
        return self._typed_value

    def is_matched(self, address: ipaddress._IPAddressBase) -> bool:
        """ このルールが特定のアドレスにマッチするかどうかを判定します。 """
        return address in self._typed_value


class NmNetworkMatchRuleByRegex(NmNetworkMatchRule):
    """ NmNetworkMatchRuleByRegex クラスは、
    NmNetworkMatchRule クラスの拡張クラスであり、 "type" が "regex" の場合の実装です。
    正規表現によるマッチングを行います。
    """

    def __init__(self, name: str, rule: dict) -> None:
        super().__init__(name, rule)
        self._typed_value = re.compile(self._value, re.ASCII)

    @property
    def typed_value(self) -> re.Pattern:
        """ この拡張クラス固有のデータ型に変換された "value" の値を返します。 """
        return self._typed_value

    def is_matched(self, address: ipaddress._IPAddressBase) -> bool:
        """ このルールが特定のアドレスにマッチするかどうかを判定します。 """
        return self._typed_value.search(str(address)) is not None


class NetworkSettingEntry():
    """ NetworkSettingEntry クラスは、
    "netspec_settings"の中のエントリに対するデータモデルです。
    """

    def __init__(self, name: str, network_setting: dict) -> None:
        """ コンストラクタです。引数にネットワーク名と設定の両方を取ることに注意してください。
        """
        self._name = name
        self._match = []
        self._routes = []
        self._extra_routes = []
        self._dns_servers = []
        self._dns_search = []

        for rule in network_setting.get('match', []):
            self._match.append(
                NmNetworkMatchRule.make_instance(
                    name=self._name, rule=rule))

        for route in network_setting.get('routes', []):
            self._routes.append(NmNetworkRouteEntry(route))

        for route in network_setting.get('extra_routes', []):
            self._extra_routes.append(NmNetworkRouteEntry(route))

        for dns_server in network_setting.get('dns_servers', []):
            self._dns_servers.append(ipaddress.ip_address(dns_server))

        for dns_search in network_setting.get('dns_search', []):
            if re.match(r'^[a-zA-Z0-9\.\-]+$', dns_search):
                self._dns_search.append(dns_search)
            else:
                raise AnsibleError(
                    f'Invalid attribute, "dns_search" is not acceptable in a network setting. '
                    f'Only "[a-zA-Z0-9.-]+" are available.')

    def clone(self) -> 'NetworkSettingEntry':
        """ このインスタンスのクローンを生成します。 """
        return NetworkSettingEntry(self._name, self.serialize())

    @property
    def match(self) -> list[NmNetworkMatchRule]:
        """ "match" に対応します。特定のアドレスにマッチするかどうかを判定するためのルールです。
        """
        return self._match

    @property
    def routes(self) -> list[NmNetworkRouteEntry]:
        """ "route" に対応します。ルーティングテーブルのエントリです。
        """
        return self._routes

    @property
    def extra_routes(self) -> list[NmNetworkRouteEntry]:
        """ "extra_routes" に対応します。追加のルーティングテーブルのエントリです。
        """
        return self._extra_routes

    @property
    def dns_servers(self) -> list[ipaddress._IPAddressBase]:
        """ "dns_servers" に対応します。DNSサーバのアドレスです。
        """
        return self._dns_servers

    @property
    def dns_search(self) -> list[str]:
        """ "dns_search" に対応します。DNSサーバの検索ドメインです。
        """
        return self._dns_search

    def is_matched(self, address: ipaddress._IPAddressBase):
        for m in self.match:
            m: NmNetworkMatchRule
            if m.is_matched(address):
                return True
        return False

    def serialize(self):
        """ このインスタンスをfact向けのデータ構造に変換します。
        """
        return {
            'match': [m.serialize() for m in self._match],
            'routes': [r.serialize() for r in self._routes],
            'extra_routes': [r.serialize() for r in self._extra_routes],
            'dns_servers': list(map(str, self._dns_servers)),
            'dns_search': self._dns_search
        }

    def clone_and_bind(self, address_info: NmAnsibleNetworkAddressFact) -> 'NetworkSettingEntry':
        """ このインスタンスを生成元のfact用に辞書データ構造に変換します。
        変換にあたり、特定のインターフェース、IPアドレスにバインドされた情報を付加します。
        """
        binded = self.clone()
        resolved_routes = []
        for route in binded.routes:
            if route.network_class == address_info.version:
                resolved_route = NmNetworkResolvedRouteEntry(route.serialize(), address_info)
                resolved_routes.append(resolved_route)
        binded._routes = resolved_routes

        resolved_routes = []
        for route in binded.extra_routes:
            if route.network_class == address_info.version:
                resolved_route = NmNetworkResolvedRouteEntry(route.serialize(), address_info)
                resolved_routes.append(resolved_route)
        binded._extra_routes = resolved_routes
        return binded


class NetSpec():
    """ NetSpec クラスは、
    特定のインターフェースにマッチしたのネットワーク設定の情報を保持するデータモデルです。
    このクラスの`serialize` 関数は、`netspec_organizer_find_network_interface_metadata`カスタムフィルタの出力として、
    Ansible Factに対してインターフェース設定用のメタ情報を付加するために使用されます。
    """
    
    def __init__(self,
                 interface: NmAnsibleNetworkInterfaceFact,
                 netspec_settings: dict[str, NetworkSettingEntry],
                 ) -> None:
        self._interface = interface
        self._netspec_settings = netspec_settings

    @property
    def interface(self) -> NmAnsibleNetworkInterfaceFact:
        return self._interface

    @property
    def netspec_settings(self) -> dict[str, NetworkSettingEntry]:
        return self._netspec_settings

    @property
    def network_names(self) -> list[str]:
        return list(self.netspec_settings.keys())

    @property
    def ipv4_routing_table(self) -> list[NmNetworkResolvedRouteEntry]:
        return self.get_routing_table(version=4)

    @property
    def ipv6_routing_table(self) -> list[NmNetworkResolvedRouteEntry]:
        return self.get_routing_table(version=6)

    @property
    def ipv4_default_route(self) -> typing.Optional[ipaddress.IPv4Address]:
        for r in self.ipv4_routing_table:
            if r.to.prefixlen == 0:
                return r.gateway  # type: ignore

    @property
    def ipv6_default_route(self) -> typing.Optional[ipaddress.IPv6Address]:
        for r in self.ipv6_routing_table:
            if r.to.prefixlen == 0:
                return r.gateway  # type: ignore

    @property
    def has_ipv4_default_route(self) -> bool:
        return any((r.to.prefixlen == 0 for r in self.ipv4_routing_table))

    @property
    def has_ipv6_default_route(self) -> bool:
        return any((r.to.prefixlen == 0 for r in self.ipv6_routing_table))

    @property
    def ipv4_dns_servers(self) -> list[ipaddress._IPAddressBase]:
        return [s for s in self.get_dns_servers() if s.version == 4]

    @property
    def ipv6_dns_servers(self) -> list[ipaddress._IPAddressBase]:
        return [s for s in self.get_dns_servers() if s.version == 6]

    @property
    def dns_search(self) -> list[str]:
        dns_search = []
        for setting in self.netspec_settings.values():
            if setting.dns_search:
                dns_search += setting.dns_search
        return dns_search

    def get_routing_table(self, version: typing.Optional[int] = None) -> list[NmNetworkResolvedRouteEntry]:
        routes = []
        for nw_name, nw_info in self.netspec_settings.items():
            if nw_info.routes:
                routes += nw_info.routes
            if nw_info.extra_routes:
                routes += nw_info.extra_routes
        def _filter(r):
            return (isinstance(r, NmNetworkResolvedRouteEntry)) \
                and (version is None or r.to.version == version)
        routes = list(filter(_filter, routes))
        return routes

    def get_dns_servers(self) -> list[ipaddress._IPAddressBase]:
        dns_servers = []
        for setting in self.netspec_settings.values():
            if setting.dns_servers:
                dns_servers += setting.dns_servers
        return dns_servers

    def serialize(self) -> dict[str, typing.Any]:
        """ このインスタンスをfact用の辞書データ構造に変換します。
        """
        dr_ipv4 = None
        dr_ipv6 = None
        if self.ipv4_default_route:
            dr_ipv4 = str(self.ipv4_default_route)
        if self.ipv6_default_route:
            dr_ipv6 = str(self.ipv6_default_route)
        return {
            'interface': self._interface.device,
            'network_names': self.network_names,
            'ipv4_routing_table': [s.serialize() for s in self.ipv4_routing_table],
            'ipv6_routing_table': [s.serialize() for s in self.ipv6_routing_table],
            'ipv4_default_route': dr_ipv4,
            'ipv6_default_route': dr_ipv6,
            'ipv4_dns_servers': [str(s) for s in self.ipv4_dns_servers],
            'ipv6_dns_servers': [str(s) for s in self.ipv6_dns_servers],
            'dns_search': self.dns_search,
        }


def netspec_organizer_build_netspec_settings(netspec_settings: dict, netspec_override_settings: dict = {}) -> dict:
    """ この関数は、"netspec_settings" と "netspec_override_settings" から、
    ネットワーク設定の情報を生成します。
    AnsibleのTaskから、下記のように呼び出されるFilterとして利用されます。
    
        ```yaml
        - name: netspec - Build network settings (with a custom filter plugin)
          ansible.builtin.set_fact:
            netspec_settings: >-
                {{ netspec_settings | netspec_organizer_build_netspec_settings(netspec_override_settings) }}
        ```
    """
    if not isinstance(netspec_settings, dict):
        raise AnsibleError(
            f'Invalid attribute, "netspec_settings" is not dict.')
    if not isinstance(netspec_override_settings, dict):
        raise AnsibleError(
            f'Invalid attribute, "netspec_override_settings" is not dict.')
    for name, properties in netspec_override_settings.items():
        name: str
        properties: dict
        if netspec_settings.get(name):
            netspec_settings[name].update(**properties)
        else:
            netspec_settings[name] = properties
    return netspec_settings


def netspec_organizer_find_network_interface_metadata(netspec_interfaces: list[dict], netspec_settings: dict[str, dict]) -> list[dict]:
    """ この関数は、Ansible Factが収集したネットワークインターフェースの一覧と"netspec_settings" を元に、
    インターフェースが所属するネットワークの対応付けを行い、"ansible_interfaces"側に情報を付加します。
    AnsibleのTaskから、下記のように呼び出されるFilterとして利用されます。
    
        ```yaml
        - name: netspec - search network interfaces
          ansible.builtin.set_fact:
            netspec_interfaces: "{{ (netspec_interfaces | default([])) + [ansible_facts[item]] }}"
          with_items: "{{ ansible_interfaces | reject('equalto', 'lo') }}"

        - name: netspec - Find network interface metadata (with a custom filter plugin)
          ansible.builtin.set_fact:
            netspec_interfaces: >-
                {{ netspec_interfaces | netspec_organizer_find_network_interface_metadata(netspec_settings) }}
        ```
    """
    settings = { k: NetworkSettingEntry(k, v) for k, v in netspec_settings.items() }
    for interface_info in netspec_interfaces:
        # Ansible Spec が収集したネットワークインターフェイス一つ分の情報をデータモデルに変換します。
        interface_fact = NmAnsibleNetworkInterfaceFact(interface_info)
        binded_netspec_settings: dict[str, NetworkSettingEntry] = {}
        # インターフェースが持つ全てのIPアドレス情報を順に評価します。
        for address_fact in interface_fact.all_ip_addresses:
            # 定義されたネットワーク設定の中から、アドレス情報にマッチするものを探します。
            for nw_name, nw_info in settings.items():
                if nw_info.is_matched(address_fact.address):
                    # マッチしたネットワーク設定を元に、
                    # インターフェースのアドレス情報にバインドされた設定を生成します。
                    binded_netspec_settings[nw_name] = nw_info.clone_and_bind(address_fact)
        # 最終的にネットワークインターフェースに付与する情報を生成します。
        netspec = NetSpec(interface_fact, binded_netspec_settings)
        interface_info['netspec'] = netspec.serialize()
    # 入力で受け取ったインターフェース配列を元に、各インターフェースに "netspec" を付与した配列を返します。
    return netspec_interfaces


def netspec_find_interfaces(netspec_interfaces: list[dict], network_name: str) -> list[dict]:
    """ この関数は、netspec-organizerが収集した "netspec_interfaces" から、
        対象のネットワーク名にマッチするインターフェースの一覧を返します。
    """
    results = []
    for netspec_interface in netspec_interfaces:
        if netspec_interface.get('netspec'):
            netspec = netspec_interface['netspec']
            if network_name in netspec['network_names']:
                results.append(netspec_interface)
        else:
            raise AnsibleError(
                f'Invalid attribute, "netspec" is not exist in a network interface "{netspec_interface}".') 
    return results


class FilterModule(object):

  def filters(self):
    return {
        'netspec_organizer_build_netspec_settings': netspec_organizer_build_netspec_settings,
        'netspec_organizer_find_network_interface_metadata': netspec_organizer_find_network_interface_metadata,
        'netspec_find_interfaces': netspec_find_interfaces,
    }
