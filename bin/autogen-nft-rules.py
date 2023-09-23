#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import collections.abc
import contextlib
import enum
import errno
import functools
import ipaddress
import itertools
import os
import os.path
import pathlib
import re
import sys

# import dataclasses
from dataclasses import dataclass, field

import yaml

RE_NAME_SEP = re.compile(r'[_\-]+')
RE_NAME_STRIP_NORMALIZE = re.compile(r'[^a-z0-9_]')

IP4_LINK_LOCAL = ipaddress.IPv4Network('169.254.0.0/16')
IP6_LINK_LOCAL = ipaddress.IPv6Network('fe80::/10')

ANY_ZONE = object()

NFT_NAME_PREFIX = 'autogen_'


@enum.unique
class ZoneForwardConfiguration(enum.IntEnum):
    (
        BY_SRC_DST,
        BY_DST
    ) = range(2)
# --- end of ZoneForwardConfiguration ---


@enum.unique
class ZoneClassification(enum.IntEnum):
    (
        UNDEF,
        INTERNAL,
        EXTERNAL,
        DMZ,
        VPN,
        FWSYNC,

        # virtual classifications (not configurable)
        LOCAL_SITE,
    ) = range(7)
# --- end of ZoneClassification ---


class ObjDefCollection(collections.abc.Mapping):
    __slots__ = ['data']

    def __init__(self, data=None):
        super().__init__()
        self.data = {}
        if data:
            self.data.update(data)
    # --- end of __init__ (...) ---

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, obj):
        self.data[key] = obj

# --- end of ObjDefCollection ---


class IPObjDefCollection(ObjDefCollection):
    __slots__ = []

    def iter_net_ip4(self):
        for obj in self.data.values():
            yield from obj.iter_net_ip4()
    # --- end of iter_net_ip4 (...) ---

    def get_net_ip4(self):
        return list(ipaddress.collapse_addresses(self.iter_net_ip4()))
    # --- end of get_net_ip4 (...) ---

    def iter_net_ip6(self):
        for obj in self.data.values():
            yield from obj.iter_net_ip6()
    # --- end of iter_net_ip6 (...) ---

    def get_net_ip6(self):
        return list(ipaddress.collapse_addresses(self.iter_net_ip6()))
    # --- end of get_net_ip6 (...) ---

# --- end of IPObjDefCollection ---


class InterfacesCollection(IPObjDefCollection):
    __slots__ = []

    def add_interfaces(self, interfaces):
        for iface in interfaces:
            self.data[iface.name] = iface
    # --- end of add_interfaces (...) ---

    def iter_interfaces(self):
        return self.data.values()
    # --- end of iter_interfaces (...) ---

    def iter_zones(self):
        zones_seen = set()

        for iface in self.iter_interfaces():
            zone = iface.zone
            if (zone is not None) and (zone not in zones_seen):
                zones_seen.add(zone)
                yield zone
        # --
    # --- end of iter_zones (...) ---

    def get_zones(self):
        zones = ZonesCollection()
        zones.add_zones(self.iter_zones())

        return zones
    # --- end of get_zones (...) ---

# --- end of InterfacesCollection ---


class ZonesCollection(IPObjDefCollection):
    __slots__ = []

    def add_zone(self, zone):
        self.data[zone.name] = zone
    # --- end of add_zone (...) ---

    def add_zones(self, zones):
        for zone in zones:
            self.add_zone(zone)
    # --- end of add_zones (...) ---

    def iter_zones(self):
        return self.data.values()
    # --- end of iter_zones (...) ---

    def iter_interfaces(self):
        for zone in self.iter_zones():
            for iface in zone.interfaces.values():
                yield iface
    # --- end of iter_interfaces (...) ---

    def get_interfaces(self):
        ifaces = InterfacesCollection()
        ifaces.add_interfaces(self.iter_interfaces())
        return ifaces
    # --- end of get_interfaces (...) ---

# --- end of ZonesCollection ---


@dataclass
class InterfaceDef:
    name            : str
    norm_name       : str
    zone            : ZoneDef
    zone_ref        : str

    cluster_ip4     : list[ipaddress.IPv4Interface]
    primary_ip4     : list[ipaddress.IPv4Interface]
    fallback_ip4    : list[ipaddress.IPv4Interface]
    nat_ip4         : list[ipaddress.IPv4Interface]
    routes_ip4      : dict[ipaddress.IPv4Network, ipaddress.IPv4Address]

    cluster_ip6     : list[ipaddress.IPv6Interface]
    primary_ip6     : list[ipaddress.IPv6Interface]
    fallback_ip6    : list[ipaddress.IPv6Interface]
    nat_ip6         : list[ipaddress.IPv6Interface]
    routes_ip6      : dict[ipaddress.IPv6Network, ipaddress.IPv6Address]

    def get_ip4(self, is_primary):
        ip_list = (self.primary_ip4 if is_primary else self.fallback_ip4)
        try:
            return ip_list[0]
        except IndexError:
            return None
    # --- end of get_ip4 (...) ---

    def get_ip6(self, is_primary):
        ip_list = (self.primary_ip6 if is_primary else self.fallback_ip6)
        try:
            return ip_list[0]
        except IndexError:
            return None
    # --- end of get_ip6 (...) ---

    def _iter_ip(self, ip_link_local, ip_list):
        for ip_obj in ip_list:
            if (ip_obj is not None) and (ip_obj not in ip_link_local):
                yield ip_obj
    # --- end of _iter_ip (...) ---

    def iter_all_ip4(self):
        return self._iter_ip(
            IP4_LINK_LOCAL,
            itertools.chain(
                self.cluster_ip4,
                self.primary_ip4,
                self.fallback_ip4,
            )
        )
    # --- end of iter_all_ip4 (...) ---

    def get_all_ip4(self):
        return sorted(self.iter_all_ip4())
    # --- end of get_all_ip4 (...) ---

    def iter_node_ip4(self):
        return self._iter_ip(
            IP4_LINK_LOCAL,
            itertools.chain(
                self.primary_ip4,
                self.fallback_ip4,
            )
        )
    # --- end of iter_node_ip4 (...) ---

    def get_node_ip4(self):
        return sorted(self.iter_node_ip4())
    # --- end of get_node_ip4 (...) ---

    def iter_all_ip6(self):
        return self._iter_ip(
            IP6_LINK_LOCAL,
            itertools.chain(
                self.cluster_ip6,
                self.primary_ip6,
                self.fallback_ip6,
            )
        )
    # --- end of iter_all_ip6 (...) ---

    def get_all_ip6(self):
        return sorted(self.iter_all_ip6())
    # --- end of get_all_ip6 (...) ---

    def iter_node_ip6(self):
        return self._iter_ip(
            IP6_LINK_LOCAL,
            itertools.chain(
                self.primary_ip6,
                self.fallback_ip6,
            )
        )
    # --- end of iter_node_ip6 (...) ---

    def get_node_ip6(self):
        return sorted(self.iter_node_ip6())
    # --- end of get_node_ip6 (...) ---

    def iter_net_ip4(self):
        ip4_link_local = IP4_LINK_LOCAL  # ref

        for ip_obj in self.iter_all_ip4():
            yield ip_obj.network
        # --

        for ip_obj in self.nat_ip4:
            if ip_obj not in ip4_link_local:
                yield ip_obj.network
        # --

        for net_obj in self.routes_ip4:
            if net_obj not in ip4_link_local:
                yield net_obj
        # --
    # --- end of iter_net_ip4 (...) ---

    def get_net_ip4(self):
        return list(ipaddress.collapse_addresses(self.iter_net_ip4()))
    # --- end of get_net_ip4 (...) ---

    def iter_net_ip6(self):
        ip6_link_local = IP6_LINK_LOCAL  # ref

        for ip_obj in self.iter_all_ip6():
            yield ip_obj.network
        # --

        for ip_obj in self.nat_ip6:
            if ip_obj not in ip6_link_local:
                yield ip_obj.network
        # --

        for net_obj in self.routes_ip6:
            if net_obj not in ip6_link_local:
                yield net_obj
        # --
    # --- end of iter_net_ip6 (...) ---

    def get_net_ip6(self):
        return list(ipaddress.collapse_addresses(self.iter_net_ip6()))
    # --- end of get_net_ip6 (...) ---

# --- end of InterfaceDef ---


@dataclass
class ZoneDef:
    name            : str
    classification  : ZoneClassification
    interfaces      : InterfacesCollection = field(
        init=False, default_factory=InterfacesCollection
    )
    forward_dst     : bool = field(default=True)
    forward_src     : bool = field(default=True)

    def iter_all_ip4(self):
        for iface in self.interfaces.values():
            yield from iface.iter_all_ip4()
    # --- end of iter_all_ip4 (...) ---

    def get_all_ip4(self):
        return sorted(self.iter_all_ip4())
    # --- end of get_all_ip4 (...) ---

    def iter_node_ip4(self):
        for iface in self.interfaces.values():
            yield from iface.iter_node_ip4()
    # --- end of iter_node_ip4 (...) ---

    def get_node_ip4(self):
        return sorted(self.iter_node_ip4())
    # --- end of get_node_ip4 (...) ---

    def iter_net_ip4(self):
        for iface in self.interfaces.values():
            yield from iface.iter_net_ip4()
    # --- end of iter_net_ip4 (...) ---

    def get_net_ip4(self):
        return list(ipaddress.collapse_addresses(self.iter_net_ip4()))
    # --- end of get_net_ip4 (...) ---

    def iter_all_ip6(self):
        for iface in self.interfaces.values():
            yield from iface.iter_all_ip6()
    # --- end of iter_all_ip6 (...) ---

    def get_all_ip6(self):
        return sorted(self.iter_all_ip6())
    # --- end of get_all_ip6 (...) ---

    def iter_node_ip6(self):
        for iface in self.interfaces.values():
            yield from iface.iter_node_ip6()
    # --- end of iter_node_ip6 (...) ---

    def get_node_ip6(self):
        return sorted(self.iter_node_ip6())
    # --- end of get_node_ip6 (...) ---

    def iter_net_ip6(self):
        for iface in self.interfaces.values():
            yield from iface.iter_net_ip6()
    # --- end of iter_net_ip6 (...) ---

    def get_net_ip6(self):
        return list(ipaddress.collapse_addresses(self.iter_net_ip6()))
    # --- end of get_net_ip6 (...) ---

# --- end of ZoneDef ---


@dataclass
class ForwardZoneCombination:
    src   : Optional[ZoneDef]
    dst   : Optional[ZoneDef]
    chain : str
# --- end of ForwardZoneCombination ---


@dataclass
class FirewallConfig:
    zones        : ZonesCollection = field(init=False, default_factory=ZonesCollection)
    interfaces   : InterfacesCollection = field(init=False, default_factory=InterfacesCollection)
    forward_type : ZoneForwardConfiguration = field(init=False, default=None)

    # initialized later on
    interfaces_combo    : list = field(init=False, default=None)
    zones_combo         : list = field(init=False, default=None)
    # zones_forward_combo : list of 3-tuple (zsrc, zdst, forward chain name)
    zones_forward_combo : list[ForwardZoneCombination] = field(init=False, default=None)

# --- end of FirewallConfig ---


class FilterChainTemplate(object):
    __slots__ = ['name', 'template']

    RE_TEMPLATE_VAR = re.compile('@@(?P<vname>[A-Za-z0-9_]*)@@')

    RE_NAME = re.compile('@@NAME@@')

    def __init__(self, name, template):
        super().__init__()
        self.name     = name
        self.template = template
    # --- end of __init__ (...) ---

    def render(self, name):
        vmap = {
            '':     '@@',
            'type': self.name,
            'name': name,
        }

        def vlookup(re_match):
            key = re_match.group('vname').lower()

            try:
                repl = vmap[key]
            except KeyError:
                raise KeyError(re_match.group('vname'), self.name)
            else:
                return repl
        # --- end of vlookup (...) ---

        return self.RE_TEMPLATE_VAR.sub(vlookup, self.template)
    # --- end of render (...) ---

# --- end of FilterChainTemplate ---


def normalize_name(iface_name):
    return RE_NAME_STRIP_NORMALIZE.sub(
        '',
        RE_NAME_SEP.sub('_', iface_name.lower())
    )
# --- end of normalize_name (...) ---


def dict_namesort(d):
    return [v for k, v in sorted(d.items(), key=lambda kv: kv[0])]
# --- end of dict_namesort (...) ---


def load_config(filepath):
    is_listlike     = lambda a: (not isinstance(a, str) and (hasattr(a, '__iter__') or hasattr(a, '__next__')))
    listify         = lambda a: (list(a) if is_listlike(a) else [a])

    mkobj           = lambda cls, a: (cls(a) if a is not None else None)
    mkobj_bool      = lambda a, b: (a if a is not None else b)
    mkobj_ip4       = functools.partial(mkobj, ipaddress.IPv4Interface)
    mkobj_ip6       = functools.partial(mkobj, ipaddress.IPv6Interface)

    mkobj_list      = lambda cls, av: ([cls(a) for a in listify(av)] if av is not None else [])
    mkobj_list_ip4  = functools.partial(mkobj_list, ipaddress.IPv4Interface)
    mkobj_list_ip6  = functools.partial(mkobj_list, ipaddress.IPv6Interface)

    def mkobj_dict_routes(cls_net, cls_addr, yroutes):
        if yroutes:
            return {
                cls_net(arg_net): cls_addr(arg_addr)
                for arg_net, arg_addr in yroutes.items()
            }

        else:
            return {}
    # --- end of mkobj_dict_routes (...) ---

    mkobj_dict_routes_ip4 = functools.partial(
        mkobj_dict_routes, ipaddress.IPv4Network, ipaddress.IPv4Address
    )

    mkobj_dict_routes_ip6 = functools.partial(
        mkobj_dict_routes, ipaddress.IPv6Network, ipaddress.IPv6Address
    )

    def mkobj_zone_forward_configuration(yfwd):
        if not yfwd:
            return ZoneForwardConfiguration.BY_DST

        else:
            yfwd_norm = yfwd.strip().lower()

            if yfwd_norm in {'dst'}:
                return ZoneForwardConfiguration.BY_DST

            elif yfwd_norm in {'src-dst'}:
                return ZoneForwardConfiguration.BY_SRC_DST

            else:
                raise ValueError('unknown zone forward configuration', yfwd)
    # --- end of mkobj_zone_forward_configuration (...) ---

    def mkobj_zone_classification(ytype):
        if not ytype:
            return ZoneClassification.UNDEF

        else:
            ytype_norm = ytype.strip().lower()

            if ytype_norm in {'internal', 'lan'}:
                return ZoneClassification.INTERNAL

            elif ytype_norm in {'external', 'wan'}:
                return ZoneClassification.EXTERNAL

            elif ytype_norm in {'dmz'}:
                return ZoneClassification.DMZ

            elif ytype_norm in {'vpn'}:
                return ZoneClassification.VPN

            elif ytype_norm in {'fwsync'}:
                return ZoneClassification.FWSYNC

            else:
                raise ValueError('unknown zone classification', ytype)
    # --- end of mkobj_zone_classification (...) ---

    def load_config_zones(fw_config, yzones):
        for name, yzone in yzones.items():
            if name in fw_config.zones:
                raise KeyError("redefinition of zone", name)

            else:
                zone_def = ZoneDef(
                    name            = name,
                    classification  = mkobj_zone_classification(yzone.get('type')),
                    forward_src     = mkobj_bool(yzone.get('forward_src'), True),
                    forward_dst     = mkobj_bool(yzone.get('forward_dst'), True),
                )

                fw_config.zones[name] = zone_def
            # -- end if
        # -- end for
    # --- end of load_config_zones (...) ---

    def load_config_interfaces(fw_config, yifaces):
        for name, yiface in yifaces.items():
            if name in fw_config.interfaces:
                raise KeyError("redefinition of interface", name)

            else:
                norm_name = normalize_name(name)
                if not norm_name:
                    raise ValueError("Could not normalize interface name", name)
                # --

                iface_def = InterfaceDef(
                    name            = name,
                    norm_name       = norm_name,
                    zone            = None,
                    zone_ref        = (yiface.get('zone') or norm_name),

                    cluster_ip4     = mkobj_list_ip4(yiface.get('cluster_ip4')),
                    primary_ip4     = mkobj_list_ip4(yiface.get('primary_ip4')),
                    fallback_ip4    = mkobj_list_ip4(yiface.get('fallback_ip4')),
                    nat_ip4         = mkobj_list_ip4(yiface.get('nat_ip4')),
                    routes_ip4      = mkobj_dict_routes_ip4(yiface.get('routes_ip4')),

                    cluster_ip6     = mkobj_list_ip6(yiface.get('cluster_ip6')),
                    primary_ip6     = mkobj_list_ip6(yiface.get('primary_ip6')),
                    fallback_ip6    = mkobj_list_ip6(yiface.get('fallback_ip6')),
                    nat_ip6         = mkobj_list_ip6(yiface.get('nat_ip6')),
                    routes_ip6      = mkobj_dict_routes_ip6(yiface.get('routes_ip6')),
                )

                fw_config.interfaces[name] = iface_def
            # -- end if
        # -- end for
    # --- end of load_config_interfaces (...) ---

    with open(filepath, 'rt') as fh:
        yaml_config = yaml.safe_load(fh)
    # -- end with

    fw_config = FirewallConfig()

    fw_config.forward_type = mkobj_zone_forward_configuration(
        yaml_config.get('forward_type')
    )

    try:
        yzones = yaml_config['zones']
    except KeyError:
        pass
    else:
        if yzones is not None:
            if not isinstance(yzones, dict):
                raise TypeError("invalid config data type for zones, must be dict", yzones)

            load_config_zones(fw_config, yzones)
        # --
    # -- end try

    try:
        yifaces = yaml_config['interfaces']
    except KeyError:
        pass
    else:
        if yifaces is not None:
            if not isinstance(yifaces, dict):
                raise TypeError("invalid config data type for interfaces, must be dict", yifaces)

            load_config_interfaces(fw_config, yifaces)
        # --
    # -- end try

    # link zones and interfaces
    for iface_def in fw_config.interfaces.values():
        try:
            zone_def = fw_config.zones[iface_def.zone_ref]

        except KeyError:
            # hot-add stub zone def
            zone_def = ZoneDef(
                name=iface_def.zone_ref,
                classification=ZoneClassification.UNDEF
            )
            fw_config.zones[zone_def.name] = zone_def
        # --

        iface_def.zone = zone_def
        zone_def.interfaces[iface_def.name] = iface_def
    # -- end for

    # generate zones/interfaces combinations
    fw_config.interfaces_combo    = list(gen_interface_combinations(fw_config))
    fw_config.zones_combo         = list(gen_zone_combinations(fw_config))

    if fw_config.forward_type == ZoneForwardConfiguration.BY_DST:
        fw_config.zones_forward_combo = [
            ForwardZoneCombination(ANY_ZONE, zdst, f'{zdst.name}')
            for zdst in fw_config.zones.iter_zones()
            if zdst.forward_dst
        ]

    elif fw_config.forward_type == ZoneForwardConfiguration.BY_SRC_DST:
        fw_config.zones_forward_combo = [
            ForwardZoneCombination(zsrc, zdst, f'{zsrc.name}_to_{zdst.name}')
            for zsrc, zdst in gen_zone_forward_src_dst_combinations(fw_config)
        ]

    else:
        raise NotImplementedError(fw_config.forward_type)
    # --

    return fw_config
# --- end of load_config (...) ---


def gen_interface_combinations(fw_config, *, filter_src=None, filter_oth=None):
    fn_true = lambda z: True

    if filter_src is None:
        filter_src = fn_true
    # --

    if filter_oth is None:
        filter_oth = fn_true
    # --

    ifaces_list = dict_namesort(fw_config.interfaces)

    for iface_src in ifaces_list:
        if filter_src(iface_src):
            iface_othv = InterfacesCollection()
            iface_othv.add_interfaces((
                iface_oth for iface_oth in ifaces_list
                if (iface_oth is not iface_src) and filter_oth(iface_oth)
            ))

            yield (iface_src, iface_othv)
        # -- end if
    # -- end for
# --- end of gen_interface_combinations (...) ---


def gen_zone_combinations(fw_config, *, filter_src=None, filter_oth=None):
    fn_true = lambda z: True

    if filter_src is None:
        filter_src = fn_true
    # --

    if filter_oth is None:
        filter_oth = fn_true
    # --

    zones_list = dict_namesort(fw_config.zones)

    for za in zones_list:
        if filter_src(za):
            zothv = ZonesCollection()
            zothv.add_zones((
                zb for zb in zones_list
                if (zb is not za) and filter_oth(zb)
            ))

            yield (za, zothv)
        # --
    # -- end for
# --- end of gen_zone_combinations (...) ---


def gen_zone_forward_src_dst_combinations(fw_config):
    for zsrc, zdstv in gen_zone_combinations(
        fw_config,
        filter_src=lambda z: z.forward_src,
        filter_oth=lambda z: z.forward_dst
    ):
        for zdst in zdstv.iter_zones():
            yield (zsrc, zdst)
# --- end of gen_zone_forward_src_dst_combinations (...) ---


def get_argument_parser(prog):
    arg_parser = argparse.ArgumentParser(
        prog=os.path.splitext(os.path.basename(prog))[0]
    )

    arg_parser.add_argument(
        "config",
        help="path to the configuration file"
    )

    arg_parser.add_argument(
        '-O', '--output',
        dest='output_dir',
        required=True,
        help='output directory'
    )

    arg_parser.add_argument(
        '-T', '--templates',
        dest='template_dir',
        help='templates directory'
    )

    return arg_parser
# --- end of get_argument_parser (...) ---


def idedup(items):
    seen = set()

    for item in items:
        if item not in seen:
            seen.add(item)
            yield item
# --- end of idedup (...) ---


def gen_nft_set(name, set_type, items=None, *, flags=None, quote_value=True):
    ii = 4 * ' '

    yield f'set {name} {{'
    yield f'{ii}type {set_type};'
    if flags:
        yield '{ii}flags {};'.format(', '.join(flags), ii=ii)
    # --

    if items:
        yield ''
        yield f'{ii}elements = {{'

        if quote_value:
            for item in idedup(items):
                yield f'{ii}{ii}"{item!s}",'
        else:
            for item in idedup(items):
                yield f'{ii}{ii}{item!s},'
        # -- quote or not
        yield f'{ii}}};'
    # -- end if

    yield '};'
# --- end of gen_nft_set (...) ---


def gen_nft_ip_set(name, ipver, items, *, flags=['constant', 'interval']):
    return gen_nft_set(name, f'ipv{ipver:d}_addr', items, flags=flags, quote_value=False)
# --- end of gen_nft_ip_set (...) ---


def gen_nft_ifname_set(name, items, *, flags=['constant']):
    return gen_nft_set(name, 'ifname', items, flags=flags, quote_value=True)
# --- end of gen_nft_ifname_set (...) ---


def gen_fwrules_base_sets(fw_config):
    # virtual classifications
    # - local site := internal | dmz
    zclass_set_local_site = {
        ZoneClassification.INTERNAL,
        ZoneClassification.DMZ,
    }

    zclass_map = {
        zclass: ZonesCollection()
        for zclass in ZoneClassification
    }

    for zone in fw_config.zones.iter_zones():
        zclass_map[zone.classification].add_zone(zone)

        # add to virtual classifications
        if zone.classification in zclass_set_local_site:
            zclass_map[ZoneClassification.LOCAL_SITE].add_zone(zone)
    # --

    # by zone classification: interfaces, networks
    for zclass, zones in sorted(zclass_map.items(), key=lambda kv: kv[0]):
        zclass_name = zclass.name.lower()
        iface_list = [iface.name for iface in zones.iter_interfaces()]

        # interfaces
        yield ''
        yield f'# interfaces within the {zclass.name} zone classification'
        yield from gen_nft_ifname_set(
            f'{NFT_NAME_PREFIX}iface_class_{zclass_name}',
            sorted(iface_list)
        )

        # IPv4 networks
        yield ''
        yield f'# IPv4 networks within the {zclass.name} zone classification'
        yield from gen_nft_ip_set(
            f'{NFT_NAME_PREFIX}net4_class_{zclass_name}',
            4,
            zones.get_net_ip4()
        )

        # IPv6 networks
        yield ''
        yield f'# IPv6 networks within the {zclass.name} zone classification'
        yield from gen_nft_ip_set(
            f'{NFT_NAME_PREFIX}net6_class_{zclass_name}',
            6,
            zones.get_net_ip6()
        )
    # -- end for

    # by zone: interfaces, IP addresses, networks
    for zone in sorted(fw_config.zones.iter_zones(), key=lambda z: z.name):
        iface_list = [
            iface.name
            for iface in zone.interfaces.iter_interfaces()
        ]

        # interfaces
        yield ''
        yield f'# interfaces within the {zone.name} zone'
        yield from gen_nft_ifname_set(
            f'{NFT_NAME_PREFIX}iface_zone_{zone.name}',
            sorted(iface_list)
        )

        # IPv4 addresses
        yield ''
        yield f'# firewall IPv4 addresses within the {zone.name} zone'
        yield from gen_nft_ip_set(
            f'{NFT_NAME_PREFIX}fw4_zone_{zone.name}',
            4,
            [ip_obj.ip for ip_obj in zone.get_all_ip4()]
        )

        # IPv4 networks
        yield ''
        yield f'# firewall IPv4 addresses within the {zone.name} zone'
        yield from gen_nft_ip_set(
            f'{NFT_NAME_PREFIX}net4_zone_{zone.name}',
            4,
            zone.get_net_ip4()
        )

        # IPv6 addresses
        yield ''
        yield f'# firewall IPv6 addresses within the {zone.name} zone'
        yield from gen_nft_ip_set(
            f'{NFT_NAME_PREFIX}fw6_zone_{zone.name}',
            6,
            [ip_obj.ip for ip_obj in zone.get_all_ip6()]
        )

        # IPv6 networks
        yield ''
        yield f'# firewall IPv6 addresses within the {zone.name} zone'
        yield from gen_nft_ip_set(
            f'{NFT_NAME_PREFIX}net6_zone_{zone.name}',
            6,
            zone.get_net_ip6()
        )
    # -- end for

# --- end of gen_fwrules_base_sets (...) ---


def gen_fwrules_antispoof(fw_config):
    def drop_my_net(my_ip_list, oth_ip_list):
        # O^2
        for oth_ip_net in oth_ip_list:
            if not any((
                ((oth_ip_net == my_ip_net) or my_ip_net.subnet_of(oth_ip_net))
                for my_ip_net in my_ip_list
            )):
                yield oth_ip_net
    # ---

    def fancy_format_ip_set(ip_list):
        idx_last_ip = len(ip_list) - 1

        if idx_last_ip < 1:
            return '{{{ip_set}}}'.format(
                ip_set=', '.join(map(str, oth_ip6_list))
            )

        else:
            text_blocks = ['{ \\\n']

            for k, ip_net in enumerate(ip_list):
                text_blocks.append(
                    '        {ip_net}{sep} \\\n'.format(
                        ip_net=ip_net,
                        sep=('' if (k >= idx_last_ip) else ',')
                    )
                )
            # --

            text_blocks.append('      }')

            return ''.join(text_blocks)
        # --
    # --- end of fancy_format_ip_set (...) ---

    yield ''
    yield '# antispoofing (prerouting chain)'
    yield f'chain {NFT_NAME_PREFIX}prerouting_antispoof {{'

    is_first = True

    for ia, ibv in fw_config.interfaces_combo:
        # Do not mark own networks shared with other interfaces as spoofed.
        # In certain scenarios, interfaces may share the same IPv4 network.
        # Example: alias IP address on Hetzner root server
        # realized by using a secondary WAN interface.

        my_ip4_list = ia.get_net_ip4()
        my_ip6_list = ia.get_net_ip6()

        oth_ip4_list = sorted(drop_my_net(my_ip4_list, ibv.get_net_ip4()))
        oth_ip6_list = sorted(drop_my_net(my_ip6_list, ibv.get_net_ip6()))

        if oth_ip4_list or oth_ip6_list:
            if not is_first:
                yield ''

            yield f'    #> interface {ia.name}'

            if oth_ip4_list:
                yield (
                    '    iifname {iface} \\\n'
                    '      ip saddr {ip_set} \\\n'
                    '      counter drop comment "antispoof on {iface}";'
                ).format(
                    iface=ia.name,
                    ip_set=fancy_format_ip_set(oth_ip4_list)
                )
            # --

            if oth_ip6_list:
                if oth_ip4_list:
                    yield ''
                # --

                yield (
                    '    iifname {iface} \\\n'
                    '      ip6 saddr {ip_set} \\\n'
                    '      counter drop comment "antispoof on {iface}";'
                ).format(
                    iface=ia.name,
                    ip_set=fancy_format_ip_set(oth_ip6_list)
                )
            # --

            is_first = False
        # -- end if antispoof for iface
    # -- end for

    yield '};'
# --- end of gen_fwrules_antispoof (...) ---


def gen_fwrules_forward_table(fw_config):
    # +2 for sorrounding quotes
    max_namelen = max(
        (len(iface.name) for iface in fw_config.interfaces.iter_interfaces()),
        default=0
    ) + 2

    set_name = f'{NFT_NAME_PREFIX}forward_jump_table'

    if fw_config.forward_type == ZoneForwardConfiguration.BY_DST:
        template_fwd = (
            f'        {{dst:<{max_namelen}}} : jump forward_{{fwd_chain}},'
        )

        yield '# forward zones jump table (output iface => chain)'
        yield f'#   use with: oifname vmap @{set_name};'
        yield f'map {set_name} {{'
        yield '    type ifname : verdict;'

        if fw_config.zones_forward_combo:
            yield ''
            yield '    elements = {'

            for zfwd in fw_config.zones_forward_combo:
                for dst_iface in sorted(zfwd.dst.interfaces):
                    yield template_fwd.format(
                        dst=f'"{dst_iface}"',
                        fwd_chain=zfwd.chain
                    )
                # -- end for forward dst iface
            # -- end for forward combo

            yield '  };'
        # -- end if

        yield '};'

    elif fw_config.forward_type == ZoneForwardConfiguration.BY_SRC_DST:
        template_fwd = (
            f'        {{src:<{max_namelen}}} . {{dst:<{max_namelen}}} : jump forward_{{fwd_chain}},'
        )

        yield '# forward zones jump table (input iface X output iface => chain)'
        yield f'#   use with: iifname . oifname vmap @{set_name};'
        yield f'map {set_name} {{'
        yield '    type ifname . ifname : verdict;'

        if fw_config.zones_forward_combo:
            yield ''
            yield '    elements = {'

            for zfwd in fw_config.zones_forward_combo:
                for src_iface in sorted(zfwd.src.interfaces):
                    for dst_iface in sorted(zfwd.dst.interfaces):
                        yield template_fwd.format(
                            src=f'"{src_iface}"',
                            dst=f'"{dst_iface}"',
                            fwd_chain=zfwd.chain
                        )
                    # -- end for forward dst iface
                # -- end for forward src iface
            # -- end for forward combo

            yield '  };'
        # -- end if

        yield '};'

    else:
        raise NotImplementedError('forward type', fw_config.forward_type)
    # --
# --- end of gen_fwrules_forward_table (...) ---


def gen_fwrules_generic_zones_lookup_table(fw_config, lookup_type, kw_match):
    # +2 for sorrounding quotes
    max_namelen = max(
        (len(iface.name) for iface in fw_config.interfaces.iter_interfaces()),
        default=0
    ) + 2

    template_jump = f'        {{iface:<{max_namelen}}} : jump {{jump_chain}},'

    set_name = f'{NFT_NAME_PREFIX}{lookup_type}_jump_table'

    yield f'# {lookup_type} zones jump table (iface => chain)'
    yield f'#   use with: {kw_match} vmap @{set_name};'
    yield f'map {set_name} {{'
    yield '    type ifname : verdict;'

    if fw_config.interfaces:  # all zones empty if no interfaces configured
        yield ''
        yield '    elements = {'

        for zone in sorted(fw_config.zones.iter_zones(), key=lambda z: z.name):
            jump_chain = f'{lookup_type}_{zone.name}'

            for iface in sorted(zone.interfaces):
                yield template_jump.format(iface=f'"{iface}"', jump_chain=jump_chain)
            # -- end for
        # -- end for zone

        yield '    };'
    # -- end if

    yield '};'
# --- end of gen_fwrules_generic_zones_lookup_table (...) ---


def gen_fwrules_generic_interfaces_lookup_table(fw_config, lookup_type, kw_match):
    # +2 for sorrounding quotes
    max_namelen = max(
        (len(iface.name) for iface in fw_config.interfaces.iter_interfaces()),
        default=0
    ) + 2

    template_jump = f'        {{iface:<{max_namelen}}} : jump {{jump_chain}},'

    set_name = f'{NFT_NAME_PREFIX}{lookup_type}_jump_table'

    yield f'# {lookup_type} zones jump table (iface => chain)'
    yield f'#   use with: {kw_match} vmap @{set_name};'
    yield f'map {set_name} {{'
    yield '    type ifname : verdict;'

    if fw_config.interfaces:  # all zones empty if no interfaces configured
        yield ''
        yield '    elements = {'

        for iface in sorted(fw_config.interfaces.iter_interfaces(), key=lambda i: i.name):
            jump_chain = f'{lookup_type}_{iface.norm_name}'

            yield template_jump.format(iface=f'"{iface.name}"', jump_chain=jump_chain)
            # -- end for
        # -- end for zone

        yield '    };'
    # -- end if

    yield '};'
# --- end of gen_fwrules_generic_interfaces_lookup_table (...) ---


@contextlib.contextmanager
def open_write_text_file(filepath, overwrite=False):
    fh = None

    open_flags = (os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NOCTTY)
    if not overwrite:
        open_flags |= os.O_EXCL

    try:
        fd = os.open(filepath, open_flags, mode=0o644)

    except OSError as oserr:
        if oserr.errno == errno.EEXIST:
            yield None

        else:
            raise

    else:
        try:
            fh = os.fdopen(fd, 'wt')

        except:
            os.close(fd)
            raise
        # --

        yield fh

    finally:
        if fh is not None and not fh.closed:
            fh.close()
# --- end of open_write_text_file (...) ---


def load_filter_chain_template(template_dir, template_name):
    template_file = template_dir / f'{template_name}.nft.in'

    with open(template_file, 'rt') as fh:
        template_data = fh.read().rstrip()
    # -- end with

    return FilterChainTemplate(template_name, template_data)
# --- end of load_filter_chain_template (...) ---


def main(prog, argv):
    arg_parser   = get_argument_parser(prog)
    arg_config   = arg_parser.parse_args(argv)
    outdir       = pathlib.Path(arg_config.output_dir)
    template_dir = pathlib.Path(
        arg_config.template_dir
        or os.path.join(os.getcwd(), 'templates')
    )

    fw_config = load_config(arg_config.config)

    filter_match_kw = {
        'input'             : 'iifname',
        'output'            : 'oifname',
        'prerouting'        : 'iifname',
        'postrouting'       : 'oifname',
        'nat_prerouting'    : 'iifname',
        'nat_postrouting'   : 'oifname',
    }

    zone_filter_chains = [
        'input',
        'output',
    ]

    iface_filter_chains = [
        'prerouting',
        'postrouting',
        'nat_prerouting',
        'nat_postrouting',
    ]

    # build up the generated nft rules file
    autogen_rules = [
        '## auto-generated nft rules',
    ]

    #> base sets
    autogen_rules.extend(gen_fwrules_base_sets(fw_config))

    #> forward table
    autogen_rules.append("")
    autogen_rules.extend(gen_fwrules_forward_table(fw_config))

    #> zone filter chains
    for filter_chain in zone_filter_chains:
        autogen_rules.append("")
        autogen_rules.extend(
            gen_fwrules_generic_zones_lookup_table(
                fw_config, filter_chain,
                filter_match_kw[filter_chain]
            )
        )
    # --

    #> interface filter chains
    for filter_chain in iface_filter_chains:
        autogen_rules.append("")
        autogen_rules.extend(
            gen_fwrules_generic_interfaces_lookup_table(
                fw_config, filter_chain,
                filter_match_kw[filter_chain]
            )
        )
    # --

    #> prerouting: antispoof
    autogen_rules.extend(gen_fwrules_antispoof(fw_config))

    # create per-interface/zone files where missing
    for filter_chains, filter_names in [
        (['forward'], [zfwd.chain for zfwd in fw_config.zones_forward_combo]),
        (zone_filter_chains, sorted(fw_config.zones)),
        (
            iface_filter_chains,
            sorted(
                [i.norm_name for i in fw_config.interfaces.iter_interfaces()]
            )
        ),
    ]:
        for filter_chain in filter_chains:
            filter_chain_template = None
            filter_chain_outdir = outdir / filter_chain

            os.makedirs(filter_chain_outdir, exist_ok=True)

            for name in filter_names:
                outfile = filter_chain_outdir / f'{name}.nft'

                with open_write_text_file(outfile, overwrite=False) as fh:
                    if fh is not None:
                        print("NEW", outfile)
                        try:
                            if filter_chain_template is None:
                                filter_chain_template = load_filter_chain_template(
                                    template_dir, filter_chain
                                )
                            # --

                            fh.write(filter_chain_template.render(name) + "\n")

                        except:
                            # clean up on error, then reraise
                            fh.close()
                            outfile.unlink()
                            raise
                        # -- end try
                    # -- end new file?
                # -- end with open file
            # -- end for name
        # -- end for filter_chain, ...
    # -- end for filter_chains, ...

    autogen_rules_outdir = outdir / 'gen' / 'global'
    autogen_rules_outfile = autogen_rules_outdir / 'autogen.nft'

    os.makedirs(autogen_rules_outdir, exist_ok=True)
    with open(autogen_rules_outfile, 'wt') as fh:
        fh.write("\n".join(autogen_rules) + "\n")
    # --
# --- end of main (...) ---


if __name__ == "__main__":
    exit_code = None

    try:
        exit_code = main(sys.argv[0], sys.argv[1:])

    except KeyboardInterrupt:
        exit_code = os.EX_OK ^ 130

    else:
        if (exit_code is None) or (exit_code is True):
            exit_code = os.EX_OK

        elif (exit_code is False):
            exit_code = os.EX_OK ^ 1
    # --

    sys.exit(exit_code)
# -- end if
