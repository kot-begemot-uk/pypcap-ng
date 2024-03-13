#!/usr/bin/python3

'''Generic compiler frontend'''

import sys
import json
from argparse import ArgumentParser
import subprocess
from ipaddress import IPv6Address, IPv6Network, ip_address, ip_network
import code_objects
import bpf_objects
import u32_objects
import u32_tc_objects
from policy import PolicyEntry, FirewallPolicy

HELPERS = [
    ("u32", u32_objects.dispatcher),
    ("u32tc", u32_tc_objects.dispatcher),
    ("cbpf", bpf_objects.dispatcher),
]

ACTION_MAP = {
    "Deny": "DROP",
    "Allow": "ACCEPT"
}

def is_v6(address):
    '''Check if an address is v6'''
    try:
        addr = ip_address(address)
        if isinstance(addr, IPv6Address):
            return True
    except ValueError:
        # we let it raise a value error in this case
        addr = ip_network(address)

    return isinstance(addr, IPv6Network)



def process_icmp(p_cfg, cidr):
    '''Process ICMP'''
    pcap_expr = []
    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp[icmptype] == {}".format(p_cfg["icmp"]["icmpType"]))
    except KeyError:
        pass

    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp[icmpcode] == {}".format(p_cfg["icmp"]["icmpCode"]))
    except KeyError:
        pass

    if len(pcap_expr) == 0:
        raise ValueError("Failed to process firewall policy")

    if len(pcap_expr) == 1:
        #pylint: disable=consider-using-f-string
        return "src {} and {}".format(cidr, pcap_expr[0])

    #pylint: disable=consider-using-f-string
    return "src {} and {}".format(cidr, " and ".join(pcap_expr))

def process_icmp_v6(p_cfg, cidr):
    '''Process ICMP'''
    pcap_expr = []
    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp6[icmptype] == {}".format(p_cfg["icmpv6"]["icmpType"]))
    except KeyError:
        pass

    try:
        #pylint: disable=consider-using-f-string
        pcap_expr.append("icmp6[icmpcode] == {}".format(p_cfg["icmpv6"]["icmpCode"]))
    except KeyError:
        pass

    if len(pcap_expr) == 0:
        raise ValueError("Failed to process firewall policy")

    if len(pcap_expr) == 1:
        #pylint: disable=consider-using-f-string
        return "src {} and {}".format(cidr, pcap_expr[0])

    #pylint: disable=consider-using-f-string
    return "src {} and {}".format(cidr, " and ".join(pcap_expr))


def process_proto(proto, p_cfg, cidr):
    '''Process TCP/UDP/SCTP'''
    pcap_expr = []

    #pylint: disable=consider-using-f-string
    if "-" in p_cfg[proto]["ports"]:
        pcap_expr.append("portrange {}".format(p_cfg[proto]["ports"]))
    else:
        pcap_expr.append("port {}".format(p_cfg[proto]["ports"]))
    if len(pcap_expr) == 0:
        raise ValueError("Failed to process firewall policy")

    #pylint: disable=consider-using-f-string
    return "src {} and {} dst {}".format(cidr, proto, pcap_expr[0])

def form_tc_args(interface, rule, options):
    '''Form iptables arguments'''

    res = ""

    tc_bin = "/sbin/tc"

    try:
        code = rule.dump_code("u32tc", "iptables", options)
        if len(code) > 0:
            res = f"{tc_bin} filter add dev {interface} "
            res += f"parent ffff: prio 1 u32 {code} action drop skip_sw"
    except KeyError:
        pass

    return res

def form_args(interface, rule, mode, options):
    '''Form iptables arguments'''

    res = ""

    u32_ok = False

    if rule.v6:
        iptables = "/sbin/ip6tables"
    else:
        iptables = "/sbin/iptables"

    if mode in ["u32", "auto"]:
        try:
            code = rule.dump_code("u32", "iptables", options)
            if len(code) > 0:
                res = f"{iptables} -A IFW -j {rule.action} -i {interface} -m u32  --u32 '{code}'"
                u32_ok = True
        except KeyError:
            pass

    if not u32_ok and mode in ["cbpf", "auto"]:
        try:
            code = rule.dump_code("cbpf", "iptables", options)
            if len(code) > 0:
                res = f"{iptables} -A IFW -j {rule.action} -i {interface} -m bpf --bpf '{code}'"
        except KeyError:
            pass

    return res

def dry_run_u32_apply_fn(interface, rule, options):
    '''Dry run function - print the rules which will be applied'''
    print(form_args(interface, rule, "u32", options))
    return True

def dry_run_u32tc_apply_fn(interface, rule, options):
    '''Dry run function - print the rules which will be applied'''
    print(form_tc_args(interface, rule, options))
    return True

def dry_run_cbpf_apply_fn(interface, rule, options):
    '''Dry run function - print the rules which will be applied'''
    print(form_args(interface, rule, "cbpf", options))
    return True

def iptables_u32_apply_fn(interface, rule, options):
    '''Apply via iptables'''
    try:
        subprocess.run(form_args(interface, rule, "u32", options), shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def iptables_u32tc_apply_fn(interface, rule, options):
    '''Apply via tc'''
    try:
        subprocess.run(form_tc_args(interface, rule, options), shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def iptables_cbpf_apply_fn(interface, rule, options):
    '''Apply via iptables'''
    try:
        subprocess.run(form_args(interface, rule, "cbpf", options), shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

IF_FLUSH_DATA = [
    "/sbin/tc filter del dev {} prio 1",
    "/sbin/tc qdisc del dev {} handle ffff:"
]

FLUSH_DATA = [
    "/sbin/iptables -F IFW",
    "/sbin/ip6tables -F IFW",
]

IF_PREAMBLE_DATA = IF_FLUSH_DATA.copy()
IF_PREAMBLE_DATA.extend([
    "/sbin/tc qdisc add dev {} ingress",
])

PREAMBLE_DATA = FLUSH_DATA.copy()
PREAMBLE_DATA.extend([
    "/sbin/iptables -D INPUT -j IFW",
    "/sbin/iptables -X IFW",
    "/sbin/iptables -N IFW",
    "/sbin/iptables -I INPUT -j IFW",

    "/sbin/ip6tables -D INPUT -j IFW",
    "/sbin/ip6tables -X IFW",
    "/sbin/ip6tables -N IFW",
    "/sbin/ip6tables -I INPUT -j IFW",
])

IF_CLOSURE_DATA = []

CLOSURE_DATA = [
    "/sbin/iptables -A IFW -j RETURN",
    "/sbin/ip6tables -A IFW -j RETURN"
]

def activate_fn(data):
    '''Global config stanzas'''
    subprocess.run(data, shell=True, check=False)

def dryrun_fn(data):
    '''Global config stanzas'''
    print(data)

PROTO_MAP = {
    "ICMP":process_icmp,
    "ICMPv6":process_icmp_v6,
    "TCP":lambda p_cfg, cidr : process_proto("tcp", p_cfg, cidr),
    "UDP":lambda p_cfg, cidr : process_proto("udp", p_cfg, cidr),
    "SCTP":lambda p_cfg, cidr : process_proto("sctp", p_cfg, cidr),
}

ACTIVATORS = {
    "dryrun-cbpf":dry_run_cbpf_apply_fn,
    "iptables-cbpf":iptables_cbpf_apply_fn,
    "dryrun-u32":dry_run_u32_apply_fn,
    "iptables-u32":iptables_u32_apply_fn,
    "dryrun-u32tc":dry_run_u32tc_apply_fn,
    "iptables-u32tc":iptables_u32tc_apply_fn
}

MODES = {
    "dryrun":dryrun_fn,
    "iptables":activate_fn
}

def activate(mode, data, iface=None):
    '''Mode specific Stanzas'''
    for item in data:
        try:
            MODES[mode](item.format(iface))
        except IndexError:
            MODES[mode](item)


def makefilter_rule(p_cfg, cidr):
    '''Generate an actual filter rule
       CIDR encodes the ip version of the rule required
       '''
    return PROTO_MAP[p_cfg["protocol"]](p_cfg, cidr)

class IngressFirewallPolicy(FirewallPolicy):
    '''Class representing an ingress firewall policy'''
    def __init__(self, interface, policy, options=None):
        super().__init__()
        self.policy = policy
        self.in_hardware = []
        self.interface = interface
        self.options = options

    def generate_pcap(self):
        '''Convert policy to the same form as pcap output'''
        for item in self.policy:
            for cidr in item["sourceCIDRs"]:
                for rule in item["rules"]:
                    self.add_entry(
                        PolicyEntry(
                            ACTION_MAP[rule["action"]],
                            makefilter_rule(rule["protocolConfig"], cidr),
                            order=rule["order"],
                            model=rule,
                            v6=is_v6(cidr)
                        )
                    )

    def compile_pcap(self):
        '''Compile the actual rules'''
        for rule in self.rules:
            #pylint: disable=unused-variable
            rule.parse()
            rule.drop_type(code_objects.ProgL2)
            for (name, helper) in HELPERS:
                # we drop L2 for now. Both u32 offload and netfilter work
                # with L3 frames omitting the L2 header.
                # In fact, according to the comments in the driver code, U32 L2 not supported
                rule.add_helper(helper)
            rule.compile()

    def apply_to_hardware(self, apply_fn, offload=False):
        '''Apply Policy'''
        for rule in self.rules:
            result = apply_fn(self.interface, rule, self.options)
            if offload and result:
                self.in_hardware.append(rule)

    def dump_rules(self, software=True):
        '''Dump all rules that have not been applied'''
        result = []
        if software:
            for rule in self.rules:
                result.append(rule.model)
        else:
            for rule in self.in_hardware:
                result.append(rule.model)

        return result

def main():
    '''Load an ingress firewall ruleset'''

    model = json.load(sys.stdin)

    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
       '--mode',
        help='mode of operation dryrun, iptables',
        type=str,
        default="dryrun"
    )
    aparser.add_argument(
       '--backend',
        help='backend - u32, bpf',
        type=str,
        default="u32"
    )
    aparser.add_argument(
       '--debug',
        help='debug',
        action='store_true'
    )
    aparser.add_argument(
       '--flush',
        help='flush iptables',
        action='store_true'
    )

    args = vars(aparser.parse_args())

    if args["flush"]:
        activate(args["mode"], FLUSH_DATA)
        for interface in model:
            activate(args["mode"], IF_FLUSH_DATA, interface)


    activate(args["mode"], PREAMBLE_DATA)
    for (interface, policy) in model.items():
        activate(args["mode"], IF_PREAMBLE_DATA, interface)
        ingress = IngressFirewallPolicy(interface, policy)
        ingress.generate_pcap()
        if args.get("debug"):
            for rule in ingress.rules:
                print(rule.pfilter)
        ingress.compile_pcap()
        if args.get("debug"):
            for rule in ingress.rules:
                for helper in rule.compiled.code.keys():
                    print(rule.compiled.get_code(helper))
        ingress.apply_to_hardware(ACTIVATORS["{}-{}".format(args["mode"], "u32tc", True)])
        ingress.apply_to_hardware(ACTIVATORS["{}-{}".format(args["mode"], args["backend"])])
        activate(args["mode"], IF_CLOSURE_DATA, interface)

    ingress.apply_to_hardware(ACTIVATORS["{}-{}".format(args["mode"], args["backend"])])
    activate(args["mode"], CLOSURE_DATA)


if __name__ == "__main__":
    main()
