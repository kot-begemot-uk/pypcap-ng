''' Pure python implementation of the pcap language parser.
Compiler backends - U32TC.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import sys
import re
import ipaddress
from header_constants import ETHER, IP, IP6, ETH_PROTOS
from code_objects import AbstractCode, AbstractHelper


# Some of the names are predefined. They are instruction names. We
# should not change them.
#pylint: disable=line-too-long, invalid-name, consider-using-f-string


IPV4_REGEXP = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")



SIZE_MODS = [None, "u8", "u16", None, "u32"]

# U32TC instruction as described in the literature is not an instruction
# when using our abstractions. It is a mini-program which consists f
# LD (absolute or index), SHL or SHR, AND and a comparison - a total
# of four instructions

LD_OP = 0
SH_OP = 1
AND_OP = 2
COMP_OP = 3

class U32TCCode(AbstractCode):
    '''U32TC variant of code generation'''
    def __init__(self, sel_type, selector, size=4, val=None, mask=None, at=None):
        super().__init__()
        self.sel_type = sel_type
        self.selector = selector
        self.val = val
        self.mask = mask
        self.size = size
        self.at = at

    def validate(self):
        '''Perform validation of the values supplied to the constructor'''
        check = 1 << self.size
        if check < self.val or check < self.mask:
            raise ValueError("Argument size exceeded")

    def obj_dump(self, counter):
        '''Dump bytecode'''
        return f"{counter} {self}\n"

    def __repr__(self):
        '''Same as repr'''
        return f"{self}"

    def __str__(self):
        '''Printable form of U32TC instructions'''

        if self.sel_type is None:
            return f"match {self.selector} {self.val} {self.mask} {self.at}"

        if self.val is not None:
            return f"match {self.sel_type} {self.selector} {self.val} {self.mask}"

        return f"match {self.sel_type} {self.selector}"

V4_NET_REGEXP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class U32TCHelper(AbstractHelper):
    '''U32TC variant of AbstractHelper'''

    def __init__(self, pcap_obj=None):
        super().__init__(pcap_obj)
        self.helper_id = "u32tc"

    def dump_code(self, fmt, options):
        '''Dump U32'''

        super().dump_code(fmt, options)

        res = ""
        
        for insn in self.get_code():
            res += f"{insn}\n"

        return res


    @property
    def offset(self):
        '''match_object getter'''
        try:
            return self.attribs["offset"]
        except KeyError:
            return 0


    @property
    def loc(self):
        '''match_object getter'''
        return self.pcap_obj.loc


    @property
    def match_object(self):
        '''match_object getter'''
        return self.attribs["match_object"]

    @property
    def on_success(self):
        '''on_success getter'''
        return self.attribs["on_success"]

    @property
    def on_failure(self):
        '''on_failure getter'''
        return self.attribs["on_failure"]

    @property
    def attribs(self):
        '''attribs getter'''
        return self.pcap_obj.attribs

    @property
    def frags(self):
        '''frags getter'''
        return self.pcap_obj.frags

    @property
    def left(self):
        '''left getter'''
        return self.pcap_obj.left

    @property
    def right(self):
        '''right getter'''
        return self.pcap_obj.right

    @property
    def ip_version(self):
        '''right getter'''
        return self.pcap_obj.ip_version

class U32TCProgL3(U32TCHelper):
    '''Layer 3 protocol matcher'''
    def compile(self, compiler_state=None):
        '''Compile the code'''
        super().compile(compiler_state)
        self.add_code([U32TCCode(
            None,
            "u8",
            self.match_object,
            0xFF,
            at=9
        )])


class U32TCProgIPv4(U32TCHelper):
    '''Basic match on v4 address or network.
    '''
    def compile(self, compiler_state=None):
        '''Generate the actual code for the match'''
        try:
            addr = ipaddress.ip_address(self.match_object)
        except ValueError:
            # we let it raise a value error in this case
            addr = ipaddress.ip_network(self.match_object)

        # we do not do any further checks, because regexps
        # should narrow the input to ip_address sufficiently
        # to guarantee a v4 of some sort.


        super().compile(compiler_state)

        if "srcordst" in self.pcap_obj.quals or "srcanddst" in self.pcap_obj.quals:
            return
        if "src" in self.pcap_obj.quals:
            qual = "src"
        elif "dst" in self.pcap_obj.quals:
            qual = "dst"
        else:
            raise ValueError("Must specify src or dst")

        self.add_code([U32TCCode(
            "ip",
            f"{qual} {addr}"
        )])


class U32TCProgIPv6(U32TCHelper):
    '''Basic match on v4 address or network.
    '''
    def compile(self, compiler_state=None):
        '''Generate the actual code for the match'''
        try:
            addr = ipaddress.ip_address(self.match_object)
        except ValueError:
            # we let it raise a value error in this case
            addr = ipaddress.ip_network(self.match_object)

        super().compile(compiler_state)

        if "srcordst" in self.pcap_obj.quals or "srcanddst" in self.pcap_obj.quals:
            return

        if isinstance(addr, ipaddress.IPv6Network):
            mask = addr.prefixlen
            value = str(addr.network_address)
        else:
            mask = "128"
            value = str(addr)

        if "src" in self.pcap_obj.quals:
            qual = "src"
        elif "dst" in self.pcap_obj.quals:
            qual = "dst"
        else:
            raise ValueError("Must specify src or dst")

        self.add_code([U32TCCode(
            "ip",
            qual,
            f"{addr}/{mask}"
        )])


class U32TCProgNOT(U32TCHelper):
    '''Negate the result of all frags.
    '''
    def compile(self, compiler_state=None):
        '''Compile NOT - inverse true and false'''
        raise ValueError("NOT not supported in U32TC")


class U32TCProgOR(U32TCHelper):
    '''Perform logical OR on left and right frag(s)
    '''
    def compile(self, compiler_state=None):
        '''Compile OR - inverse true and false'''
        raise ValueError("NOT not supported in U32TC")

def dispatcher(obj):
    '''Return the correct code helper'''
    try:
        return getattr(sys.modules[__name__], f"U32TC{obj.__class__.__name__}")(obj)
    except (KeyError, AttributeError):
        return U32TCHelper(obj)
