# !/usr/bin/python3

''' pure python implementation of the pcap language parser
'''

#
# Copyright (c) 2022 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2022 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#
# Dual Licensed under the GNU Public License Version 2.0 and BSD 3-clause
#
#

from socket import gethostbyname
import ply.lex as lex
import ply.yacc as yacc
from lexer_defs import tokens
import lexer_defs
import code_objects
from header_constants import ETH_PROTOS, IP_PROTOS, LOC_CONSTANTS

precedence = (
    ('left', 'OR', 'AND'),
    ('nonassoc', 'NOT'),
    ('left', 'LSH', 'RSH'),
)

def p_operators(p):
    '''expression : binary_op
                  | negation
                  | brackets
                  | term
                  | comparisons
    '''
    p[0] = p[1]

def p_binary_operators(p):
    '''binary_op  : expression AND expression
                  | expression OR expression
    '''
    if p[2].lower() == 'or':
        p[0] = code_objects.ProgOR(left=p[1], right=p[3])
    else:
        p[0] = code_objects.ProgAND(left=p[1], right=p[3])

def p_comparisons(p):
    '''comparisons : arth LESS arth
                  | arth GREATER arth
                  | arth GEQ arth
                  | arth LEQ arth
                  | arth NEQ arth
                  | arth EQUAL arth
    '''

    p[0] = code_objects.ProgComp(op=p[2],left=p[1],right=p[3])


def p_brackets(p):
    '''brackets  : LPAREN expression RPAREN
    '''
    p[0] = p[2]

def p_negation(p):
    '''negation  : NOT expression'''
    p[0] = code_objects.ProgNOT(p[2])

def p_term(p):   
    '''term     : hterm
                | qterm
                | pname
                | other
    '''
    p[0] = p[1]

def p_hterm(p):   
    '''hterm    : head qterm
    '''
    p[2].add_frags(p[1])
    p[0] = p[2]


def p_qterm(p):   
    '''qterm    : quals id
    '''
    p[2].add_quals(p[1])
    p[0] = p[2]


def p_head(p):
    '''head     : pname 
	            | pname PROTO
	            | pname PROTOCHAIN
                | pname GATEWAY
                |
    '''
    if len(p) == 2:
        p[0] = p[1]
    elif len(p) == 2:
        raise TypeError("pname PROTO not yet supported")
        

def p_quals(p):
    '''quals    : dqual aqual
                | dqual
                | aqual
    '''
    p[0] = p[1]

       
def p_pname(p):
    '''pname    : LINK
                | IP
                | ARP
                | RARP
                | SCTP
                | TCP	
                | UDP
                | ICMP
                | IGMP
                | IGRP
                | PIM	
                | VRRP
                | CARP
                | ATALK
                | AARP	
                | DECNET
                | LAT
                | SCA
                | MOPDL
                | MOPRC
                | IPV6	
                | ICMPV6
                | AH
                | ESP
                | ISO
                | ESIS
                | ISIS
                | L1	
                | L2
                | IIH
                | LSP
                | SNP
                | PSNP
                | CSNP
                | CLNP
                | STP	
                | IPX
                | NETBEUI
                | RADIO
'''
    # protos with known header computations
    if p[1] == "ip":
        p[0] = code_objects.ProgIP()
    elif p[1] == "tcp":
        p[0] = code_objects.ProgTCP()
    else:
        if "6" in p[1]:
            ip_version = 6
        else:
            ip_version = 4
            
        try:
            p[0] = code_objects.ProgL2(ETH_PROTOS[p[1]])
        except KeyError:
            p[0] = code_objects.ProgL3(match_object=IP_PROTOS[p[1]], ip_version=ip_version)

def p_dqual(p):
    '''dqual : SRC
             | DST
             | ADDR1
             | ADDR2
             | ADDR3
             | ADDR4
             | RA
             | TA
             | srcordst
             | srcanddst
    '''
    p[0] = p[1:]

def p_srcordst(p):
    '''srcordst :  SRC OR DST
                 | DST OR SRC
    '''
    p[0] = "srcordst"
    
def p_srcanddst(p):
    '''srcanddst :  SRC AND DST
                 | DST AND SRC
    '''
    p[0] = "srcanddst"
    

def p_other(p):
    '''other    : bmcast
                | LESS NUM
                | GREATER NUM
                | INBOUND
                | OUTBOUND
                | IFINDEX NUM
                | VLAN NUM	
                | VLAN	
                | MPLS NUM	
                | MPLS
                | PPPOED
                | PPPOES NUM
                | PPPOES
                | GENEVE NUM
                | GENEVE
    '''
    pass

def p_bmcast(p):
    '''bmcast   : pname TK_BROADCAST
                | pname TK_MULTICAST
    '''
    pass
    

def p_aqual(p):
    '''aqual : HOST
             | NET
             | GATEWAY
    '''
    p[0] = p[1]

def p_id(p):
    '''id : addr
          | hostname
          | net
          | pload
          | pnum
          | portrange
    '''
    p[0] = p[1]

def p_pnum(p):
    '''pnum : PORT num
    '''
    p[0] = code_objects.ProgPort(frags=[p[2]])

def p_portrange(p):
    '''portrange : PORTRANGE num
    '''
    p[0] = code_objects.ProgPortRange(frags=[p[2]])


def p_num(p):
    '''num : arth
    '''
    p[0]=p[1]

def p_pload(p):
    '''pload    : pname peek
    '''
    # this needs to be redone - derstroy pname and
    # push it as quals into peek
    #p[0] = DISPATCH["generic"](frags=[p[1], p[2]])

    p[2].add_frags(code_objects.ProgOffset(frags=p[1]))
    p[2].use_offset = True

    p[0] = p[2]
    

def p_peek(p):
    '''peek    : LBRA arth ':' NUM RBRA
               | LBRA STRING_LITERAL RBRA
               | peekw 
               | peek_comp
    '''
    if len(p) == 6:
        p[0] = code_objects.ProgLoad(loc=p[2], size=p[4])
    elif len (p) > 2:
        (loc, size) = LOC_CONSTANTS[p[2]]
        p[0] = code_objects.ProgLoad(loc=loc, size=size)
    else:
        p[0] = p[1]

def p_peekw(p):
    '''peekw :  LBRA arth RBRA
    '''
    p[0] = code_objects.ProgLoad(loc=p[2])

def p_peek_comp(p):
    '''peek_comp  : LBRA pload RBRA
                  |  LBRA pload ':' NUM RBRA
    '''

    if len(p) == 4:
        p[0] = code_objects.IndexLoad(frags=p[2])
    else:
        p[0] = code_objects.IndexLoad(frags=p[2], size=p[4])
        


def p_arth(p):
    '''arth     : NUM
                | narth
    '''
    if isinstance(p[1], int) or isinstance(p[1], str):
        p[0] = code_objects.Immediate(match_object=int(p[1]))
    else:
        p[0] = p[1]

def p_narth(p):
    '''narth :  pload
                | arth ADD arth
                | arth SUB arth
                | arth MUL arth
                | arth DIV arth
                | arth MOD arth
                | arth A_AND arth
                | arth A_OR arth
                | arth XOR arth
                | arth LSH arth
                | arth RSH arth
    '''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = code_objects.ProgArOp(op=p[2], left=p[1], right=p[3])

def p_addr(p):
    '''addr : addr4
            | addr6
    '''
    p[0] = p[1]

def p_addr4(p):
    '''addr4 : ADDR_V4
    '''
    p[0] = code_objects.ProgIPv4(p[1])

def p_addr6(p):
    '''addr6 : ADDR_V6
    '''
    p[0] = code_objects.ProgIPv6(p[1])

def p_net(p):
    '''net  : net4
            | net6
    '''
    p[0] = p[1]

def p_net4(p):
    '''net4 : NET_V4
    '''
    p[0] = code_objects.ProgIPv4(p[1])

def p_net6(p):
    '''net6 : NET_V6
    '''
    p[0] = code_objects.ProgIPv6(p[1])

def p_hostname(p):
    '''hostname : STRING_LITERAL
    '''
    target = gethostbyname(p[1])
    if ":" in target:
        p[0] = code_objects.ProgIPv6(target)
    else:
        p[0] = code_objects.ProgIPv4(target)



lexer = lex.lex(module=lexer_defs)
PARSER = yacc.yacc(debug=1)

