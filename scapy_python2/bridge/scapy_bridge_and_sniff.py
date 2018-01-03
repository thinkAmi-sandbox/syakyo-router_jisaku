# -*- coding: utf-8 -*-
from scapy.sendrecv import bridge_and_sniff


if __name__ == '__main__':
    print '>----- enable bridge -----'
    bridge_and_sniff('eth0', 'eth1')
    print '<----- disable bridge -----'
