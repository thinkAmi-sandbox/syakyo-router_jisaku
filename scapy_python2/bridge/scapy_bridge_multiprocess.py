# -*- coding: utf-8 -*-
from scapy.all import conf
import multiprocessing


def bridge_from_eth0_to_eth1():
    eth0_socket = conf.L2socket(iface='eth0')
    eth1_socket = conf.L2socket(iface='eth1')

    while True:
        p = eth0_socket.recv()
        if p:
            eth1_socket.send(p.original)


def bridge_from_eth1_to_eth0():
    eth0_socket = conf.L2socket(iface='eth0')
    eth1_socket = conf.L2socket(iface='eth1')

    while True:
        p = eth1_socket.recv()
        if p:
            eth0_socket.send(p.original)


def bridge():
    try:
        # プロセスを用意
        bridge_eth0 = multiprocessing.Process(target=bridge_from_eth0_to_eth1)
        bridge_eth1 = multiprocessing.Process(target=bridge_from_eth1_to_eth0)

        # プロセスを開始
        bridge_eth0.start()
        bridge_eth1.start()

    except KeyboardInterrupt:
        # threadingと異なり、特に何もしなくてもCtrl + C が可能
        pass


if __name__ == '__main__':
    bridge()
