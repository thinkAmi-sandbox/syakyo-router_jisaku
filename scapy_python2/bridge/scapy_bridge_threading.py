# -*- coding: utf-8 -*-
from scapy.all import conf
import threading


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
        # スレッドを用意
        bridge_eth0 = threading.Thread(target=bridge_from_eth0_to_eth1)
        bridge_eth1 = threading.Thread(target=bridge_from_eth1_to_eth0)

        # 今回はいきなり止まっても問題ないため、デーモンモードで動くようにする
        # https://docs.python.jp/3/library/threading.html#thread-objects
        bridge_eth0.daemon = True
        bridge_eth1.daemon = True

        # スレッドを開始
        bridge_eth0.start()
        bridge_eth1.start()

        # KeyboardInterruptを受け付けるよう、join()を秒指定で使う
        bridge_eth0.join(5)
        bridge_eth1.join(5)

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    bridge()
