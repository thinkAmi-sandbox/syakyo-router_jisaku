# -*- coding: utf-8 -*-
from scapy.all import conf
import select


def bridge():
    try:
        # レイヤ2のソケットを用意
        eth0_socket = conf.L2socket(iface='eth0')
        eth1_socket = conf.L2socket(iface='eth1')
        # 別のインタフェースからパケットを送信するための辞書
        next_socket = {
            eth0_socket: eth1_socket,
            eth1_socket: eth0_socket,
        }
        while True:
            # select()関数で使えるようになるまで待機
            readable_sockets, _, _ = select.select([eth0_socket, eth1_socket], [], [])

            for s in readable_sockets:
                # 準備できたソケットから受信
                p = s.recv()

                if p:
                    # パケットの型をターミナルへ表示
                    print '---- packet type from recv(): {}'.format(type(p))
                    # => <class 'scapy.layers.l2.Ether'>
                    print '---- original type from recv(): {}'.format(type(p.original))
                    # => <type 'str'>

                    # パケット全体をターミナルへ表示
                    p.show()

                    # 受信したパケットを別のインタフェースから送信
                    next_socket[s].send(p.original)

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    bridge()
