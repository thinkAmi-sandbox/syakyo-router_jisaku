# -*- coding: utf-8 -*-
from scapy.all import conf
import select


def bridge():
    try:
        # レイヤ2のソケットを用意
        eth0_socket = conf.L2socket(iface='eth0')
        eth1_socket = conf.L2socket(iface='eth1')

        epoll = select.epoll()
        # 読み出し可能なデータが存在する場合を登録
        # https://docs.python.jp/2/library/select.html#edge-and-level-trigger-polling-epoll-objects
        epoll.register(eth0_socket.fileno(), select.EPOLLIN)
        epoll.register(eth1_socket.fileno(), select.EPOLLIN)

        while True:
            # イベントを1秒待機
            events = epoll.poll(1)
            print '--- events type: {}'.format(type(events))
            # => events type: <type 'list'>

            for fd, event in events:
                # それぞれのオブジェクトの型をコンソールに表示する
                print '--- fd type: {}'.format(type(fd))
                # => fd type: <type 'int'>
                print '--- event type: {}'.format(type(event))
                # => event type: <type 'int'>

                # ファイルディスクリプタがeth0のものと等しい場合
                if fd == eth0_socket.fileno():
                    p_eth0 = eth0_socket.recv()

                    if p_eth0:
                        # eth0で受信したパケットをeth1で送信
                        eth1_socket.send(p_eth0.original)

                # ファイルディスクリプタがeth1のものと等しい場合
                elif fd == eth1_socket.fileno():
                    p_eth1 = eth1_socket.recv()

                    if p_eth1:
                        # eth1で受信したパケットをeth0で送信
                        eth0_socket.send(p_eth1.original)

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    bridge()
