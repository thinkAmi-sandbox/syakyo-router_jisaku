# -*- coding: utf-8 -*-
# NAPTルータ
# 構成は以下の前提
# (ローカル) Win - eth1 - eth0 - WiFi - Mac (グローバル)
# また、パケットは、ローカル -> グローバル -> ローカル の順で流れる前提
# NATと変わったところのみコメントを付けてある
# また、かなり遅いため、curlがタイムアウトしやすいので注意
from scapy.all import conf, send, get_if_hwaddr, get_if_addr
from select import select
from scapy.layers.inet import IP, TCP, UDP
import os
import random


def recreate_ip_packet(ip_packet):
    if ip_packet.haslayer(TCP):
        del ip_packet.getlayer(TCP).chksum
    if ip_packet.haslayer(UDP):
        del ip_packet.getlayer(UDP).chksum
    del ip_packet.chksum

    result = IP(str(ip_packet))
    return result


def is_ssh_packet(target_packet):
    if not target_packet.haslayer(TCP):
        return False
    tcp_layer = target_packet.getlayer(TCP)
    return tcp_layer.dport == 22


def napt_router():
    try:
        global_socket = conf.L2socket(iface='eth0')
        local_socket = conf.L2socket(iface='eth1')

        global_eth_mac_address = get_if_hwaddr('eth0')
        global_eth_ip_address = get_if_addr('eth0')
        local_eth_mac_address = get_if_hwaddr('eth1')

        os.system('sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

        # NAPTテーブル
        napt_table = {}

        while True:
            readable_sockets, _, _ = select([global_socket, local_socket], [], [])

            for s in readable_sockets:
                p = s.recv()

                if not p or not p.haslayer(IP):
                    continue
                if is_ssh_packet(p):
                    continue

                if p.dst == local_eth_mac_address:
                    packet_from_local_to_global = p.getlayer(IP)

                    # すでにNAPTで使用したローカルIP&ポートの場合は、以前のグローバルIP&ポートを使う
                    # IPとポートが変わってしまうと、TCPコネクションがうまくいかず、通信が途切れる
                    if (packet_from_local_to_global.src, packet_from_local_to_global.sport) \
                            in napt_table.values():
                        for global_eth_ip_address, global_port in napt_table.keys():
                            if napt_table[(global_eth_ip_address, global_port)] == \
                                    (packet_from_local_to_global.src, 
                                     packet_from_local_to_global.sport):
                                break
                    else:
                        # まだNAPTで使用していないローカルIP&ポートの場合
                        # NAPTで使う変換後のポートをランダムに取得する
                        # ポートの範囲は、プライベートポート番号とする
                        global_port = random.randint(49152, 65535)
                        # レスポンスパケットのIPアドレス・ポートを変換するため、
                        # 変換後のIPアドレス・ポートをキーとして、変換前のIPアドレス・ポートを保管しておく
                        napt_table[(global_eth_ip_address, global_port)] = \
                            (packet_from_local_to_global.src, packet_from_local_to_global.sport)
                        
                    # 送信元IPアドレスとポートを、ルーターのグローバル側IPアドレスとランダムなポートに差し替える
                    packet_from_local_to_global.src = global_eth_ip_address
                    packet_from_local_to_global.sport = global_port

                    packet_to_global = recreate_ip_packet(packet_from_local_to_global)
                    print packet_to_global.summary()
                    send(packet_to_global, verbose=0)

                elif p.dst == global_eth_mac_address:
                    packet_from_global_to_local = p.getlayer(IP)
                    # 変換後のIPアドレス・ポートから変換前IPアドレスを取得する
                    local_pc_ip_address, local_pc_port = napt_table.get(
                        (packet_from_global_to_local.dst, packet_from_global_to_local.dport))
                    # 念のため、変換できない場合はパケットを送信しない
                    if local_pc_ip_address is None or local_pc_port is None:
                        continue
                    # 宛先IPアドレス・ポートを変換前IPアドレス・ポートに差し替える
                    packet_from_global_to_local.dst = local_pc_ip_address
                    packet_from_global_to_local.dport = local_pc_port

                    packet_to_local = recreate_ip_packet(packet_from_global_to_local)
                    print packet_to_local.summary()
                    send(packet_to_local, verbose=0)

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    napt_router()
