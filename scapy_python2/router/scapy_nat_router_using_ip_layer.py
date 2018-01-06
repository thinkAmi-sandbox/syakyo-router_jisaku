# -*- coding: utf-8 -*-
# NAPTルータ
# 構成は以下の前提
# (ローカル) Win - eth1 - eth0 - WiFi - Mac (グローバル)
# また、パケットは、ローカル -> グローバル -> ローカル の順で流れる前提
from scapy.all import conf, send, get_if_hwaddr, get_if_addr
from select import select
from scapy.layers.inet import IP, TCP, UDP
import os


def recreate_ip_packet(ip_packet):
    # 各レイヤのチェックサムは、削除することでScapyが再計算してくれる
    # https://stackoverflow.com/questions/5953371/how-to-calculate-a-packet-checksum-without-sending-it
    if ip_packet.haslayer(TCP):
        del ip_packet.getlayer(TCP).chksum
    if ip_packet.haslayer(UDP):
        del ip_packet.getlayer(UDP).chksum
    del ip_packet.chksum

    # 再計算するために、IPレイヤより上層のパケットインスタンスを生成する
    result = IP(str(ip_packet))
    return result


def is_ssh_packet(target_packet):
    if not target_packet.haslayer(TCP):
        return False
    tcp_layer = target_packet.getlayer(TCP)
    return tcp_layer.dport == 22


def nat_router():
    try:
        global_socket = conf.L2socket(iface='eth0')
        local_socket = conf.L2socket(iface='eth1')

        # ルータのインタフェースのMACアドレス・IPアドレスを取得しておく
        global_eth_mac_address = get_if_hwaddr('eth0')
        global_eth_ip_address = get_if_addr('eth0')
        local_eth_mac_address = get_if_hwaddr('eth1')

        # RSTパケットをラズパイから送信すると、TCPが途中で切れてしまうので、送信しないようにする
        os.system('sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP')

        # NATテーブル
        nat_table = {}

        while True:
            readable_sockets, _, _ = select([global_socket, local_socket], [], [])

            for s in readable_sockets:
                p = s.recv()

                if not p or not p.haslayer(IP):
                    continue

                # 今回の場合、MacとラズパイをSSHでつないでいることからSSHパケットは除外する
                # 除外しないとパケット量が増えてしまい、curlがタイムアウトしてしまう
                if is_ssh_packet(p):
                    continue

                # ローカルからグローバルへ抜けるパケットが入ってきた場合
                if p.dst == local_eth_mac_address:
                    # IPレイヤのパケットを取得する
                    packet_from_local_to_global = p.getlayer(IP)
                    # レスポンスパケットのIPアドレスを変換するため、
                    # 変換後のIPアドレスをキーとして、変換前のIPアドレスを保管しておく
                    nat_table[global_eth_ip_address] = packet_from_local_to_global.src
                    # 送信元IPアドレスを、ルーターのグローバル側IPアドレスに差し替える
                    packet_from_local_to_global.src = global_eth_ip_address
                    # 送信用パケットを再生成する
                    packet_to_global = recreate_ip_packet(packet_from_local_to_global)
                    # 送信用パケットの概要をコンソールに表示する
                    print p.summary()

                    # send()はLayer3のパケットをいい感じに送信してくれる
                    # verbose=2(デフォルト値)など、1~3の場合、以下が表示される
                    # .
                    # Sent 1 packets.
                    # verbose=0の場合、何も出力されない
                    send(packet_to_global, verbose=0)

                # グローバルからローカルへ抜けるパケットが入ってきた場合
                elif p.dst == global_eth_mac_address:
                    packet_from_global_to_local = p.getlayer(IP)
                    # 変換後のIPアドレスから変換前IPアドレスを取得する
                    local_pc_ip_address = nat_table.get(packet_from_global_to_local.dst)
                    # 念のため、変換できない場合はパケットを送信しない
                    if local_pc_ip_address is None:
                        continue
                    # 宛先IPアドレスを変換前IPアドレスに差し替える
                    packet_from_global_to_local.dst = local_pc_ip_address

                    packet_to_local = recreate_ip_packet(packet_from_global_to_local)
                    print p.summary()
                    send(packet_to_local, verbose=0)

    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    nat_router()
