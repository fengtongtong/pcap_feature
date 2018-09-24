#python 3.5.2

from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP


# pcap文件信息读取
def packet_info(pkt):
    info=[]
    info.append(pkt.time)             #0 当前时间戳
    info.append(pkt[Ether].src)       #1 源mac地址
    info.append(pkt[Ether].dst)       #2 目的mac地址
    info.append(pkt[Ether].type)      #3 协议类型,例如IP4,IP6,ICMP
    info.append(pkt[IP].version)      #4 IP版本号
    info.append(pkt[IP].ihl)          #5 IP首部长度
    info.append(pkt[IP].len)          #6 IP总长度
    info.append(pkt[IP].ttl)          #7 IP报文的生存时间
    info.append(pkt[IP].proto)        #8 IP报文的生存时间
    info.append(pkt[IP].chksum)       #9 IP报文的校验和字段
    info.append(pkt[IP].src)          #10 源IP地址
    info.append(pkt[IP].dst)          #11 目的IP地址
    info.append(pkt[TCP].sport)       #12 源端口号
    info.append(pkt[TCP].dport)       #13 目的端口号
    info.append(pkt[TCP].seq)         #14 TCP报文的序号
    info.append(pkt[TCP].ack)         #15 TCP报文的确认序号
    info.append(pkt[TCP].window)      #16 TCP报文的窗口字段,用于标识发送方的窗口大小
    info.append(pkt[TCP].chksum)      #17 TCP报文的校验和
    
    flag=[]
    flags=int(dpkt[3][TCP].flags)
    for i in range(8):
        flag.append(flags%2)
        flags=flags//2
    
    info.append(flag[0])               #18 FIN,终止一个连接
    info.append(flag[1])               #19 SYN,同步一个连接
    info.append(flag[2])               #20 RST,TCP连接出现差错时,释放连接,重新连接
    info.append(flag[3])               #21 PSH,进程之间的快速交互
    info.append(flag[4])               #22 ACK,确认字段
    info.append(flag[5])               #23 URL,紧急字段,有紧急数据,需要紧急传输
    info.append(flag[6])               #24 ECE,网络有阻塞标志
    info.append(flag[7])               #25 CRW,通知对方已将拥塞窗口缩小
    
    return info


# flow的信息读取
def flow_info(flow):
    info=[]
    for pkt in flow:
        info.append(packet_info(pkt))
    return info


# 主函数
if __name__ == '__main__':
    filenames='test_data/A/0.pcap'
    dpkt = sniff(offline=filenames)
    print(flow_info(dpkt))  
