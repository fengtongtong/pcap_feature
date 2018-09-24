#python 3.5.2
#pcap文件中流信息的划分
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP



#获取packet的五元组,进行唯一标识一个流
def get_tuple(packet):
    ty = packet[Ether].type
    protocol = packet[Ether].proto
    #tcp and udp protocol,ipv4 protocol
    if ty == 0x800 and (protocol == 6 or protocol == 17): 
        srcIP = packet[IP].src
        dstIP = packet[IP].dst
        srcPort = packet[Ether].sport
        dstPort = packet[Ether].dport
        protocol = packet[Ether].proto
        forTuple = [srcIP, dstIP, srcPort, dstPort, protocol]
        backTuple = [dstIP, srcIP, dstPort, srcPort, protocol]
        return forTuple,backTuple
    else:
        return [],[]



#将pcap文件按流进行划分,并进行逐个保存
def flow_divide(filename):
    
    #loading the pcap file
    dpkt=rdpcap(filename)  
    path=filename.split('.')
    
    forTuple,backTuple=get_tuple(dpkt[0])
    flow_Tuple=[forTuple,backTuple]
    flow_id=0
    packets=[dpkt[0]]
    
    for packet in dpkt[1:]:
        forTuple,backTuple=get_tuple(packet)
        if forTuple==[] or backTuple==[]:
            continue
        if forTuple in flow_Tuple:
            packets.append(packet)
            continue
        else:
            wrpcap(str(path[0])+'_'+str(flow_id)+'.pcap',packets)
            flow_Tuple=[forTuple,backTuple]
            flow_id+=1
            packets=[packet]
    
    wrpcap(str(path[0])+'_'+str(flow_id)+'.pcap',packets)
    print('flow_divide,down!!!')
    

# 主函数，仅有1个参数，就是文件路径
if __name__ == '__main__':
    filename='test_data/A/a+b.pcap'
    flow_divide(filename)
