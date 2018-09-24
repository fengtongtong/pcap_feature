#python 3.5.2
#pcap文件中流信息
# 可以根据生成的文件,获取流的数目,获得tuple分布(dict保存,排序),获取packet的分布
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


    
# 获取流的信息
def flow_info(filename):
    
    #loading the pcap file
    dpkt=rdpcap(filename)
    
    path=filename.split('.')
    w = open(str(path[0])+'_flow_info.csv', 'w')
    w.write('flow_id,flow_tuple,packet_num\n')
    
    forTuple,backTuple=get_tuple(dpkt[0])
    flow_Tuple=[forTuple,backTuple]
    flow_id=0
    w.write(str(flow_id)+','+str(forTuple)+',')
    packet_num=1
    
    for packet in dpkt[1:]:
        forTuple,backTuple=get_tuple(packet)
        if forTuple==[] or backTuple==[]:
            continue
        if forTuple in flow_Tuple:
            packet_num+=1
            continue
        else:
            w.write(str(packet_num)+'\n')
            flow_Tuple=[forTuple,backTuple]
            flow_id+=1
            w.write(str(flow_id)+','+str(forTuple)+',')
            packet_num=1
    
    w.write(str(packet_num)+'\n')
    w.close()     
    print('flow_info,down!!!')
    

    
# 主函数，仅有1个参数，就是文件名
if __name__ == '__main__':
    filename='test_data/A/a+b.pcap'
    flow_info(filename)
