#python 3.5.2
#pcap文件的合并
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP


# 遍历整个文件夹
def each_file(filepath):
    pathDir = os.listdir(filepath)
    for allDir in pathDir:
        child = os.path.join('%s/%s' % (filepath, allDir))
        if os.path.isfile(child):
            each_pkt(child)
        elif os.path.isdir(child) and allDir != '.ipynb_checkpoints':
            each_file(child)
        else:
            continue
    print('pcap_merge,down!!!')


#将packet包进行合并
def each_pkt(filename):
    global packets
    #loading the pcap file
    dpkt=rdpcap(filename)   
    for packet in dpkt:
        packets.append(packet)

        
# flow合并
def flow_merge(filepath):
    each_file(filepath)
    wrpcap(str(filenames)+'/pcap_merge.pcap',packets)


# 主函数，仅有1个参数，就是文件路径
if __name__ == '__main__':
    packets=[]
    filepath='test_data/C'
    flow_merge(filepath)
