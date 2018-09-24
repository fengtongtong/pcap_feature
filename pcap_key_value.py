#python 3.5.2
#将pcap文件转化为key-value文件,并进行保存
import numpy as np
from scapy.all import *


# 对文件夹进行遍历
def eachFile(filepath):
    pathDir = os.listdir(filepath)
    for allDir in pathDir:
        child = os.path.join('%s/%s' % (filepath, allDir))
        if os.path.isfile(child):
            pcap_key_value(child)
            continue
        eachFile(child)
        

# pcap转化为key_value文件
def pcap_key_value(filename):
    
    #loading the pcap file
    x=rdpcap(filename)
    path = filename.split('.')
    w = open(str(path[0])+'.csv', 'w')
    
    keys=['Ethernet_dst', 'Ethernet_src', 'Ethernet_type', 'IP_chksum', 'IP_dst',
           'IP_flags', 'IP_frag', 'IP_id', 'IP_ihl', 'IP_len', 'IP_options',
           'IP_proto', 'IP_src', 'IP_tos', 'IP_ttl', 'IP_version', 'TCP_ack',
           'TCP_chksum', 'TCP_dataofs', 'TCP_dport', 'TCP_flags',
           'TCP_reserved', 'TCP_seq', 'TCP_sport', 'TCP_urgptr', 'TCP_window']
    for key in keys:
        w.write(str(key)+',')
    w.write('\n')

    for pkt in x:
            #packet layernumber
            i = 0
            while (pkt[i].name != pkt.lastlayer().name):
                i += 1
            i+=1
            #change the dictionary with the keys
            for m in range(i):
                keylist = list(pkt[m].fields.keys())
                for n in keylist:
                    pkt[m].fields[pkt[m].name + '_' + n] = pkt[m].fields.pop(n, None)            
            for k in range(i-1):
                pkt[0].fields.update(pkt[k+1].fields)
            pkt_info=pkt[0].fields
            for key in keys:
                if key not in pkt_info:
                    w.write(str(0)+',')
                else:
                    w.write(str(pkt_info[key])+',')
            w.write('\n')
    w.close()


    
import csv
if __name__ == '__main__':
    pcap_key_value('test_data/A/a+b.pcap')
    x=[i for i in csv.reader(open('test_data/A/a+b.csv','r'))]
    print(x)
    
