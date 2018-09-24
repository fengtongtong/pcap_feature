#python 3.5.2
#将pcap文件转化为8进制文件,并进行保存
from scapy.all import *
import numpy as np


# 对文件夹进行遍历
def eachFile(filepath):
    pathDir = os.listdir(filepath)
    for allDir in pathDir:
        child = os.path.join('%s/%s' % (filepath, allDir))
        if os.path.isfile(child):
            pcap_int(child)
            continue
        eachFile(child)
        
        
def pcap_int(filename):
    #loading the pcap file
    x=rdpcap(filename)
    path = filename.split('.')
    w = open(str(path[0])+'.txt', 'w')
    raw=np.empty((len(x),),dtype=object )
    for i in range (0,len(x)):
        tmp=bytes(x[i])
        raw[i]=np.fromstring(tmp,dtype=np.uint8)
        w.write(str(raw[i])+'\n')
    w.close()
    

if __name__ == '__main__':
    eachFile('test_data')
