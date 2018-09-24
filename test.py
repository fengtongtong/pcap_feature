#python 3.5.2
#文件结果测试

from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
import csv

import time

pre_time=time.time()
print('pre_time:',time.asctime( time.localtime(time.time()) ))


x=[i for i in open('dataset2/benign_feature.csv','r')]
print(len(x))
y=[i for i in open('dataset2/malicious_feature.csv','r')]
print(len(y))
pathDir = os.listdir('dataset2/benign')
print(len(pathDir))
pathDir2 = os.listdir('dataset2/malicious')
print(len(pathDir2))


next_time=time.time()
print('next_time:',time.asctime( time.localtime(time.time())))
pass_time=next_time-pre_time
print('past_time:',pass_time)
