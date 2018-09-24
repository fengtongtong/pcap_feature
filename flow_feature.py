from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP
import time


# 划分上行流和下行流
def flow_divide(flow):
    local_adr='10.0.2.15'
    fwd_flow=[]
    bwd_flow=[]
    for pkt in flow:
        if pkt[IP].src==local_adr:
            fwd_flow.append(pkt)
        elif pkt[IP].dst==local_adr:
            bwd_flow.append(pkt)
        else:
            continue
    return fwd_flow,bwd_flow
            


# 均值,标准差,最大值,最小值计算
def calculation(list_info):
    mean_,min_,max_,std_=0,0,0,0
    if len(list_info) < 1:
        return [mean_,min_,max_,std_]
    else:
        min_=round(min(list_info),6)
        max_=round(max(list_info),6)
        mean_ = round(sum(list_info)/len(list_info),6)
        sd = sum([(i - mean_) ** 2 for i in list_info])
        std_ = round((sd / (len(list_info))) ** .5,6)
        return [mean_,min_,max_,std_]
    
    
    
# 包长度特征
def packet_len(flow):   
    pl=[]
    for pkt in flow:
        pl.append(len(pkt))
    pl_total=round(sum(pl), 6)
    pl_mean,pl_min,pl_max,pl_std=calculation(pl)
    return pl_total,pl_mean,pl_min,pl_max,pl_std
    
    
    
# 包到达时间间隔特征 
def packet_iat(flow):    
    piat=[]
    if len(flow)>0:
        pre_time = flow[0].time
        for pkt in flow[1:]:
            next_time = pkt.time
            piat.append(next_time-pre_time)
            pre_time=next_time
        piat_mean,piat_min,piat_max,piat_std=calculation(piat)
    else:
        piat_mean,piat_min,piat_max,piat_std=0,0,0,0
    return piat_mean,piat_min,piat_max,piat_std



# 拥塞窗口大小特征        
def packet_win(flow):   
    pwin = [] 
    for pkt in flow:
        pwin.append(pkt[TCP].window)
    pwin_total = round(sum(pwin), 6)
    pwin_mean,pwin_min,pwin_max,pwin_std=calculation(pwin)
    return pwin_total,pwin_mean,pwin_min,pwin_max,pwin_std



# 包中的标志字段统计
def packet_flags(flow,key): 
    flag=[0,0,0,0,0,0,0,0]
    for pkt in flow:
        flags=int(pkt[TCP].flags)
        for i in range(8):
            flag[i] += flags%2
            flags=flags//2
    if key==0:
        return flag
    else:
        return flag[3],flag[5]



# 包头部长度
def packet_hdr_len(flow): 
    p_hdr_len=0
    for pkt in flow:
        p_hdr_len = p_hdr_len+14+4*pkt[IP].ihl+20
    return p_hdr_len



def flow_feature(filename):
    two_way_flow=rdpcap(filename)
    fwd_flow,bwd_flow=flow_divide(two_way_flow)
 
    # 包到达的时间间隔 13
    fiat_mean,fiat_min,fiat_max,fiat_std = packet_iat(fwd_flow)
    biat_mean,biat_min,biat_max,biat_std = packet_iat(bwd_flow)
    diat_mean,diat_min,diat_max,diat_std = packet_iat(two_way_flow)
    diat_total = duration = round(two_way_flow[-1].time -two_way_flow[0].time+ 0.0001, 6) 
    
    # 拥塞窗口大小特征 15
    fwin_total,fwin_mean,fwin_min,fwin_max,fwin_std = packet_win(fwd_flow)
    bwin_total,bwin_mean,bwin_min,bwin_max,bwin_std = packet_win(bwd_flow)
    dwin_total,dwin_mean,dwin_min,dwin_max,dwin_std = packet_win(two_way_flow)
    
    # 包的数目 7
    fpnum=len(fwd_flow)
    bpnum=len(bwd_flow)
    dpnum=fpnum+bpnum
    bfpnum_rate = round(bpnum / (fpnum + 0.001), 6) 
    fpnum_s = round(fpnum / duration, 6)
    bpnum_s = round(bpnum / duration, 6)
    dpnum_s = round(dpnum / duration, 6)
    
    # 包的总长度 19
    fpl_total,fpl_mean,fpl_min,fpl_max,fpl_std = packet_len(fwd_flow)
    bpl_total,bpl_mean,bpl_min,bpl_max,bpl_std = packet_len(bwd_flow)
    dpl_total,dpl_mean,dpl_min,dpl_max,dpl_std = packet_len(two_way_flow)
    bfpl_rate = round(bpl_total / (fpl_total + 0.001), 6) 
    fpl_s = round(fpl_total / duration, 6)
    bpl_s = round(bpl_total / duration, 6)
    dpl_s = round(dpl_total / duration, 6)
    
    # 包的标志特征 12
    fin_cnt,syn_cnt,rst_cnt,pst_cnt,ack_cnt,urg_cnt,cwe_cnt,ece_cnt=packet_flags(two_way_flow,0)
    fwd_pst_cnt,fwd_urg_cnt=packet_flags(fwd_flow,1)
    bwd_pst_cnt,bwd_urg_cnt=packet_flags(bwd_flow,1)
    
    # 包头部长度 6
    fp_hdr_len=packet_hdr_len(fwd_flow)
    bp_hdr_len=packet_hdr_len(bwd_flow)
    dp_hdr_len=packet_hdr_len(two_way_flow)
    f_ht_len=round(fp_hdr_len /(fpl_total+1), 6)
    b_ht_len=round(bp_hdr_len /(bpl_total+1), 6)
    d_ht_len=round(dp_hdr_len /dpl_total, 6)
    
    # 总共提取72个特征
    feature=[fiat_mean,fiat_min,fiat_max,fiat_std,biat_mean,biat_min,biat_max,biat_std,
             diat_mean,diat_min,diat_max,diat_std,duration,fwin_total,fwin_mean,fwin_min,
             fwin_max,fwin_std,bwin_total,bwin_mean,bwin_min,bwin_max,bwin_std,dwin_total,
             dwin_mean,dwin_min,dwin_max,dwin_std,fpnum,bpnum,dpnum,bfpnum_rate,fpnum_s,
             bpnum_s,dpnum_s,fpl_total,fpl_mean,fpl_min,fpl_max,fpl_std,bpl_total,bpl_mean,
             bpl_min,bpl_max,bpl_std,dpl_total,dpl_mean,dpl_min,dpl_max,dpl_std,bfpl_rate,
             fpl_s,bpl_s,dpl_s,fin_cnt,syn_cnt,rst_cnt,pst_cnt,ack_cnt,urg_cnt,cwe_cnt,ece_cnt,
             fwd_pst_cnt,fwd_urg_cnt,bwd_pst_cnt,bwd_urg_cnt,fp_hdr_len,bp_hdr_len,dp_hdr_len,
            f_ht_len,b_ht_len,d_ht_len]
    return feature




# 对文件夹进行遍历
def each_file(filepath):
    pathDir = os.listdir(filepath)
    for allDir in pathDir:
        child = os.path.join('%s/%s' % (filepath, allDir))
        if os.path.isfile(child):
            feature=flow_feature(child)
            for i in range(71):
                f.write(str(feature[i])+',')
            f.write(str(feature[71])+'\n')
            continue
        elif os.path.isdir(child) and allDir != '.ipynb_checkpoints':
            each_file(child)
        else:
            continue
    print('flow_feature,down!!!')


# 全部特征
def files_feature(filepath):
    pre_time=time.time()
    # 特征column
    feature=['fiat_mean','fiat_min','fiat_max','fiat_std','biat_mean','biat_min','biat_max','biat_std',
             'diat_mean','diat_min','diat_max','diat_std','duration','fwin_total','fwin_mean','fwin_min',
             'fwin_max','fwin_std','bwin_total','bwin_mean','bwin_min','bwin_max','bwin_std','dwin_total',
             'dwin_mean','dwin_min','dwin_max','dwin_std','fpnum','bpnum','dpnum','bfpnum_rate','fpnum_s',
             'bpnum_s','dpnum_s','fpl_total','fpl_mean','fpl_min','fpl_max','fpl_std','bpl_total','bpl_mean',
             'bpl_min','bpl_max','bpl_std','dpl_total','dpl_mean','dpl_min','dpl_max','dpl_std','bfpl_rate',
             'fpl_s','bpl_s','dpl_s','fin_cnt','syn_cnt','rst_cnt','pst_cnt','ack_cnt','urg_cnt','cwe_cnt','ece_cnt',
             'fwd_pst_cnt','fwd_urg_cnt','bwd_pst_cnt','bwd_urg_cnt','fp_hdr_len','bp_hdr_len','dp_hdr_len',''
            'f_ht_len','b_ht_len','d_ht_len']
    for i in range(71):
        f.write(feature[i]+',')
    f.write(feature[71]+'\n')
    each_file(filepath)
    next_time=time.time()
    past_time=next_time-pre_time
    print('Using time is:',past_time)
    

# 主函数，仅有1个参数，就是文件路径
if __name__ == '__main__':
    filepath='test_data/C' 
    path=filepath.split('/')
    f=open(str(path[0])+'/'+str(path[1])+'_feature.csv','w') 
    files_feature(filepath)
    f.close()
