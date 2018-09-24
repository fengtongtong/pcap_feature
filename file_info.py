import os
# 可以获取文件夹中文件的数目,类型分布


# 对文件夹进行遍历
def each_file(filepath):
    pathDir = os.listdir(filepath)
    for allDir in pathDir:
        child = os.path.join('%s/%s' % (filepath, allDir))
        if os.path.isfile(child):
            # 操作函数
            continue
        elif os.path.isdir(child) and allDir != '.ipynb_checkpoints':
            each_file(child)
        else:
            continue
    print('file_info,down!!!')


# 主函数，仅有1个参数，就是文件路径
if __name__ == '__main__':
    filepath='test_data/C' 
    each_file(filepath)
