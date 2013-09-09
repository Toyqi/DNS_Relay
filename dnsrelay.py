# -*- coding: utf-8 -*-

from socket import *
import time
import sys
import os

LOCALFILE = 'dnsrelay.txt'
PORT = 53
HOST = ''
OUTER_DNS_PORT = 53
OUTER_DNS_SERVER = '10.3.9.4'
BUFSIZE = 1024

#加载本地域名解析文件
def loadLocalInfo(filename):
    ipTable = {}
    try:
        infile = open(filename)
    except:
        print("Local file does not exist!")
        os._exit(0)
    for line in infile.readlines():
        lineArr = line.strip().split(' ')
        ipTable[lineArr[1]] = lineArr[0]
    return ipTable
    
#从DNS请求包中获取请求的url字符串
def getRequestUrl(infoList):
    url = ''
    tempList = infoList
    index = 0
    wordLen = tempList[index]
    while wordLen != 0:
        for i in range(wordLen):
            index += 1
            #chr()函数用一个范围在range（256）内的（就是0～255）整数作参数，返回一个对应的字符
            url = url+chr(tempList[index])
        index += 1
        wordLen = tempList[index]
        if wordLen != 0:
            url = url+'.'
    return url

#根据查询到的IP连同原有请求包组装成回应包
def makeAnswerFrame(ip, msg):
    answerList = []
    #标识和标志以及查询问题部分保持与原msg中相同
    for ch in msg:
        answerList.append(ch)
    #问题数1，资源数记录1，授权资源记录数0，额外资源记录数0
    answerList[4:12] = ['\x00','\x01','\x00','\x01','\x00','\x00','\x00','\x00']
    
    #\xc0\x0c:一般响应报文中资源部分的域名都是指针C00C，刚好指向请求部分的域名
    #\x00\x01:资源部分类型一般为1
    #\x00\x01:资源部分类一般为1
    #\x00\x02\xa3\x00:资源记录生存时间为：通常为2天(172800秒)
    #\x00\x04:资源数据长度为4，限其后所附IP地址为4字节
    answerList = answerList+['\xc0','\x0c','\x00','\x01','\x00','\x01','\x00','\x00','\x02','\x58','\x00','\x04']

    #inet_aton()是一个改进的方法来将一个字符串IP地址转换为一个32位的网络序列IP地址
    netIp = inet_aton(ip)
    #构造答案ip部分与answerList组合
    ipList = []
    for ch in netIp:
        ipList.append(ch)
    answerList = answerList + ipList
    answerMsg = ''.join(anserList)
    return answerMsg


if __name__ == '__main__':
    #分析程序参数
    paraLen = len(sys.argv)
    paraDict = {}
    if paraLen != 1:
        if paraLen!=3 and paraLen!=5:
            print("Invalid argument")
            print("dns [-f filename] [-d DNSHost]")
            os._exit(0)
        else:
            for i in range(int(paraLen/2)):
                paraDict[sys.argv[2*i+1]] = sys.argv[2*i+2]
            if '-f' in paraDict:
                LOCALFILE = paraDict['-f']
            if '-d' in paraDict:
                OUTER_DNS_SERVER = paraDict['-d']
    
    #本地DNS服务器套接字
    udpSerSock = socket(AF_INET, SOCK_DGRAM)
    udpSerSock.bind((HOST, PORT))
    ipDict = loadLocalInfo(LOCALFILE)
    
    clientWait = [] #(fromIp)
    clientKeyDict = {}#(请求标识+fromIp , 系统当时时间)
    clientAddrDict = {}#(系统当时时间 , (fromIp,fromPort))
    
    while True:
        try:
            data, (fromClient, fromPort) = udpSerSock.recvfrom(BUFSIZE)
            print("(fromClient,fromPort):", fromClient, " & ", fromPort)
        except:
            print("Sorry,a crash problem!") 
            continue
            
        requestList = list(data)
        url= getRequestUrl(requestList[12:])
        
        if fromPort == OUTER_DNS_PORT:
            #表示这是来自外部中继服务器的回应信息
            showIp = inet_ntoa(data[-4:])
            print("Remote DNS Server:", url, " -> ", showIp)
            index = 0
            for client in clientWait:
                id_client = str(requestList[0])+str(requestList[1])+str(client)
                if id_client not in clientKeyDict:
                    continue
                time_key = clientKeyDict[id_client]
                if time_key in clientAddrDict :
                    udpSerSock.sendto(data,clientAddrDict[time_key])
                    del clientWait[index]
                    del clientKeyDict[id_client]
                    del clientAddrDict[time_key]
                    break
                index += 1   
                
        else:
            if url in ipDict:
                if ipDict[url] == '0.0.0.0':
                    print("*****域名不存在!*****")
                else:
                    #向客户发送在本地文件中已经查取到的ip
                    print("Local DNS server:", url, " -> " , ipDict[url])
                    answerMsg = makeAnswerFrame(ipDict[url], data)
                    updSerSock.sendto(answerMsg, (fromClient, fromPort))
            else:
                #向外部DNS服务器发出查询
                print("Send request to remote DNS server:", url)
                udpSerSock.sendto(data, (OUTER_DNS_SERVER, OUTER_DNS_PORT))
                #将请求标识存入等待队列中
                time_key = time.strftime('%Y-%m-%d',time.localtime(time.time())) 
                clientKeyDict[str(requestList[0])+str(requestList[1])+str(fromClient)] = time_key
                clientAddrDict[time_key] = (fromClient,fromPort)
                if fromClient not in clientWait:
                    clientWait.append(fromClient)
    
