DNS_Relay
=========

DNS服务器程序。

读入“域名-IP地址”对照表（dnsrelay.txt）,当客户端查询域名对应的IP地址，用域名检索该对照表，三种检索结果：

 - 检索结果ip为0.0.0.0，向客户端返回“域名不存在的报错消息”（不良网站拦截功能）
 - 检索结果为普通IP地址，向客户端返回这个地址（服务器功能）
 - 表中微检索到该域名，向因特网DNS服务器发出查询，讲解过返回给客户端（中继功能）
 * 考虑多个计算机上的客户端会同时查询，需要进行消息ID转换
