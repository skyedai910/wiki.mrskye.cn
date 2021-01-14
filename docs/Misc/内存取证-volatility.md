# 内存取证-volatility

## 安装

实测kali 7.x自带，而最新的kali 9.x没有

## 使用

判断镜像信息，获取操作系统类型

```
volatility -f ?.img/raw/... imageinfo
```



知道操作系统类型后，用`--profile`指定系统的操作类型

```
volatility -f ?.img --profile=...
```



查看当前显示的notepad文本（提取某个程序）

```
volatility  -f file.raw --profile=WinXPSP2x86 notepad
```



查看当前运行的进程

```
volatility  -f file.raw --profile=WinXPSP2x86 psscan/pslist
```



扫描所有的文件列表(常常结合grep，即正则)

```
volatility  -f file.raw --profile=WinXPSP2x86 filescan
```



根据offset提取出文件

```
volatility  -f file.raw --profile=WinXPSP2x86 dumpfiles -D . -Q 0x.....
```



扫描 Windows 的服务

```
volatility -f file.raw --profile=WinXPSP2x86 svcscan
```



查看网络连接

```
volatility -f file.raw --profile=WinXPSP2x86 connscan
```



查看命令行上的操作

```
volatility -f file.raw --profile=WinXPSP2x86 cmdscan
```



根据pid dump出相应的进程

```
volatility -f easy_dump.img --profile=Win7SP1x64 memdump -p 2580 -D 目录
```





## 参考

[内存取证之旅](https://coomrade.github.io/2018/10/27/%E5%86%85%E5%AD%98%E5%8F%96%E8%AF%81%E4%B9%8B%E6%97%85/)

[内存取证工具volatility用法与实战](<http://shaobaobaoer.cn/archives/693/memory-forensics-tool-volatility-usage-and-practice>)（ps:这个含手动安装）