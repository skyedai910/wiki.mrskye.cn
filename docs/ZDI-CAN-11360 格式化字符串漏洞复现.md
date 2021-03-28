# ZDI-CAN-11360 格式化字符串漏洞复现

## 复现环境

* 漏洞固件 http://www.dlinktw.com.tw/techsupport/download.ashx?file=11617

  版本号为 v1.09

* qemu v5.2

* Ubuntu 18.04

* ida 7.5

## 漏洞分析

将用户可控的 cookie 的 uid 字段作为格式化字符串使用。

二进制文件在 `./web/cgi-bin/hnap/hnap_service` ，定位到 Login 函数的 136 行附近：

```c
  v6 = getenv("COOKIE");                        // 提取cookie，这个提取是判断是否存在cookie
  if ( v6 && *v6 )
  {
    memset(v44, 0, sizeof(v44));
    v8 = getenv("COOKIE");
    snprintf(v44, 128u, "%s", v8);              // 将cookie以字符串形式存入v44
    v9 = strstr(v44, "uid=");                   // 匹配出cookie的uid字段
    if ( v9 )                                   // 包含uid
    {
      v10 = v9 + 4;                             // 跳过uid=
      v11 = strchr(v9 + 4, ';');                // 提取纯净uid
      if ( v11 )
        *v11 = '\0';                            // 补上一个结束符
      snprintf((char *)v40, 11u, v10);          // 格式化字符串漏洞
                                                // v10为用户控制内容，被作为格式化字符串写入
                                                // snprintf(ptr,size,format,string,...)
      v12 = (const char *)&v57[9];
    }
    else                                        // 不包含uid
    {
      snprintf((char *)v40, 11u, v44);
      v12 = (const char *)&v57[9];
    }
```

Getenv 获取 cookie 放入 v8 ，用 snprintf 写入到 v44 ，这里使用没有问题，用户可控的 v8 是作为格式化字符串的参数。后面进一步提取 uid 的值存放在 v10 ，用 snprintf 将 v10 写入 v40 ，对比上面 snprintf 明显看出来：用户可控的 v10 被当做是格式化字符串，相当于 ctf 的 ``printf(v10);`` 。

qemu 仿真测试没搞懂流量包怎么传进去，应该在 78 行。84 行处理传入的数据包，92 行调用 Login 。

![image-20210216154253469](https://gitee.com/mrskye/Picbed/raw/master/img/20210216154300.png)

到公网上找个设备复现。访问 `/hnap/hnap_service` 会返回设备信息，FirmwareVersion 就是固件版本信息：

![image-20210216155118459](https://gitee.com/mrskye/Picbed/raw/master/img/20210216155118.png)

根据先前分析处理数据报函数可以大致数据报 content 要有什么东西。

由于漏洞位于处理 HNAP 请求的逻辑中，我们可以把其他 Dlink 设备的 HNAP 请求照搬过来（from CataLpa）。没有 DLink 设备，复制一下师傅的例子：

```
POST /hnap/hnap_service HTTP/1.1
Host: 61.93.85.63
SOAPAction: "http://purenetworks.com/HNAP1/Login"
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Cookie: uid=aaaa;
Content-Length: 374

<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Login xmlns="http://purenetworks.com/HNAP1/"><Action>login</Action><Username></Username><LoginPassword></LoginPassword></Login></soap:Body></soap:Envelope>
```

有回显，结果如下：

![image-20210216155718558](https://gitee.com/mrskye/Picbed/raw/master/img/20210216155718.png)

将 uid 改成格式化字符串访问不存在地址，让系统报错没有回显，系统应该是会重启，服务就暂停一会：

![image-20210216160046057](https://gitee.com/mrskye/Picbed/raw/master/img/20210216160046.png)

