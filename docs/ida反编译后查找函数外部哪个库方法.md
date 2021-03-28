# ida反编译后查找函数外部哪个库方法

研究路由器固件时，这个函数调用外部函数库中的 `usrGetPass` ：

![image-20210216223450479](https://gitee.com/mrskye/Picbed/raw/master/img/20210216223450.png)

切换到固件根目录后：

```shell
grep -rn "usrGetPass"
```

![image-20210216223824489](https://gitee.com/mrskye/Picbed/raw/master/img/20210216223824.png)

匹配出含有 `usrGetPass` 的文件，第一个是分析的文件，第二个就是要找的动态函数库。

在 ida 开头也有记录需要哪些外部函数库：

![image-20210216224733494](https://gitee.com/mrskye/Picbed/raw/master/img/20210216224733.png)