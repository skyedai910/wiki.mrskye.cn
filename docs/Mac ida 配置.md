# Mac ida 配置

版本是飘云阁泄露的 7.5 绿色全插件版。运行在正版 crossover 上，里面容器是 win10 64bit ，安装了 python 3.9。

安装 rizzo 这种作者自己写的库直接复制到 plugin 就能用了，但是遇到 findcryto 这种复制文件到 plugin 之后还需要 pip 安装额外库的现在遇到一点问题。

就是 pip 直接安装会遇到 ``Microsoft visual c++ 14.0 is required`` 问题，所以采取去 pypi 下载 whl 文件直接安装，但是部分库没有提供 py39 win64 amd 对应的文件，所以安装不上只能等待更新

crossover 打开终端窗口需要每次自己手动打开，路径为："/Users/skye/Library/Application Support/CrossOver/Bottles/IDA Pro 7.5/drive_c/windows/system32/cmd.exe"

## 参考文章

https://blog.csdn.net/ting0922/article/details/82355663

https://blog.csdn.net/u014081841/article/details/80842705

https://blog.csdn.net/ting0922/article/details/82355663