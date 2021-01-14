# yafu安装及使用

yafu用于自动整数因式分解，**在RSA中，当p、q的取值差异过大或过于相近的时候，使用yafu可以快速的把n值分解出p、q值**，原理是使用Fermat方法与Pollard rho方法等。

如果 p 与 q 相差较大（小），使用 yafu 可以很快分解出来。如果 n 较大，且经过几轮分解都没有得出结果，对于 ctf 题目来说，应该有其他解法。

## 安装

yafu 基本覆盖全平台。反正功能一样，选择最简便安装方法--Windows 下安装。

打开[下载地址](https://sourceforge.net/projects/yafu/)，下载后解压即可使用。解压后有两个版本，根据自己系统位数选择（下文使用 x64 版本）。

## 使用

1. 使用 cmd 进入到 yafu 所在目录下，或将目录加入到系统环境 PATH 变量，或打开目录文件夹后 shift+右键 选择在此处打开 powershell 。

2. 假如要分解因数 6 ，输入命令：``.\yafu-x64.exe "factor(6)"``。

3. 如果因数过长，将 因数 用文本文件存放在 yafu 目录下，例如：data.txt 。**文件最后一行一定要换行，否则eof; done processing batchfile**。

   运行命令：``.\yafu-x64.exe "factor(@)" -batchfile data.txt``

   