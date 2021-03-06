## NFC卡分类

常用的NFC卡可以分为ID卡和IC卡。ID卡全称身份识别卡(Identification Card)，为低频卡，工作频率为 125KHz-1000Khz（与大部分手机、[智能设备](https://www.smzdm.com/fenlei/chuandaishebei/)工作频率不同，无法模拟），编号固定，卡号公开，不可写入数据，逐步淘汰中。IC卡全称集成电路卡(Integrated Circuit Card)，又称智能卡(Smart Card)，工作频率为 13.56MHz（与大部分手机 NFC 频率一样，可模拟）。

## IC卡类型 

常用IC卡主要有以下类型（以下介绍来自网络）：

**Mifare S50（M1）:**MIFARE Classic是恩智浦半导体开发的可用于非接触式智能卡，符合ISO/IEC 14443 A类标准。用于公共交通票证等应用，还可用于各类其他应用有S20，S50(M1)，S70几种规格，主要是根据存储器容量划分，存储器容量分别有320B，1K，4K。具有以下防干扰、轻松简便以及安全等特性。日常使用的电梯卡、门禁卡等智能卡发卡商所使用的都是 M1 卡，可以理解为物业发的原卡（母卡）。常见校园卡、公交卡等也是 M1 卡。M1 卡仅仅适合发卡方发新卡使用。

**CPU卡：**CPU卡芯片内含有一个微处理器，配合操作系统即片上 OS，可以达到金融级别的安全等级。适用于金融、保险、交警、政府行业等多个领域。CPU 卡由 CPU 部分 7K 以及 M1 部分 1K 组成，最多破解其中 M1 部分，CPU 区域数据无法破解。实际上由于 CPU 部分和 M1 部分的数据会交互，所以基本上 CPU 卡无法破解。

### IC复制卡种类

**UID卡：**普通 IC 复制卡，可以重复擦写所有扇区。UID 可被重复修改，响应后门指令（意味着可被使用后门指令检测是否为克隆卡的机器发现），遇到带有防火墙的读卡器就会失效。

**CUID卡：**UID的升级版，可擦写防屏蔽卡，可以重复擦写所有扇区，不响应后门指令(意味着不容易被反克隆系统发现)，可以绕过防火墙。

目前IC卡主要有UID,CUID,FUID,UFUID,这几种，其中CUID是天朝人民发明的卡，被国外成为Chinese magic card，因为他能更改0扇区卡号。

CUID,FUID,UFUID 卡都带有防火墙，CUID可以重复擦写所有扇区，FUID,UFUID为一次性的卡，0扇区只能写一次就被锁死了，不能更换。

一般我们读出了母卡数据，如果是静态数据，先用UID写卡，看复制卡是否能使用，如果不能再用CUID试，CUID目前是市面上使用最多的卡种，如果依旧不行，继续用FUID和UFUID试试看。

## M1 卡结构

Mifare Classic提供1k-4k的容量，现在国内采用的多数是Mifare Classic 1k(S50)[后面简称M1卡]。

M1卡有从0到15共16个扇区，每个扇区配备了从0到3共4个段，每个段可以保存16字节的内容。

每个扇区的第4个段（也就是3段）是用来保存KeyA，KeyB和控制位的，因为M1卡允许每个扇区有一对独立的密码保护，这样能够更加灵活的控制数据的操作，控制位就是这个扇区各种详细权限计算出来的结果。

每张M1卡都有一个全球唯一的UID号，这个UID号保存在卡的第一个扇区（0扇区）的第一段（0段），也称为厂商段，其中前4个字节是卡的UID，第5个字节是卡UID的校验位，剩下的是厂商数据，并且这个段在出厂之前就会被设置了写入保护，只能读取不能修改，当然也有例外就是各种复制卡。

![img](https://gitee.com/mrskye/Picbed/raw/master/img/20210202153449.png)

## M1 卡破解方法

1. 暴力破解

   M1卡是被动卡，需要读卡器为它提供能量，一旦读卡器切断了电源，卡中的临时数据就会丢失，永远不会因为密码输入错误太多而被锁定。

2. 重放攻击

   重放攻击是基于M1卡的PRNG算法漏洞实现。当卡接近读卡器获得能量的时候，就会开始生成随机数序列，因为卡是被动式卡，也就是随机数是依靠（基于LSRF的PRNG）算法生成的。

3. 克隆卡片

   需要用到 uid、cuid 等克隆卡片

4. 密钥流窃听

   利用 proxmark 3 嗅探到全加密 M1卡。在卡和已经授权的读卡器交换数据的时候进行窃听，就能读取 tag 数据，利用 XOR 算 key 工具就可以把扇区的密钥计算出来，这也是PRNG算法的漏洞所导致的

5. 验证漏洞

   验证漏洞是目前使用最多的M1破解手段，在读卡器尝试去读取一个扇区时，卡会首先发一个随机数给读卡器，读卡器接到随机数之后利用自身的算法加密这个随机数再反馈回给卡，卡再用自己的算法计算一次，发现结果一致的话就认为读卡器是授权了的，然后就用开始自己的算法加密会话并跟读卡器进行传送数据。这时候问题就来了，当我们再次尝试去访问另一个扇区，卡片又会重复刚才那几个步骤，但此时卡跟读卡器之间的数据交换已经是被算法加密了的，而这个算法又是由扇区的密钥决定的，所以密钥就被泄露出来了。因此验证漏洞要求我们至少知道一个扇区的密钥，但目前大部分的扇区都没有全部加密，所以很容易就会被破解。

## 基于 pn532 + m1T 破解实战

### 工具列表

* PN532 （含 ch340 或其他 ttl 转 usb 拓展）
* [MifareOneTool](https://github.com/xcicode/MifareOneTool/releases/tag/v1.7.0)
* CUID卡（复制到手机&手环才需要）

> https://mrskye.lanzous.com/iMRVol83exe
> 密码:mrskye

### 安装驱动&链接 pn532

买 pn532 的时候搭配买上 ttl 转 usb 模块，usb 模块与 pn532 链接参考店家给的文档，只有 VCC 和 GND 不接翻都不会烧芯片。

怼上电脑后，如果打好驱动接线正确就能在设备管理器查看到（com 因电脑而异不一定相同）：

![image-20210202161020718](https://gitee.com/mrskye/Picbed/raw/master/img/20210202161020.png)

打开 m1T 检测链接，查看是否链接上 pn532 ，留意 com 是否和设备管理器的一致。

![image-20210202161353051](https://gitee.com/mrskye/Picbed/raw/master/img/20210202161353.png)

### 破译密码

将卡片放上去，点击扫描卡片，确定识别到卡片。

识别到卡片后点击检测加密，如果半加密卡就很有戏，去加密的可以先试下，如果跑不出来就考虑试下 pm3 。

#### 半加密卡

如果不知道任何一个加密扇区密码就直接点一键解原卡

#### 全加密卡

选择上方高级操作模式，点击里面的全加密爆破

无论哪种卡成功解密完成后，软件都会弹窗提示保存 dump 数据，也就是卡片全部数据（含密码），保存后面需要用到。

### 复制到卡片

各地小区、电梯安全策略有高有低，如果使用成本低的 uid 卡不成功，改用 cuid 。两者区别是卡片的 uid 是否可改变，也就是 0 扇区的前 8 字节数据。

#### 写入 uid

点击写入普通卡，选择破译出来的 dump 文件。由于 uid 不能改，写入完成不能达到 64/64 。用破译出来密码读取一下卡片内容，确认是否成功写入数据。

#### 写入 cuid

点击写入C\FUID卡，步骤同上，写入完成度可以达到 100% ，一样的读取写入卡片内容，确定是否成功写入，尤其是 0 扇区前 8 字节。

#### 写入手机或者手环

复制一份 dump 文件，打开 m1T 打开高级操作模式，点击里面的 Hex编辑器，加载复制的 dump 文件。

打开 0 扇区复制第 0 块的前 8 位数字，即 uid 。新建一份文件，点击工具修改 UID ，粘贴 8 位数字，保存这个份文件。依照上面操作写入到 cuid 里面。

将该 cuid 复制到手机里面，打开手机刷卡，放到 pn532 上面，重复写入 cuid 的布置，这次写入的是完整的 dumo 文件。











[PN532工具合集](http://pm3.echo.cool/index.php/2019/03/24/pn532工具合集/)

[pn532 指令参数](http://pm3.echo.cool/index.php/2019/03/23/nfc%e8%8a%af%e7%89%87-pn532%e7%9a%84%e4%bd%bf%e7%94%a8/)

[Proxmark 实验室](http://pm3.echo.cool/)