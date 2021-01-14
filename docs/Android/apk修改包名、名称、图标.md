## 前言

不为人知的某游戏 APP 会对手机检查是否有作弊 APP ，也就是检测手机上 APP 的包名嘛。在其次 wx 没有类似 qq 的关联功能，双号用户差评。

因为进行了反编译和回编译，所以 apk 签名会改变 ，部分 APP 对进行签名校验。以下记录都是以这个练手 [apk](https://mrskye.lanzous.com/b0c8crdkd) 记录的基础步骤。(密码:8was)

## 修改包名

### 反编译 APK 获取包名

可以用 apktool 也可以用 apkkiller（后面简称AK） 反编译 apk ，在文件夹下找到 AndroidManifest.xml 。

一般在 xml 的头部能找到：``package="app.skyenews.jy"``。``app.skyenews.jy``就是原始包名。

### 更改包名

原始包名：``app.skyenews.jy``

目标包名：``app.skyenews.jy123``

首先改相关资源的路径，就是 xml 里面的 activity 的路径；在这一步也同时修改了 xml 的 provider（内容提供者）属性。

在 AK 操作的话，搜索字符：``app.skyenews.jy``，替换字符：``app.skyenews.jy123``，搜索范围：当前整个项目，先按搜索再按全部替换。

![](https://mrskye.cn-gd.ufileos.com/img/2020-05-15-O1pwTXLyhc7yw8pF.png)

然后就是替换 smail 代码等里面的路径。搜索字符：``app/skyenews/jy``，替换字符：``app/skyenews/jy123``，搜索范围：当前整个项目，先按搜索再按全部替换。

![](https://mrskye.cn-gd.ufileos.com/img/2020-05-15-IyLg2nSa3pnhN98S.png)

### 回编译

替换完成后就可以回编译 apk ，安装即可。

<img src="https://mrskye.cn-gd.ufileos.com/img/2020-05-15-p2CMskFMKDgjNSBv.png" style="zoom:80%;" />

两个 apk 都能正常工作：

![](https://mrskye.cn-gd.ufileos.com/img/2020-05-15-2a0IpF8VrQsHDynk.png)

当你了解并学习完修改包名的操作后，自己修改其他 apk 包名时，有可能遇到包名检测等错误而无法正常使用修改版的 apk ，请善用 debug 。比如遇到包名检测，可以试着找到包名检测的 smail 代码，修改跳转条件等操作。

## 修改名称

第一步还是先反编译。

在 AK 中搜索字符：``app_name``或``label``，搜索范围：当前整个项目。如果出现多个搜索结果，真正存放的地方一般是在``strings.xml``或``AndroidManifest.xml``。修改无效的可以考虑直接搜索 app 名称，通常是明文存储或是 unicode 编码存储。

存储在 ``strings.xml``的例子：

![](https://mrskye.cn-gd.ufileos.com/img/2020-05-15-TDXO60VemtrdEk5S.png)

明文存储在 ``AndroidManifest.xml``的例子：（main activity 中的 label 属性可作为 APP 的名称）

![](https://mrskye.cn-gd.ufileos.com/img/2020-05-15-5E7kQZ5hNgvgpkik.png)

## 修改图标

第一步还是先反编译。

找到根目录的``AndroidManifest.xml``，然后找 ``application`` 标签。标签内的``android:icon="@mipmap/launcher_icon"``就是管图标的，其中：``@mipmap/launcher_icon``是图标的路径，翻译过来就是 res/mipap-xxxx/launcher_icon.png 。其中 xxxx 是对应各个分辨率的文件夹，运行会根据手机分辨率不同，自动去拿对应分辨率的。

假设修改为 res/drawable/abc_ic_menu_paste_mtrl_am_alpha.png ，就应该修改属性为：``android:icon="@drawable/abc_ic_menu_paste_mtrl_am_alpha"``

![](https://mrskye.cn-gd.ufileos.com/img/2020-05-15-3HsKvhLprxdVGROn.png)

## 练习资源

[蓝奏云](https://mrskye.lanzous.com/b0c8crdkd)

密码（请使用base64解密）:OHdhcw==