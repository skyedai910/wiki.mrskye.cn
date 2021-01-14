## 获取当前页面的信息

可以获取当前页面所在的 smail 文件等信息

[collapse title="展开查看详情" status="false"]

adb 命令：

```shell
adb shell dumpsys activity top
```

输入样式：

```shell
>adb shell dumpsys activity top
TASK com.v2ray.ang id=55527 userId=0
  ACTIVITY com.v2ray.ang/.ui.MainActivity e6fdfe pid=3052
    Local Activity 49dce53 State:
      mResumed=false mStopped=true mFinished=false
      mChangingConfigurations=false
      mCurrentConfig={1.0 0  460mcc1mnc [zh_CN,en_US] 
```

dumpsys 命令用于获取详尽的系统信息，通常在后面搭配参数只输出部分信息，如：屏幕输入值、电源、内存等，详细使用手册可以到[安卓开发者平台](https://developer.android.com/studio/command-line/dumpsys)查看。

[/collapse]

## 打开/关闭页面执行函数

广告打开/关闭页面时弹出，或者打开/关闭 APP 时弹出，可能与 ``onCreat``/``onDestroy`` 函数有关。

## smail 代码

[collapse title="展开查看详情" status="false"]

* 方法下面的``.locals n``表示方式局部使用``n``个寄存器
* ``pn``代表方法传入的第``n``个参数
* ``vn``代表使用第``n``个寄存器

[/collapse]