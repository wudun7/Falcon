# Falcon

```
对xx驱动深度学习代码，可编译为库文件和驱动文件，方便调用和调试学习，希望大家共同努力完善代码！
```

# 安装

```
md X:\Labs
cd /d X:\Labs
git clone https://github.com/wudun7/MiniSDK.git
git clone https://github.com/wudun7/WRK.git
git clone https://github.com/wudun7/Falcon.git
```

克隆完成后目录结构

```
Falcon
MiniSDK
WRK
```

# 构建



```
cd /d X:\Labs\Falcon

方法1：运行FastBuild.cmd
方法2：使用VisualStudio编译
```



# 使用示例

```
驱动加载时执行FalconEntry，卸载驱动时执行FalconUnload，示例可见：
https://github.com/wudun7/FalconLibTest.git
编译示例时请使用VisualStdio开发者命令行工具,并修改makefile中的KM_PATH和LIBDIR 为本机路径
```



# 代码

```
内置Capstone和zydis反汇编引擎，反汇编代码并指定回调
	CapstoneDisasmWithCallback

内核MinHook(PG绕过已经部分实现还未发布，后续完善测试后再进行发布)
	MinHook
	MinUnHook
	
DPC/Ipi多核同步代码执行
	SyncDpcExecuteProxy
	SyncIpiExecuteProxy
	
Ntdll映射
	MapNtdll
	
NtosKrnl映射，可以指定回调
	MapNtoskrnlFileWithCallback

内核栈回溯
	StackWalk
	
SSDT/SSSDT Nt Api地址解析(全局初始化调用号，以此来获取函数地址)
	GetSsdtRoutineAddress
	
获取pool内存池信息，扫描pool查找image文件
	GetPoolInfoByAddress
	SacnBigPoolAndFindImage
	
内存读写，hash，文件，进程，时钟流速检查....
```



# 鸣谢

感谢飞哥早期开源的shark，学到很多

```
https://github.com/9176324/Shark
```







