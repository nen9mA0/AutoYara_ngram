### Requirement

* radare2  最新版5.7.6，我们实验机是windows所以装的是win64的安装包 https://github.com/radareorg/radare2/releases/download/5.7.6/radare2-5.7.6-w64.zip
  
  如果采用的linux就选择对应版本吧 [Release 5.7.6 · radareorg/radare2 · GitHub](https://github.com/radareorg/radare2/releases/tag/5.7.6)
  
  **解压完成后需要把radare2下的bin文件夹加入环境变量（对于windows）**，若成功，在命令行输入r2会回显radare2主程序的选项

* python r2pipe包 `pip install r2pipe`

* makefile 我的版本是
  
  ```
  GNU Make 3.81
  Copyright (C) 2006  Free Software Foundation, Inc.
  This is free software; see the source for copying conditions.
  There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
  PARTICULAR PURPOSE.
  
  This program built for i386-pc-mingw32
  ```
  
  版本差异应该不大，是make都行，有问题再说
  
  **这里也注意要把bin下的make.exe加入环境变量（对于windows）**

### Configuration

#### makefile

目前makefile调用extractor.py，该python使用radare2对目标程序（`假设为a.exe`）进行分析，并将解析出的反汇编保存在 `a.asmdump` 文件下

##### 配置

修改 `TARGET_FOLDER` 变量为样本所在的文件夹，修改 `DUMP_FOLDER` 变量为分析后文件所在的文件夹，这里建议是把该程序文件、样本文件和dump文件分别放在不同的目录下

```
例如 TARGET_FOLDER = D:/sample  DUMP_FOLDER = D:/dump
则对于 D:/sample/calc.exe 分析后对应的文件是 D:/dump/calc.asmdump
```

**注意：路径分隔符斜杠方向，是`/`而不是`\`**

### 运行

* 在程序文件夹下打开终端

* 先 `make init` ，这里会调用一个脚本把所有大写后缀 `.EXE` 改为 `.exe`

* 再执行主要的操作
  
  ```
  make -i 2>err.log
  ```

* `-i` 忽略错误 `2>err.log`将错误信息保存到err.log

~~**注意，之前测了一下好像make -j有点问题，具体问题打算之后再看，可以先跑着（或者各位dalao帮忙找下）**~~

现在测了下make -j应该没什么问题

### Scripts

- makefile 用于对多个样本批量处理

- extractor.py 对一个样本文件使用radare2进行分析，并dump出各个函数的字节串，保存
  
  - -i 输入的样本文件路径
  
  - -o 输出的asmdump文件路径

- load.py 解析asmdump文件并根据当前的ngram规则生成结果（基本完成）

- ngram_reader.py  用来检查database中采集的ngram内容的，因为database的格式是我自己hash过的，所以需要这个程序做解析

- rename.py 很不优雅的代码，因为发现样本集里有些文件后缀是大写的 `.EXE` ，windows找文件不区分大小写但make是区分的，这个脚本用来把大写后缀 `.EXE` 改成小写 `.exe`

### Changelog

* 2022/8/13
  
  * extractor.py完成，makefile完成
  
  * TODO： load.py

* 2022/8/14
  
  * 加入rename.py
  * load.py基本完成
  * ngram_reader.py完成

* 2022/8/15
  
  * 整了老半天make -j的东西，好像能用了但我不知道为什么
