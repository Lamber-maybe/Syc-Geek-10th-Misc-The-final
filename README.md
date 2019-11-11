# Syc Geek 10th -- Misc -- The final 出题心得 && WriteUp

## 一、出题心得
### 出题背景
起初出这个题的时候主要是为了让外校的师傅能有一点玩头（毕竟一个主要面向新生的比赛，可能老师傅们做起来会感觉索然无味）。
所以这个题目在初步规划的时候就画了一个很大的饼，预期设计10个part左右，然后环环相扣，再辅以一个完整剧本。
但实际出题的时候，发现如果规模过大的话，最后对题目进行测试时会非常麻烦，而且一旦出了bug，会牵动到很多部分，修补起来也会异常困难。
所以在与几位小伙伴商量之下，决定控制在5个part左右，以达到题目的最优性能。
而对于每个part之间的剧情联系，尽量降到最低。方便每个part单独管理，这样在出了bug的情况下，不至于动辄修补整个题目。
但有点可惜的是，题目出好了之后，刚好是hxb跟hmb举办的时候。很多师傅都去肝那两个比赛了。这道题也无人问津。
最后就只能留给新生解了，不过也是预期之中，新生没有一个解出来的。

### 出题流程
整个题的灵感来源于ctftime上看见的一种叫malbolg的语言，在维基百科上可以看到一句话
> This article is about the programming language. For the eighth circle of hell in Dante's Inferno, see Malebolge.
 
可以看到这个语言跟但丁的神曲有点关系，而神曲有三部。地狱 -- 炼狱 -- 天堂，刚好可以作为题目剧本。说干就干！
然后在选择题目载体的时候，最开始计划直接用zip，但是会显得题目有点干燥。所以选择使用了VMDK文件作为载体。（也考虑过使用vmem，但奈何vmem题目的解题操作实在繁琐，可能会影响做题体验）
然后就将每个部分出好之后，放入win7虚拟机（注意我并没有将题目文件放入同一个目录下，而是根据每一个部分的题目文件所具备的特性，放入了比较适合那个文件的文件目录）
一切准备好之后，将VMware虚拟机目录下的VMDK文件打包成压缩包，然后上传至云盘。整个题目就算出好了



## 二、Something useful
### 解题思路
根据备注信息: 
```
Stupid mortal, you must enter the eighth circle of Hell to get the Tip of god。'=B;:?8\<;:921Uv.3,1*No'&J*)iF~%$#zy?w|{zsr8pun4rTji/PONMLKJIHGFEDCBA@?>=<;:
987SRQ3IHMFKDCBf)('&%$#"!~}|{zyxwvutsrqpon,+*)i'&%${zy?}|{t:xwp6Wsrkj0QPONML
KJIHGFEDCBA@VUTYXWVUTSRKoON0LKDCgfS
```
谷歌关键字 `the eighth circle of Hell` 可以在维基百科上看到一种叫[Malbolge](https://en.wikipedia.org/wiki/Malbolge) 的加密。找到[解密网站](http://malbolge.doleczek.pl/#)解密密文部分，得到压缩包密码
```
%&^&#@()(*:";'/,,
```

然后解压之后，可以看到该题目所需要的所有部分
```
神说：要有ELF！！！
神说：要有WORD！！！
神说：要有NTFS！！！
神说：要有PDF！！！
神说：要有OSZ！！！
```

并且可以拿到这道题目的故事线
```
地狱 -- 炼狱 -- 天堂
```

## 三、NTFS --> Door
### 解题思路
入手VMDK文件, 推荐最简单快捷的方式是利用 `7-zip` 压缩软件解压。
解压之后，可以看到是一个完整的Windows目录。在桌面目录下，我们可以看到有一个 `Door.png` 内容为 `我不入地狱，谁入地狱`。可以想到此处应该是整个故事的起始点。
但经过各种图片隐写的尝试之后，发现并没有任何效果。回去看 `Something useful` 在这个地方有可能出现的只有 `NTFS`。

### 处理NTFS流 --> Purgatory.exe
首先用 `dir /a /r` 确定该目录下存在ntfs流
![](https://i.imgur.com/g3662HO.png)

然后利用工具， 提取ntfs流文件。
![](https://i.imgur.com/PdBpbn6.png)

执行结果如下
```
请将该文件放入炼狱中执行（能进入天堂的是Mr.png，Mrs.jpg只能下地狱）
```

现在拿到的线索就有两个了，一个是该文件需要放入“炼狱”中执行，另一个是png上天堂，jpg下地狱。

## 四、ELF --> Purgatorio（炼狱）

### 将NTFS提取出的文件，在炼狱中执行
上一个part里面，我们执行了从NTFS里面提取出来的Purgatory.exe。其中一个提示是放入炼狱中执行。
我们在 `Windows7_by_Lamber.vmdk\Program Files (x86)\Linux\` 目录下找到了我们的炼狱（Purgatorio）
将Purgatory.exe放入该目录，执行得到结果如下
```
智慧之神evoA说，你需要修复ELF
```
同时这里有一个小坑，运行之后会把该目录下的elf文件删除（2333）
注意这里的 `evoA` 如果有脑洞厉害的同学，在接下来的解题过程中能用上。脑洞不够大也没关系，对解题影响不大。

### 解题思路
修复ELF文件，随后通过提示解MD5得到秘钥，通过传参方式输入秘钥从服务器下载得到flag。
### ELF修复
1. 在修复ELF文件时，首先要获知其损毁部分。将损坏的ELF文件拖入hxd或其他二进制软件中，可发现Magic为0x20,0x45,0x4c,0x46，但正确的ELF文件Magic为0x7f 0x45 0x4c 0x46，此处修改保存即可。
2. 放入linux系统尝试执行，将提示文件为不可执行，使用readelf -h \<file\>指令，获取文件属性，可发现文件为32位可执行文件，且文件类型为ET_NONE，此处需要将文件类型修改为ET_EXEC或ET_DYN，由于难以直接确定地址，可考虑通过脚本修复。

脚本如下：
```cpp=
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * release: gcc ./FileFix.c -m32 -o ./FileFix
 * 若提示权限问题，请使用root权限执行
 * 参考资料：《Linux二进制分析》
 * 使用方法：FileFix <filename>
 * */

int main(int argc,char *argv[]){
    int fd;
    uint8_t *mem;
    struct stat st;
 
    Elf32_Ehdr *ehdr;

    if(argc < 2){
        printf("No input file.\n");
        exit(0);
    }

    //尝试读取文件
    if((fd = open(argv[1],O_RDWR)) < 0){
        perror("open");
        exit(0);
    }

    //校验文件大小
    if(fstat(fd, &st) < 0){
        perror("fstat");
        exit(0);
    }

    /*映射文件到内存*/
    mem = mmap(NULL,st.st_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
    if(mem == MAP_FAILED){
        perror("mmap");
        exit(0);
    }

    /*识别并修改elf各部分内容*/
    ehdr = (Elf32_Ehdr *)mem;


    //校验标志位
    if(mem[0] != 0x7f && strcmp(&mem[1],"ELF")){
	mem[0] = 0x7f;
    	mem[1] = 'E';
	mem[2] = 'L';
	mem[3] = 'F';	
        printf("File <%s> magic has been fixed.\n",argv[1]);        
    }else{
	printf("File <%s> magic do not need to fix.\n",argv[1]);    
    }

    //检验文件类型是否为可执行（ET_EXEC）
    if(ehdr->e_type == ET_NONE){
        ehdr->e_type = ET_EXEC;
	printf("File <%s> head type has been fixed.\n",argv[1]);
    }else{
        printf("File <%s> do not need to fix\n",argv[1]);
        exit(0);
    }

    //写入文件
    if(munmap((void*)mem,st.st_size) == -1){
        perror("munmap");
        exit(0);
    }

    printf("File <%s> has been fixed\n",argv[1]);
}
```
将脚本编译后执行，结果如下：
```bash
root@:/home/Misc# readelf -l ./Misc_32_modify 
readelf：错误： 不是 ELF 文件 - 它开头的 magic 字节错误
root@:/home/Misc# ./FileFix ./Misc_32_modify
File <./Misc_32_modify> magic has been fixed.
File <./Misc_32_modify> head type has been fixed.
File <./Misc_32_modify> has been fixed
root@:/home/Misc# readelf -l Misc_32_modify 

Elf 文件类型为 EXEC (可执行文件)
Entry point 0x5c0
There are 9 program headers, starting at offset 52
#略去之后内容
```
### ELF文件分析

#### 常规解法
1. 修复完ELF文件后，尝试执行文件，会得到“Foolish human! Use your mind to think about what god's will means!”提示。
2. 使用ida分析，会发现程序经过去符号处理；尝试搜索字符串，会发现没有有效结果，因此推测字符串被进行了加密处理，不过通过分析start函数，即可快速定位main函数。
![](https://i.imgur.com/MpnPg1V.png)
3. 分析main函数，可发现对传入参数进行了检查，需满足传入参数大于1且argv\[1\]不为空。
![](https://i.imgur.com/kRhzKGy.png)
4. 尝试传入参数执行，将得到提示“Wise man, Can you help me solve this problem: 30e308e8e7122579b8ea2fae774d1999 ?”，根据经验判断为md5编码，随便找一个在线解md5的网站即可解得结果为evoA，此处也可以通过exe文件推测秘钥为evoA。
5. 执行\<filename\> evoA得到结果为：
pdfkG@0zl_3ptmVPfa7LHuB8rs#cRdi$

#### 非常规解法
本题ELF文件逻辑并不复杂，通过常规逆向分析也可解出，只是需要花费更多时间。
1. 通过start函数找到main函数，可发现main函数首先调用sub_8049F47进行反调试操作，一旦检测到程序被调试将强制删除自身并尝试执行关机指令，若需进行调试分析，可修改跳转。
2. 程序随后会判断传入参数合法性，并根据不同传参情况给予不同提示。若传入参数为空，则会提示“Foolish human! Use your mind to think about what god's will means!”；若传入参数长度不为4，则会提示“Wise man, Can you help me solve this problem: 30e308e8e7122579b8ea2fae774d1999 ?”；若传入参数长度为4，则会对传入参数进行md5编码，并与“30e308e8e7122579b8ea2fae774d1999”校对，此处可通过在线md5解密网站或者写脚本爆破得到结果evoA。
3. 正常情况下解到这步就无需继续逆向，但若继续分析，可得到flag产生原理。程序之后会使用rc4解密一处全局变量，私钥即为传入参数evoA，随后调用sub_804A369，追踪该函数可发现程序会创建一个名为.tgnlc的隐藏文件，并将之前解密的全局变量内容写入.tgnlc，之后执行如下shell指令：
    ```bash
    chmod 777 ./.tgnlc    #为文件分配最高权限
    python3 ./.tgnlc      #执行python文件
    rm -f ./.tgnlc        #强制删除python文件
    ```
4. 通过dump或者写脚本解密等方式可提取出python文件，稍作分析即可发现该python脚本通过socket连接服务器，并以evoA作为key验证，在验证通过后会返回正确信息，失败则会返回假flag，若出现连接失败等情况，也会直接输出假flag。出于安全考虑，服务端的代码不做公布，客户端（即dump下的python脚本）代码如下：
```python=
#!usr/bin/Python3
import socket
host = '47.94.39.239'
Port = 9987
key = 'evoA'
Str = ''
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host,Port))
	s.sendall(bytes(key,encoding='utf-8'))
	Str = str(s.recv(1024),encoding='utf-8')
except:
	pass
finally:
	if(len(Str) == 0):
		print("flag{This_1s_a_fake_flag_666}")
	else:
		print(Str)
```
修复后的ELF文件、包含详细注释的idb文件、脚本和编译之后的可执行文件可通过此链接下载：
https://res.cloudinary.com/macc1989/raw/upload/v1573149768/samples/Purgatorio%E8%AF%A6%E8%A7%A3.rar


## 五、PDF --> proverbs.pdf

### 解题思路
首先我们在download目录下，找到我们的pdf文件。
在上一个 `ELF part` 中，最后会拿到一串密文 `pdfkG@0zl_3ptmVPfa7LHuB8rs#cRdi$` 观察密文，开头几位是pdf，说明这串密文应该是pdf的密码。
解开pdf之后，可以看到一串密文。
![](https://i.imgur.com/c42H3Ye.png)

该密文为键盘密码，对照笔记本键盘翻译密文得到明文如下
```
The password of word is capital(proverbs of god)
```

拿到word部分的密码 `PROVERBS OF GOD` 。
注意这里有一个坑点，根据前文推测，表情包代表一个空格。所以在密码中间是有空格的。

## 六、Word --> Purgatory.docm
### 解题思路
首先我们在documents目录下，找到包含我们word文件的zip压缩包。
利用上一个 `PDF part` 中得到的密码，解开压缩包，拿到word。
打开之后，发现是一篇十六进制码。复制粘贴到010 editor中，可以看到有一个jpg文件头。根据 `NTFS part` 中的信息，该图片的文件头是被修改过的，正确文件头应该是png文件头。
修补好图片之后，还可以注意到，word文档提醒我们是否启用宏。说明这个word的宏部分有内容。查看宏模块
![](https://i.imgur.com/2yVLjzN.png)

发现有很长一段base64，此处采用的是一种叫base64隐写的隐藏信息的方式。
解密脚本如下
```python=
# base64steg_decode.py
b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
with open('1.txt', 'rb') as f:
    bin_str = ''
    for line in f.readlines():
        stegb64 = ''.join(line.split())
        rowb64 =  ''.join(stegb64.decode('base64').encode('base64').split())
        offset = abs(b64chars.index(stegb64.replace('=','')[-1])-b64chars.index(rowb64.replace('=','')[-1]))
        equalnum = stegb64.count('=')
        if equalnum:
            bin_str += bin(offset)[2:].zfill(equalnum * 2)
        print ''.join([chr(int(bin_str[i:i + 8], 2)) for i in xrange(0, len(bin_str), 8)]) 
        
# Hidden1nWord_
```

现在我们手上就有一个png图片，和一个密码 `Hidden1nWord_` 
根据密码句意隐藏在word文件中，而word文档中我们找到的文件只有一个png图片。
这时候想到使用带密码的lsb隐写(https://github.com/livz/cloacked-pixel) 解码得到
```
The password of paradise:Bliss_Syc!!!!
```
接下来就可以去最后一部分paradise（天堂）了！


## 七、OSU --> Paradise.osz

### 解题思路
收集信息，了解“.osz”后缀名及其编辑器，继续收集hint寻找解题方法，最终组合出flag。
### 处理“.osz”文件及其解压缩文件
在最后一部分可以获得一个名为paradise.osz的文件。查看其文件头会发现是zip格式。用zip格式解压后发现以下文件：
![](https://i.imgur.com/dgYwVgO.png)
#### AFKL - The final test (Syclover) [ascend to heaven].osu
其中AFKL - The final test (Syclover) [ascend to heaven].osu文件可以使用记事本等编辑器打开，可以发现以下数据：
```
[Metadata]
Title:The final test
TitleUnicode:最後のしれん
Artist:AFKL
ArtistUnicode:AFKL
Creator:Syclover
Version:Ascend To Heaven
Source:av33029948?p=6 bilibili
Tags:GEEK FLAG TIMEBASE README 36112Start md5ed CircleAndSlider
```
发现在Source中给了我们一个名为bilibili的视频网站的视频编号。浏览后发现其为介绍一款名为osu!的音乐游戏中自带的铺面编辑器。这提示我们应该用osu!来打开、编辑osz文件。
如果先去了解osz文件，也可以发现其实为音乐游戏osu!的铺面文件。那么接下来便是去用osu!来打开osz文件。这样做的人需要注意到在刚使用osu!打开后可以在左上角发现“av33029948?p=6 bilibili”：
![](https://i.imgur.com/qd70u8m.jpg)
但这样做的人是很难联想到去寻找解压后的铺面文件，为后期的解题带来困难。

#### readme.jpg
在解压的文件中还有一个readme.jpg打开后是正常图片。使用010eidtor打开。在文件尾部发现以下信息：
![](https://i.imgur.com/XOXUB1Y.png)
其中“in map”提示我们flag在铺面中。后面则给了一堆数字以及“Syc{}”，还有“Traversing.Time”。再结合“AFKL - The final test (Syclover) [ascend to heaven].osu”文件中tags所给的信息。我们可以发现，hint中大量提及了时间。不难想到这些数字的真正意味是“时间”。
### 使用编辑器寻找flag
现在用编辑器打开铺面。
在编辑器中，我们可以发现在左下角有“00:00:000”，可推测其代表的是时间。对照readme.jpg的数字，将其移动至对应时间。
首先第一组数字，我们可以发现滑条的形状组成了“S”，与之前在readme.jpg里数字后的“S”相符。
这个代表S![](https://i.imgur.com/dEXe55X.jpg)

再测试第二组，发现滑条的形状符合第二组数字后的“y”。
这个代表y![](https://i.imgur.com/9jHM5xx.jpg)

由此我们可以确定解题方向为“数字=>时间=>字符”。
接下来直接按顺序展示第二组以后每个时间点的元件摆放方式及其所代表的字符。
这个代表c![](https://i.imgur.com/YEGQ95f.jpg)

这个代表{![](https://i.imgur.com/gFdr6aJ.jpg)

这个代表4![](https://i.imgur.com/qhWUiQQ.jpg)

这个代表6![](https://i.imgur.com/eUIRxmC.jpg)

这个代表9![](https://i.imgur.com/cQdSuLA.jpg)

这个代表c![](https://i.imgur.com/iTWCCcs.jpg)

这个代表a![](https://i.imgur.com/i98LB1b.jpg)

这个代表4![](https://i.imgur.com/U3p2sPE.jpg)

这个代表8![](https://i.imgur.com/CSDcUr7.jpg)

这个代表e![](https://i.imgur.com/JvGZAse.jpg)

这个代表2![](https://i.imgur.com/eMKcNQB.jpg)

这个代表3![](https://i.imgur.com/U1JMsIp.jpg)

这个代表7![](https://i.imgur.com/jftjbd9.jpg)

这个代表f![](https://i.imgur.com/68x6NwR.jpg)

这个代表5![](https://i.imgur.com/xsMMNft.jpg)

这个代表9![](https://i.imgur.com/CCYmbJA.jpg)

这个代表d![](https://i.imgur.com/JEUrFzl.jpg)

这个代表6![](https://i.imgur.com/00ZDWM7.jpg)

这个代表f![](https://i.imgur.com/Cca87ri.jpg)

这个代表8![](https://i.imgur.com/WbPSR3V.jpg)

这个代表4![](https://i.imgur.com/KTPHMY9.jpg)

这个代表7![](https://i.imgur.com/xgwa3Pa.jpg)

这个代表c![](https://i.imgur.com/eruNcOT.jpg)

这个代表6![](https://i.imgur.com/tain6xR.jpg)

这个代表2![](https://i.imgur.com/Ib9fm0t.jpg)

这个代表3![](https://i.imgur.com/TwWRhiu.jpg)

这个代表c![](https://i.imgur.com/tIQwQsU.jpg)

这个代表e![](https://i.imgur.com/WPndsIB.jpg)

这个代表e(这里有两次)![](https://i.imgur.com/WPndsIB.jpg)

这个代表f![](https://i.imgur.com/r7FYwBv.jpg)

这个代表5![](https://i.imgur.com/6UE9IEd.jpg)

这个代表7![](https://i.imgur.com/asRgrjv.jpg)

这个代表7![](https://i.imgur.com/GuRgCz3.jpg)

这个代表7![](https://i.imgur.com/TnTNEEl.jpg)

这个代表}![](https://i.imgur.com/1bSpZLs.jpg)

由此组合出flag为：
```
Syc{469ca48e237f59d6f847c623ceef5777}
```
当然，我不排除部分人可能会在没有获得时间信息的情况下，发现滑条组成了字母，并用此直接拼接出flag。但这样是不可能行得通的。首先，在铺面中除了flag所包含的字符外，还有一些假字符，在没有获得时间的hint下是不可能略过它们的。其次，表示字符的不单单有滑条，还有单个的圆圈，在没有获得时间的hint下是一定会略过它们的。
