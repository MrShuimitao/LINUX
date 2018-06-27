#####  开始正题之前，先简单谈谈每一层的协议
###### 不同协议服务实现
###### 物理层：
	数据物理传输 PCS+PMA 
###### 链路层：
	局域网的连通问题 MAC header    src mac  dest mac l/t 
	PPPOE ARP(ARP欺骗 ARP嗅探)
###### 网络层：
	网络传输	src ip  dest ip 
	路由协议 NAT协议 ICMP   
###### 传输层：进程数据传输问题  
	SRC PORT DEST PORT  TYPE
	端口：80 443 22（ssh） 21（ftp） 23（telnet） 3306（mysql） 998 1702 等等分别对应了什么服务
###### 会话层：session 
###### 表示层：Socket
###### 	  应用层：
			HTTP HTTPS SSH TELNET P2P
			FTP  
	  原始套接字：
			ICMP SCTP OSPF MPLS RIP PPPOE 

### 首先一个问题！什么是socket？
![](http://47.100.10.167/wp-content/uploads/2018/04/41b17282cbc1a663db1632c0379eedb7.png)
### socket套接字：

>    
socket起源于Unix，而Unix/Linux基本哲学之一就是“一切皆文件”，都可以用“打开open –> 读写write/read –> 关闭close”模式来操作。Socket就是该模式的一个实现，socket即是一种特殊的文件，一些socket函数就是对其进行的操作（读/写IO、打开、关闭）.  
说白了Socket是应用层与TCP/IP协议族通信的中间软件抽象层，它是一组接口。在设计模式中，Socket其实就是一个门面模式，它把复杂的TCP/IP协议族隐藏在Socket接口后面，对用户来说，一组简单的接口就是全部，让Socket去组织数据，以符合指定的协议。

### socket需要什么协议？
最常见的两种是TCP/IP和UDP。
![](http://47.100.10.167/wp-content/uploads/2018/04/a6ee60138251a03bdd912936e3f39955.png)

##### 在讲述TCP/IP和UDP之前 我想先讲述一下 什么是ip地址？并且IP的地址的分类？
###### 首先，讲什么的是IP地址

-------------------------------------------------------
IP地址是指互联网协议地址（英语：Internet Protocol Address，又译为网际协议地址），是IP Address的缩写。IP地址是IP协议提供的一种统一的地址格式，它为互联网上的每一个网络和每一台主机分配一个逻辑地址，以此来屏蔽物理地址的差异。
IP地址是一个32位的二进制数，通常被分割为4个“8位二进制数”（也就是4个字节）。IP地址通常用“*点分十进制*”表示成（a.b.c.d）的形式，其中，a,b,c,d都是0~255之间的十进制整数。例：点分十进IP地址（100.4.5.6），实际上是32位二进制数（01100100.00000100.00000101.00000110）。( :smile: 请记住斜体字)

###### IP地址的分类 
	Internet上的每台主机(Host)都有一个唯一的IP地址。IP协议就是使用这个地址在主机之间传递信息，这是Internet 能够运行的基础。IP地址的长度为32位(共有2^32个IP地址)，分为4段，每段8位，用十进制数字表示，每段数字范围为0～255，段与段之间用句点隔开。例如159.226.1.1。IP地址可以视为网络标识号码与主机标识号码两部分，因此IP地址可分两部分组成，一部分为网络地址，另一部分为主机地址。IP地址分为A、B、C、D、E5类，它们适用的类型分别为：大型网络；中型网络；小型网络；多目地址；备用。常用的是B和C两类。
	如下图所示：
![](http://47.100.10.167/wp-content/uploads/2018/04/bb0a25af1ec4dc4774bc586939f65cfb.png)

| 类别  |  最大网络数 | IP地址范围  | 最大主机数  |  私有IP地址范围 |
| ------------ | ------------ | ------------ | -----------  -- | ------------ |
|  A  |   126（2^7-2) |  1.0.0.1-126.255.255.254  |  16777214|  10.0.0.0-10.255.255.255   |
|  B  |  16384(2^14)  |  128.0.0.0-191.255.255.255  | 65534  |  172.16.0.0-172.31.255.255  |
|  C  |  2097152(2^21)  |   192.0.0.0-223.255.255.255  |  254 |  192.168.0.0-192.168.255.255  |

###### 特殊的网址
1. 每一个字节都为0的地址（“0.0.0.0”）对应于当前主机；
2. IP地址中的每一个字节都为1的IP地址（“255．255．255．255”）是当前子网的广播地址；
3. IP地址中凡是以“11110”开头的E类IP地址都保留用于将来和实验使用。
4. IP地址中不能以十进制“127”作为开头，该类地址中数字127．0．0．1到127．255．255．255用于回路测试，如：127.0.0.1可以代表本机IP地址，用“http://127.0.0.1”就可以测试本机中配置的Web服务器。
5. 网络ID的第一个8位组也不能全置为“0”，全“0”表示本地网络。
(来自百度百科 www.baidu.com)


### 那TCP/IP和UDP分别是什么且有什么区别？
下图很明确的解释了两者的区别。
![]()

###### 接下来，说一下网络中数据传输的是以什么样的形式传输的？
![](http://47.100.10.167/wp-content/uploads/2018/06/4adadd423736bd9bd281aad74bdbb0c3.png)

![](http://47.100.10.167/wp-content/uploads/2018/06/e2eb679817b86e1f5de0c963773f0dd7.png)

![](http://47.100.10.167/wp-content/uploads/2018/06/78cb0c710bdd5921820369ee6defefe6.png)
数据传输过程中层层套头的过程，通信过程中，一方会进行加上这些头，把数据打成包，发送给数据的接收方，接受就会进行一层层的去头，最终得到通信数据。这个过程需要一层一层的协议。

![](http://47.100.10.167/wp-content/uploads/2018/04/5baa490cc5a0417c3121e08775052dc6.png)
#### 以太网链路层的数据帧格式
![](http://47.100.10.167/wp-content/uploads/2018/04/f661ff506339cc6582cd728ac88c0cb3.png)

#### IP数据包头
![](http://47.100.10.167/wp-content/uploads/2018/04/a148f05591b30d89f4a66738920e7ebf.png)
#### TCP包头
![](http://47.100.10.167/wp-content/uploads/2018/04/45ef26f320186425164add95ec1beada.png)
#### UDP包头
![](http://47.100.10.167/wp-content/uploads/2018/04/7f4d9545ea94c53f395adf4ce85b82bd.png)

<!--nextpage-->

### 简述通信过程
#### 面向链接的socket通信
![](http://47.100.10.167/wp-content/uploads/2018/04/85cfe516d5836bbbc0ab15873fcdbade.png)
#### 面向无链接的socket通信
![](http://47.100.10.167/wp-content/uploads/2018/04/55bcd768a68ad33a678b3fca0fd3d0b1.png)
1. 	首先，服务器端需要做以下准备工作：
（1）调用socket()函数。建立socket对象，指定通信协议。
（2）调用bind()函数。将创建的socket对象与当前主机的某一个IP地和端口绑定。
（3）调用listen()函数。使socket对象处于监听状态，并设置监听队列大小。

2. 	客户端需要做以下准备工作：
（1）调用socket()函数。建立socket()对象，指定相同通信协议。
（2）应用程序可以显式的调用bind()函数为其绑定IP地址和端口，当然，也可以将这工作交给TCP/IP协议栈。

3. 	接着建立通信连接：
（1）客户端调用connect()函数。向服务器端发出连接请求。
（2）服务端监听到该请求，调用accept()函数接受请求，从而建立连接，并返回一个新的socket文件描述符专门处理该连接。
然后通信双方发送/接收数据：
（1）服务器端调用write()或send()函数发送数据，客户端调用read()或者recv()函数接收数据。反之客户端发送数据，服务器端接收数据。
（2）通信完成后，通信双方都需要调用close()或者shutdown()函数关闭socket对象

### Socket编程API
#### 1.socket
![](http://47.100.10.167/wp-content/uploads/2018/04/11a84bb6019116813b8942c64a0bb8e3.png)
	socket函数对应于普通文件的打开操作。普通文件的打开操作返回一个文件描述字，而socket()用于创建一个socket描述符（socket descriptor），它唯一标识一个socket。这个socket描述字跟文件描述字一样，后续的操作都有用到它，把它作为参数，通过它来进行一些读写操作。
	正如可以给fopen的传入不同参数值，以打开不同的文件。创建socket的时候，也可以指定不同的参数创建不同的socket描述符，socket函数的三个参数分别为：
•	protofamily：即协议域，又称为协议族（family）。常用的协议族有，AF_INET(IPV4)、AF_INET6(IPV6)、AF_LOCAL（或称AF_UNIX，Unix域socket）、AF_ROUTE等等。协议族决定了socket的地址类型，在通信中必须采用对应的地址，如AF_INET决定了要用ipv4地址（32位的）与端口号（16位的）的组合、AF_UNIX决定了要用一个绝对路径名作为地址。
•	type：指定socket类型。常用的socket类型有，SOCK_STREAM、SOCK_DGRAM、SOCK_RAW、SOCK_PACKET、SOCK_SEQPACKET等等（socket的类型有哪些？）。
•	protocol：故名思意，就是指定协议。常用的协议有，IPPROTO_TCP、IPPTOTO_UDP、IPPROTO_SCTP、IPPROTO_TIPC等，它们分别对应TCP传输协议、UDP传输协议、STCP传输协议、TIPC传输协议（这个协议我将会单独开篇讨论！）。
	注意：并不是上面的type和protocol可以随意组合的，如SOCK_STREAM不可以跟IPPROTO_UDP组合。当protocol为0时，会自动选择type类型对应的默认协议。
	当我们调用socket创建一个socket时，返回的socket描述字它存在于协议族（address family，AF_XXX）空间中，但没有一个具体的地址。如果想要给它赋值一个地址，就必须调用bind()函数，否则就当调用connect()、listen()时系统会自动随机分配一个端口。
	
---------------------------------------------
#### 2.bind()函数
正如上面所说bind()函数把一个地址族中的特定地址赋给socket。例如对应AF_INET、AF_INET6就是把一个ipv4或ipv6地址和端口号组合赋给socket。
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
函数的三个参数分别为：
•	sockfd：即socket描述字，它是通过socket()函数创建了，唯一标识一个socket。bind()函数就是将给这个描述字绑定一个名字。
•	addr：一个const struct sockaddr *指针，指向要绑定给sockfd的协议地址。这个地址结构根据地址创建socket时的地址协议族的不同而不同，如ipv4对应的是： 

```
	struct sockaddr_in {
	    sa_family_t    sin_family; /* address family: AF_INET */
	    in_port_t      sin_port;   /* port in network byte order */
	    struct in_addr sin_addr;   /* internet address */
	};
	/* Internet address. */
	struct in_addr {
	    uint32_t       s_addr;     /* address in network byte order */
};

ipv6对应的是： 
struct sockaddr_in6 { 
    sa_family_t     sin6_family;   /* AF_INET6 */ 
    in_port_t       sin6_port;     /* port number */ 
    uint32_t        sin6_flowinfo; /* IPv6 flow information */ 
    struct in6_addr sin6_addr;     /* IPv6 address */ 
    uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */ 
};

struct in6_addr { 
    unsigned char   s6_addr[16];   /* IPv6 address */ 
};

Unix域对应的是：#define UNIX_PATH_MAX    108
struct sockaddr_un { 
    sa_family_t sun_family;               /* AF_UNIX */ 
    char        sun_path[UNIX_PATH_MAX];  /* pathname */ 
};
```

> 
addrlen：对应的是地址的长度。  :bowtie::stuck_out_tongue_closed_eyes:
特别强调一下这里为什么用的是socklen_t而不是int整形,因为并非所有的机器内部对int类型的规定是的4字节，例如ARM中int就为两字节，为了通信的正常和方便，规定了了socklen_t。
注：这里的sockaddr和sockaddr_in两个结构体，可以相互强转，sockaddr一般传递参数时使用，sockaddr_in一般在自己设置结构的的时候使用。
> 

##### 网络字节序与主机字节序
**主机字节序就是我们平常说的大端和小端模式：不同的CPU有不同的字节序类型，这些字节序是指整数在内存中保存的顺序，这个叫做主机序。引用标准的Big-Endian和Little-Endian的定义如下：**
> a) Little-Endian就是低位字节排放在内存的低地址端，高位字节排放在内存的高地址端。
　b) Big-Endian就是高位字节排放在内存的低地址端，低位字节排放在内存的高地址端。
> 

**网络字节序：4个字节的32 bit值以下面的次序传输：首先是0～7bit，其次8～15bit，然后16～23bit，最后是24~31bit。这种传输次序称作大端字节序。由于TCP/IP首部中所有的二进制整数在网络中传输时都要求以这种次序，因此它又称作网络字节序。字节序，顾名思义字节的顺序，就是大于一个字节类型的数据在内存中的存放顺序，一个字节的数据没有顺序的问题了。**


![](http://47.100.10.167/wp-content/uploads/2018/04/2696fbb986b4f9b33b73104fb3f4e901.png)
解决方法：
![](http://47.100.10.167/wp-content/uploads/2018/04/8169d4b9f9a62b0d2124ee59eec7271f.png)

---------------------------------------
#### 3.listen()、connect()函数
>
如果作为一个服务器，在调用socket()、bind()之后就会调用listen()来监听这个socket，如果客户端这时调用connect()发出连接请求，服务器端就会接收到这个请求。
```
int listen(int sockfd, int backlog);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); 
```
listen函数的第一个参数即为要监听的socket描述字，第二个参数为相应socket可以排队的最大连接个数。socket()函数创建的socket默认是一个主动类型的，listen函数将socket变为被动类型的，等待客户的连接请求。
connect函数的第一个参数即为客户端的socket描述字，第二参数为服务器的socket地址，第三个参数为socket地址的长度。客户端通过调用connect函数来建立与TCP服务器的连接。
>
------------------------------------------
#### 4.accept()函数
TCP服务器端依次调用socket()、bind()、listen()之后，就会监听指定的socket地址了。TCP客户端依次调用socket()、connect()之后就向TCP服务器发送了一个连接请求。TCP服务器监听到这个请求之后，就会调用accept()函数取接收请求，这样连接就建立好了。之后就可以开始网络I/O操作了，即类同于普通文件的读写I/O操作。
```
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); //返回连接connect_fd
```
参数sockfd
参数sockfd就是上面解释中的监听套接字，这个套接字用来监听一个端口，当有一个客户与服务器连接时，它使用这个一个端口号，而此时这个端口号正与这个套接字关联。当然客户不知道套接字这些细节，它只知道一个地址和一个端口号。
参数addr
这是一个结果参数，它用来接受一个返回值，这返回值指定客户端的地址，当然这个地址是通过某个地址结构来描述的，用户应该知道这一个什么样的地址结构。如果对客户的地址不感兴趣，那么可以把这个值设置为NULL。
参数len
如同大家所认为的，它也是结果的参数，用来接受上述addr的结构的大小的，它指明addr结构所占有的字节个数。同样的，它也可以被设置为NULL。
如果accept成功返回，则服务器与客户已经正确建立连接了，此时服务器通过accept返回的套接字来完成与客户的通信。
注意：
      accept默认会阻塞进程，直到有一个客户连接建立后返回，它返回的是一个新可用的套接字，这个套接字是连接套接字
	  
---------------------------------------
#### 5.read()、write()等函数
万事具备只欠东风，至此服务器与客户已经建立好连接了。可以调用网络I/O进行读写操作了，即实现了网咯中不同进程之间的通信！网络I/O操作有下面几组：
```
	read()/write()
	recv()/send()
	readv()/writev()
	recvmsg()/sendmsg()
	recvfrom()/sendto()
```
我推荐使用recvmsg()/sendmsg()函数，这两个函数是最通用的I/O函数，实际上可以把上面的其它函数都替换成这两个函数。它们的声明如下：
```
#include <unistd.h>
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);

#include <sys/types.h>
#include <sys/socket.h>
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
```

read函数是负责从fd中读取内容.当读成功时，read返回实际所读的字节数，如果返回的值是0表示已经读到文件的结束了，小于0表示出现了错误。如果错误为EINTR说明读是由中断引起的，如果是ECONNREST表示网络连接出了问题。
write函数将buf中的nbytes字节内容写入文件描述符fd.成功时返回写的字节数。失败时返回-1，并设置errno变量。 在网络程序中，当我们向套接字文件描述符写时有俩种可能。1)write的返回值大于0，表示写了部分或者是全部的数据。2)返回的值小于0，此时出现了错误。我们要根据错误类型来处理。如果错误为EINTR表示在写的时候出现了中断错误。如果为EPIPE表示网络连接出现了问题(对方已经关闭了连接)。

--------------------------------------------
#### 6.close()函数
在服务器与客户端建立连接之后，会进行一些读写操作，完成了读写操作就要关闭相应的socket描述字，好比操作完打开的文件要调用fclose关闭打开的文件。
``#include <unistd.h>``
``int close(int fd);``
close一个TCP socket的缺省行为时把该socket标记为以关闭，然后立即返回到调用进程。该描述字不能再由调用进程使用，也就是说不能再作为read或write的第一个参数。
注意：close操作只是使相应socket描述字的引用计数-1，只有当引用计数为0的时候，才会触发TCP客户端向服务器发送终止连接请求。

-----------------------------------------------
## TCP/IP的三次握手
![](http://47.100.10.167/wp-content/uploads/2018/04/9a8babb59937742deb47663eb5f5eb4f.png)
Socket编程过程中，我想强调的一点是accept()是一个阻塞函数，并且由它来完成TCP/IP协议中非常极其重要的三次握手，具体过程如上图。

**第一次握手：建立连接时，客户端发送syn包(syn=j)到服务器，并进入SYN_SEND状态，等待服务器确认；SYN：同步序列编号(Synchronize Sequence Numbers)。
第二次握手：服务器收到syn包，必须确认客户的SYN（ack=j+1），同时自己也发送一个SYN包（syn=k），即SYN+ACK包，此时服务器进入SYN_RECV状态；
第三次握手：客户端收到服务器的SYN+ACK包，向服务器发送确认包ACK(ack=k+1)，此包发送完毕，客户端和服务器进入ESTABLISHED状态，完成三次握手。
一个完整的三次握手也就是： 请求---应答---再次确认。**

## TCP/IP的四次握手释放
**很奇怪为什么一个三次握手需要四次握手来释放呢？**
其实，这是由TCP的半关闭(half-close)造成的。
![](http://47.100.10.167/wp-content/uploads/2018/04/283baa02f33b8b73a9fbca3c5117d1a7.png)
**1．为什么建立连接协议是三次握手，而关闭连接却是四次握手呢？**
这是因为服务端的LISTEN状态下的SOCKET当收到SYN报文的建连请求后，它可以把ACK和SYN（ACK起应答作用，而SYN起同步作用）放在一个报文里来发送。但关闭连接时，当收到对方的FIN报文通知时，它仅仅表示对方没有数据发送给你了；但未必你所有的数据都全部发送给对方了，所以你可以未必会马上会关闭SOCKET,也即你可能还需要发送一些数据给对方之后，再发送FIN报文给对方来表示你同意现在可以关闭连接了，所以它这里的ACK报文和FIN报文多数情况下都是分开发送的。
**2．为什么TIME_WAIT状态还需要等2MSL后才能返回到CLOSED状态？**
这是因为虽然双方都同意关闭连接了，而且握手的4个报文也都协调和发送完毕，按理可以直接回到CLOSED状态（就好比从SYN_SEND状态到ESTABLISH状态那样）；但是因为我们必须要假想网络是不可靠的，你无法保证你最后发送的ACK报文会一定被对方收到，因此对方处于LAST_ACK状态下的SOCKET可能会因为超时未收到ACK报文，而重发FIN报文，所以这个TIME_WAIT状态的作用就是用来重发可能丢失的ACK报文。

### 实例演示
![](http://47.100.10.167/wp-content/uploads/2018/04/f3b0e4abfd31b4c109a774d4364282bb.png)