# pHttpClient是适用于PHP-FPM的长连接HTTP客户端扩展

在PHP-FPM环境下，通常使用curl或者stream wrapper获取HTTP API内容。由于每个请求都会释放资源，因此没有办法保持持久连接，无法获得更佳的性能。
php本身提供了一系列持久化stream的函数：
```php
resource pfsockopen ( string $hostname [, int $port = -1 [, int &$errno [, string &$errstr [, float $timeout = ini_get("default_socket_timeout") ]]]] )
```
可以使用这部分函数建立持久的socket连接，自己封装http协议。但需要自行解析php协议，性能较差。
为了在PHP-FPM环境中使用长连接HTTP，开发了此程序。

该扩展利用Zend Stream API建立socket长连接，拼装http请求后，利用php_http_parser解析http请求。使用方式比较简单：
```php
$url = "http://news.sohu.com/20160623/n455988077.shtml?ver=1";

$opt = array(
	'headers' => array(
		'User-Agent'=>'pHttpClient',
	),
	'proxy' => 'xx.xx.xx.xx:8080',
	'timeout' => 1,
);

phttp_get($url, $opt);
```

其中$opt为配置项，支持这几个配置：
```php
$opt = array(
	'headers' => array(),               //头信息 array
	'proxy' => 'xx.xx.xx.xx:8080',      //代理服务器ip:port
	'timeout' => 1.0,                   //超时double (s)
    'data' => array(),                  //POST使用的数据string|array()
    'method' => 'GET',                  //自行指定method，GET|POST|HEAD等
);
```
返回值包括：
```php
Array
(
    [headers] => Array
        (
            [Date] => Fri, 24 Jun 2016 06:19:26 GMT
            [Content-Type] => text/html;charset=utf-8
            [Connection] => keep-alive
            [Vary] => Accept-Encoding
        )

    [body] => "Hello, world!"
    [http_code] => 200
    [error_code] => 0
)
```
当发生错误时，error_code不为0，错误码同linux socket错误码：
```c	
124 EMEDIUMTYPE Wrong medium type
123 ENOMEDIUM No medium found
122 EDQUOT Disk quota exceeded
121 EREMOTEIO Remote I/O error
120 EISNAM Is a named type file
119 ENAVAIL No XENIX semaphores available
118 ENOTNAM Not a XENIX named type file
117 EUCLEAN Structure needs cleaning
116 ESTALE Stale NFS file handle
115 EINPROGRESS +Operation now in progress
114 EALREADY Operation already in progress
113 EHOSTUNREACH No route to host
112 EHOSTDOWN Host is down
111 ECONNREFUSED Connection refused
110 ETIMEDOUT +Connection timed out
109 ETOOMANYREFS Too many references: cannot splice
108 ESHUTDOWN Cannot send after transport endpoint shutdown
107 ENOTCONN Transport endpoint is not connected
106 EISCONN Transport endpoint is already connected
105 ENOBUFS No buffer space available
104 ECONNRESET Connection reset by peer
103 ECONNABORTED Software caused connection abort
102 ENETRESET Network dropped connection on reset
101 ENETUNREACH Network is unreachable
100 ENETDOWN Network is down
99 EADDRNOTAVAIL Cannot assign requested address
98 EADDRINUSE Address already in use
97 EAFNOSUPPORT Address family not supported by protocol
96 EPFNOSUPPORT Protocol family not supported
95 EOPNOTSUPP Operation not supported
94 ESOCKTNOSUPPORT Socket type not supported
93 EPROTONOSUPPORT Protocol not supported
92 ENOPROTOOPT Protocol not available
91 EPROTOTYPE Protocol wrong type for socket
90 EMSGSIZE +Message too long
89 EDESTADDRREQ Destination address required
88 ENOTSOCK Socket operation on non-socket
87 EUSERS Too many users
86 ESTRPIPE Streams pipe error
85 ERESTART Interrupted system call should be restarted
84 EILSEQ Invalid or incomplete multibyte or wide character
83 ELIBEXEC Cannot exec a shared library directly
82 ELIBMAX Attempting to link in too many shared libraries
81 ELIBSCN .lib section in a.out corrupted
80 ELIBBAD Accessing a corrupted shared library
79 ELIBACC Can not access a needed shared library
78 EREMCHG Remote address changed
77 EBADFD File descriptor in bad state
76 ENOTUNIQ Name not unique on network
75 EOVERFLOW Value too large for defined data type
74 EBADMSG +Bad message
73 EDOTDOT RFS specific error
72 EMULTIHOP Multihop attempted
71 EPROTO Protocol error
70 ECOMM Communication error on send
69 ESRMNT Srmount error
68 EADV Advertise error
67 ENOLINK Link has been severed
66 EREMOTE Object is remote
65 ENOPKG Package not installed
64 ENONET Machine is not on the network
63 ENOSR Out of streams resources
62 ETIME Timer expired
61 ENODATA No data available
60 ENOSTR Device not a stream
59 EBFONT Bad font file format
57 EBADSLT Invalid slot
56 EBADRQC Invalid request code
55 ENOANO No anode
54 EXFULL Exchange full
53 EBADR Invalid request descriptor
52 EBADE Invalid exchange
51 EL2HLT Level 2 halted
50 ENOCSI No CSI structure available
49 EUNATCH Protocol driver not attached
48 ELNRNG Link number out of range
47 EL3RST Level 3 reset
46 EL3HLT Level 3 halted
45 EL2NSYNC Level 2 not synchronized
44 ECHRNG Channel number out of range
43 EIDRM Identifier removed
42 ENOMSG No message of desired type
40 ELOOP Too many levels of symbolic links
39 ENOTEMPTY +Directory not empty
38 ENOSYS +Function not implemented
37 ENOLCK +No locks available
36 ENAMETOOLONG +File name too long
35 EDEADLK +Resource deadlock avoided
34 ERANGE +Numerical result out of range
33 EDOM +Numerical argument out of domain
32 EPIPE +Broken pipe
31 EMLINK +Too many links
30 EROFS +Read-only file system
29 ESPIPE +Illegal seek
28 ENOSPC +No space left on device
27 EFBIG +File too large
26 ETXTBSY Text file busy
25 ENOTTY +Inappropriate ioctl for device
24 EMFILE +Too many open files
23 ENFILE +Too many open files in system
22 EINVAL +Invalid argument
21 EISDIR +Is a directory
20 ENOTDIR +Not a directory
19 ENODEV +No such device
18 EXDEV +Invalid cross-device link
17 EEXIST +File exists
16 EBUSY +Device or resource busy
15 ENOTBLK Block device required
14 EFAULT +Bad address
13 EACCES +Permission denied
12 ENOMEM +Cannot allocate memory
11 EAGAIN +Resource temporarily unavailable
10 ECHILD +No child processes
9 EBADF +Bad file descriptor
8 ENOEXEC +Exec format error
7 E2BIG +Argument list too long
6 ENXIO +No such device or address
5 EIO +Input/output error
4 EINTR +Interrupted system call
3 ESRCH +No such process
2 ENOENT +No such file or directory
1 EPERM +Operation not permitted
0 Success
100001 ERROR_PARSE_ERROR
```



## 性能测试

在virtualbox中运行的ubuntu，php 5.4.41

服务端代码：
```php
$serv = new swoole_http_server("127.0.0.1", 9502);
$serv->on('Request', function($request, $response) {
    $response->end("Hello, swoole!\n");
});

$serv->start();

```
测试代码：
```php
date_default_timezone_set('PRC');
ini_set('memory_limit','20M');

$url = "http://192.168.xx.xx:80/";

$get = 'phttp_get';

$opt = array(
	'headers' => array(
		'User-Agent'=>'mine',
	),
	'timeout' => 1,
);

function phttp_get2($url, $opt){
	$a= file_get_contents($url);
	return array('body'=>$a);
}

function phttp_get3($url, $opt){
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	$output = curl_exec($ch);
	curl_close($ch);
	return array('body'=>$output);
}

$i=0;
$a = '';
while($i++<10){
	$a = $get($url, $opt);
}
print_r($a);
```
测试结果如下：
```
//ab -n5000 -c8 -k  "http://127.0.0.1:8080/a.php"

phttp_get               711 QPS
file_get_contents       487 QPS
curl                    394 QPS

```