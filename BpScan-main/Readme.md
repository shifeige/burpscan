

## 简介

BpScan:  一款用于辅助渗透测试工程师日常渗透测试的Burp被动漏扫插件，开发灵感来源于开源项目(https://github.com/EASY233/BpScan)。

##  插件功能

目前BpScan暂时只支持扫描以下漏洞:

- SpringSpiderScan，支持扫描Spring Actuator组件未授权访问，Swagger API 泄露，Druid Monitor 未授权访问，支持路径逐层扫描探测，支持自动Bypass路径(使用Bypass字符..;)。

- Log4jScan,对所有请求参数以及指定的header头进行Log4j Rce漏洞探测。
- FastJsonScan，对POST内容为JSON或者POST参数为JSON处进行FastJson Rce漏洞探测。
- HadoopScan，支持扫描Hadoop组件未授权访问



## 注意事项

1、默认使用jdk1.8编译，若出现jdk问题插件不可用，请下载源码自行编译。

2、有时候流量过大插件扫描会比较慢，请耐心等待插件扫描结束。

3、 目前代码可能还很不成熟，后续更新较快，平时可以多关注一下项目的更新情况。

## 感谢列表

在开发过程中参考学习了非常多前辈们的优秀开源项目，特此感谢!

https://github.com/EASY233/BpScan


