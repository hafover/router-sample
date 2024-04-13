---

---

# router-sample

dns router

### 配置格式

```
port: 7893
log-level: debug
hosts:
  +.test.com: 192.168.1.23

dns:
  listen: :53
  nameserver:
    DEFAULT: [223.5.5.5, 119.29.29.29]
    doh: [https://doh.pub/dns-query, https://dns.alidns.com/dns-query]
  rule:
    - [+.google.com, doh]

proxy:
  - { name: a, type: a, server: a, port: 111}

policy:
  - { name: aaa, type: select, ns: FAKE-IP, proxy: [a] }
  - { name: bbb, type: select, ns: doh, proxy: [a] }

rule:
  - [DEFAULT, DIRECT]
  - [DOMAIN, +.github.com, bbb]
  - [DOMAIN, +.meta.com, aaa]
```

### dns路由规则

1 匹配rule，获取policy名称

2 如果policy是REJECT返回ip获取失败

3 如果policy是DIRECT，执行dns rule获取nameserver组名

4 其他情况使用policy.ns作为nameserver组名，组名为空时执行dns rule获取nameserver组名

5 nameserver组名为FAKE-IP返回虚拟ip 198.18.0.0/24

6 nameserver组名不存在时使用DEFAULT组
