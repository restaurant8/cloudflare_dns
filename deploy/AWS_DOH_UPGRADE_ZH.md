# AWS EC2 DoH 白名单升级与验证

目标结构：

```text
普通公网 DNS -> Cloudflare -> 固定迷惑 IP
Clash 指定 DoH -> CloudFront -> EC2 -> 当前健康真实 IP
其他 DoH 域名 -> DNS REFUSED (Status 5)
```

公开查询入口使用标准 `/dns-query`。长随机路径只临时兼容旧客户端。
`/_admin/doh-sync` 不是公开管理接口：它要求时间戳、一次性随机数和
HMAC-SHA256 签名，管理密钥只保存在 EC2 与 `cloudflare_dns` 的加密数据库中。

## 一、准备信息

记录下面三个值：

```text
CLOUDFRONT_URL=https://dxxxxxxxxxxxx.cloudfront.net
OLD_DOH_PATH=/原来的长路径/dns-query
HMAC_SECRET=稍后生成
```

生成独立管理密钥（不要把它填写到 Clash）：

```bash
openssl rand -hex 32
```

保存输出。EC2 和 `cloudflare_dns` 后台必须填写完全相同的值。

## 二、确认 CloudFront 行为

进入 CloudFront 分配 -> `Behaviors` -> 默认行为，确认：

- Allowed HTTP methods 包含 `GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE`；
- Cache policy 为 `CachingDisabled`；
- Origin request policy 为 `AllViewerExceptHostHeader`；
- Viewer protocol policy 为 `Redirect HTTP to HTTPS` 或 `HTTPS only`。

管理同步需要 POST 及 `X-DoH-*` 请求头。当前部署若已经按上述设置，无须修改。

## 三、进入 EC2 终端

AWS 控制台进入：

```text
EC2 -> Instances -> 选中 DoH 实例 -> Connect -> Session Manager -> Connect
```

如果 Session Manager 不可用，使用现有 SSH/EC2 Instance Connect 方式进入。
本次升级必须先获得实例终端；不要重建 CloudFront 分配。

先找出当前占用 80 端口的旧 DoH 服务：

```bash
sudo ss -ltnp '( sport = :80 )'
sudo systemctl list-units --type=service | grep -Ei 'doh|dns'
```

记下旧服务名。先不要删除它，升级失败时可以重新启用回滚。

## 四、把升级文件放到 EC2

本项目需要复制下面三个文件：

```text
deploy/ec2-doh/doh_server.py
deploy/ec2-doh/private-doh.service
deploy/ec2-doh/private-doh.env.example
```

在 EC2 上建立目录：

```bash
sudo install -d -m 0755 /opt/private-doh
sudo install -d -m 0700 /var/lib/private-doh
```

通过你现有的 SCP、Session Manager 文件传输或 S3 临时文件方式，把文件复制为：

```text
/tmp/doh_server.py
/tmp/private-doh.service
/tmp/private-doh.env.example
```

然后安装：

```bash
sudo install -m 0755 /tmp/doh_server.py /opt/private-doh/doh_server.py
sudo install -m 0644 /tmp/private-doh.service /etc/systemd/system/private-doh.service
sudo install -m 0600 /tmp/private-doh.env.example /etc/private-doh.env
sudo nano /etc/private-doh.env
```

在编辑器中至少修改：

```ini
DOH_HMAC_SECRET=第一步生成的64位十六进制密钥
DOH_LEGACY_QUERY_PATHS=/原来的长路径/dns-query
```

注意：`DOH_LEGACY_QUERY_PATHS` 只填写 CloudFront 域名后面的完整路径。如果旧 URL
没有以 `/dns-query` 结尾，就按旧 URL 的实际路径填写。

## 五、切换服务

先做语法检查：

```bash
sudo /usr/bin/python3 -m py_compile /opt/private-doh/doh_server.py
```

停止旧服务。把命令中的 `<旧服务名>` 换成第三步查到的名称：

```bash
sudo systemctl disable --now <旧服务名>
```

启动新服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now private-doh
sudo systemctl status private-doh --no-pager
curl -s http://127.0.0.1/healthz
```

此时 `record_count` 为 0 是正常的：还没有从 `cloudflare_dns` 下发白名单。

如启动失败：

```bash
sudo journalctl -u private-doh -n 100 --no-pager
```

回滚方式：

```bash
sudo systemctl disable --now private-doh
sudo systemctl enable --now <旧服务名>
```

## 六、升级并配置 cloudflare_dns

部署本次项目代码后，在项目目录执行：

```bash
docker compose up -d --build
docker compose logs backend --tail 100
```

数据库会自动新增 DoH 输出字段；所有旧故障切换组保持：

```text
Cloudflare 输出 = 跟随健康源站
DoH 输出 = 关闭
```

因此升级本身不会改变现有 Cloudflare 解析。

在网页后台操作：

1. 打开 `DoH` 菜单；
2. 名称填写 `AWS Hong Kong DoH`；
3. CloudFront 地址填写 `https://dxxxxxxxxxxxx.cloudfront.net`，不要带 `/dns-query`；
4. 管理同步路径保持 `/_admin/doh-sync`；
5. 公开查询路径保持 `/dns-query`；
6. HMAC 管理密钥填写 EC2 中相同的密钥；
7. 保存后点击“立即同步”。第一次同步的空白名单也是有效配置；
8. 打开 `故障切换`，编辑 `snejsat.baidu.com` 对应组；
9. 将 Cloudflare 公网输出选择“保留现有迷惑记录，不接管”；
10. 勾选“DoH 返回真实健康源站”；
11. 选择刚创建的 DoH 服务；
12. 白名单填写 `snejsat.baidu.com`；
13. 保存并应用，先确认 DoH 已返回真实 IP；
14. 最后进入现有 Cloudflare DNS 记录页面，把公网记录改成你自己控制的迷惑 IP。

第 13 步保存后，系统不再读取、修改或删除该 Cloudflare 记录，同时 DoH 下发当前
选中的真实健康源站。此时再执行第 14 步，迷惑 IP 就不会被调度器改回。后续故障切换、
恢复回切和自动换 IP 都复用原有健康检查，只更新 DoH 真实答案。

## 七、验证标准入口和白名单

允许的域名应返回 `Status: 0` 和真实 IP：

```bash
curl -s -H 'accept: application/dns-json' \
  'https://dxxxxxxxxxxxx.cloudfront.net/dns-query?name=snejsat.baidu.com&type=A'
```

输出中应包含：

```json
{"Status":0,"Answer":[{"data":"真实IP"}]}
```

非白名单必须返回 DNS `REFUSED`。HTTP 状态仍会是 200，判断依据是 JSON 中的
`"Status":5`：

```bash
curl -s -H 'accept: application/dns-json' \
  'https://dxxxxxxxxxxxx.cloudfront.net/dns-query?name=google.com&type=A'
```

预期包含：

```json
{"Status":5}
```

同时验证公网 Cloudflare 仍返回迷惑 IP：

```bash
dig +short snejsat.baidu.com @1.1.1.1
```

## 八、更新 Clash

```yaml
dns:
  enable: true
  nameserver-policy:
    'snejsat.baidu.com':
      - https://dxxxxxxxxxxxx.cloudfront.net/dns-query
```

不要使用 Markdown 链接语法；YAML 中只能填写纯 URL。

## 九、删除旧长路径

所有客户端迁移并验证至少一天后，在 EC2 修改：

```bash
sudo nano /etc/private-doh.env
```

改为：

```ini
DOH_LEGACY_QUERY_PATHS=
```

重启并确认：

```bash
sudo systemctl restart private-doh
sudo systemctl status private-doh --no-pager
```

最终只保留标准公开查询入口 `/dns-query`；HMAC 管理密钥继续保留，不能取消。
