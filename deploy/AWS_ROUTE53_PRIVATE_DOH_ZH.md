# AWS Route 53 私有 DoH：首次配置、接入与排障

本文对应控制台的「AWS 私有 DoH」面板。目标是让私有 DoH 返回 Route 53 私有托管区中、由本项目健康检查和故障切换选出的当前健康 IP。

## 1. 最终链路

```text
故障切换组健康检查与优先级选择
  → Route 53 私有托管区 A/AAAA 记录
  → VPC Resolver 169.254.169.253
  → EC2 PrivateDoH 2.0
  → CloudFront /dns-query
  → Clash 或其他 DoH 客户端
```

Route 53 是真实 IP 的唯一数据源。EC2 不再保存真实 IP，只保存允许查询的域名；命中白名单后，EC2 把请求转发给 VPC Resolver。Cloudflare 公网权威记录仍可保留迷惑值，不受私有托管区影响。

## 2. 两种 DoH 模式不要混用

| 菜单 | 数据来源 | 是否操作 Route 53 | EC2 快照 |
| --- | --- | --- | --- |
| DoH 故障切换 | 独立候选目标 | 否 | `version: 1`，保存真实 IP |
| AWS 私有 DoH | 通用故障切换组 + Route 53 私有区 | 是 | `version: 2`，保存 `source: "vpc_resolver"` 白名单标记 |

同一个查询域名不要同时配置到这两个菜单。若 EC2 的 `records.json` 中仍出现 `doh_failover_group_id` 和真实 IP，说明该域名仍在使用旧的静态模式。

## 3. 添加前检查

- 已有一台运行 PrivateDoH 的 EC2，并知道它所在的 VPC ID 和区域。
- 私有托管区由准备使用的 AWS 账号拥有，并关联上述 VPC。
- 已在控制台配置并启用 DoH/CloudFront 服务。
- 健康检查使用目标真实开放的 TCP 端口，例如 HTTPS 服务填写 `443`；不要用无关的 `1.1.1.1:22` 测试。
- 控制端已配置 `APP_ENCRYPTION_KEY`，用于加密保存 AWS 密钥。

## 4. 确认 EC2、VPC 和私有托管区

先查 DoH EC2 的 VPC：

```bash
aws ec2 describe-instances \
  --region <EC2_REGION> \
  --filters "Name=private-ip-address,Values=<EC2_PRIVATE_IP>" \
  --query 'Reservations[].Instances[].{InstanceId:InstanceId,VpcId:VpcId,SubnetId:SubnetId,PrivateIp:PrivateIpAddress,State:State.Name}' \
  --output table
```

再查该 VPC 已关联的私有托管区：

```bash
aws route53 list-hosted-zones-by-vpc \
  --vpc-id <VPC_ID> \
  --vpc-region <EC2_REGION> \
  --query 'HostedZoneSummaries[].{Name:Name,ZoneId:HostedZoneId,OwnerAccount:Owner.OwningAccount}' \
  --output table
```

若列表为空，先创建私有托管区。面板不会自动创建托管区：

```bash
aws route53 create-hosted-zone \
  --name <QUERY_DOMAIN> \
  --vpc VPCRegion=<EC2_REGION>,VPCId=<VPC_ID> \
  --hosted-zone-config Comment="Private DoH",PrivateZone=true \
  --caller-reference "private-doh-$(date +%s)"
```

Route 53 托管区是全局资源，控制台右上角区域不会筛选它。若控制台显示 0 个托管区，重点检查当前登录账号是否是托管区所有者，而不是切换控制台区域。

## 5. 创建最小权限 IAM 用户和 Access Key

不要使用 root Access Key，也不要复用 GitHub Actions、SES SMTP 等已有用户。

### 5.1 创建客户托管策略

进入 AWS 控制台：`IAM → 策略 → 创建策略 → JSON`，粘贴以下内容，并把 `ZPRIVATE_ZONE_ID` 替换为真实私有托管区 ID：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["route53:ListHostedZones"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["route53:GetHostedZone"],
      "Resource": "arn:aws:route53:::hostedzone/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": "arn:aws:route53:::hostedzone/ZPRIVATE_ZONE_ID"
    }
  ]
}
```

面板为列出每个私有区关联的 VPC，需要读取所有托管区的基本信息；写入权限仍严格限制在指定私有托管区。策略名称可使用 `cloudflare-dns-route53`。

### 5.2 创建专用 IAM 用户

1. 进入 `IAM → IAM 用户 → 创建用户`。
2. 用户名填写 `cloudflare-dns-route53`。
3. 不启用 AWS 管理控制台访问权限。
4. 创建后进入该用户的「权限」，附加上一步的 `cloudflare-dns-route53` 策略。

### 5.3 创建 Access Key

1. 打开该 IAM 用户的「安全凭证」。
2. 在「访问密钥」中点击「创建访问密钥」。
3. 使用案例选择「在 AWS 之外运行的应用程序」。
4. 描述标签可填写 `cloudflare-dns-route53`。
5. 完成后立即把 Access Key ID 和 Secret Access Key 填入本项目面板。

Secret Access Key 只显示一次。不要截图、不要发到聊天、不要写入本文档或 Git 仓库；遗失时应停用旧 Key 并创建新 Key。

## 6. 升级 EC2 PrivateDoH

必须先升级 EC2，再创建 AWS 输出。`version: 2` 快照会让旧服务端拒绝白名单占位符，避免错误地把 `0.0.0.0` 当作答案。

将 `deploy/ec2-doh/doh_server.py` 上传并覆盖 systemd `ExecStart` 使用的脚本。标准位置为：

```text
/opt/private-doh/doh_server.py
```

在 `/etc/private-doh.env` 中确认：

```bash
DOH_VPC_RESOLVER=169.254.169.253
DOH_VPC_RESOLVER_TIMEOUT_SECONDS=5
```

然后执行：

```bash
sudo python3 -m py_compile /opt/private-doh/doh_server.py
sudo systemctl restart private-doh
sudo systemctl status private-doh --no-pager
```

通过 CloudFront 查询一次，响应头应包含 `Server: PrivateDoH/2.0`：

```powershell
curl.exe -i -H "accept: application/dns-json" "https://<CLOUDFRONT_DOMAIN>/dns-query?name=<QUERY_DOMAIN>&type=A"
```

## 7. 在「AWS 私有 DoH」面板接入

### 步骤 1：添加 AWS 凭证

填写专用 IAM 用户的 Access Key ID、Secret Access Key 和 SDK 区域，点击「保存并验证托管区读取」。保存成功后，在凭证列表点击「加载托管区」。

若列表为空，请检查：

- 凭证所属账号是否拥有该私有托管区；
- 策略是否包含 `ListHostedZones` 和 `GetHostedZone`；
- 托管区是否关联 DoH EC2 所在 VPC。

### 步骤 2：建立故障切换组

若查询域名还没有故障切换组，可直接在此面板创建主目标。随后进入「故障切换」菜单：

1. 添加备用 IP 或域名；
2. 为每个目标配置真实业务端口、优先级和探针；
3. 点击「立即检查」；
4. 确认组已显示当前健康源站。

没有当前健康源站时，Route 53 不会出现 A/AAAA 记录。这是保护行为，不是控制台延迟。

### 步骤 3：绑定 AWS 输出

依次选择：

1. 已有故障切换组；
2. AWS 凭证；
3. 与 DoH EC2 VPC 关联的私有托管区；
4. 已启用的 DoH/CloudFront 服务；
5. DoH 查询域名和 TTL。

绑定前控制端会先只读查询该域名现有的 `A`、`AAAA` 和 `CNAME` 记录：

- 默认不接管。只要目标名称已经存在上述任一记录，接口就返回 `409 Conflict`，原记录保持不变；
- 确认这些记录确实可以被本项目替换后，才勾选「我确认接管并替换……」并重新提交；
- 接管会把该名称现有的简单记录、Alias 记录以及加权、延迟、故障转移、地理位置等路由策略记录替换为本项目管理的简单记录；
- 由 Route 53 Traffic Policy Instance 管理的记录不能在这里接管。必须先在 AWS 中删除或解除对应 Traffic Policy Instance，再重新绑定；
- 若控制端无权读取现有记录或 AWS 查询失败，绑定会返回 `502`，不会在无法确认线上状态时盲目写入。

因此，不要把生产中的 ELB Alias、蓝绿加权记录或其他业务路由域名直接勾选接管。建议给私有 DoH 使用独立的查询名称；确需复用时，先记录并备份当前 RRset 配置。

点击「添加 AWS 输出」后，控制端会：

- 把当前健康 IP `UPSERT` 到 Route 53 私有区；
- 把该查询域名以 VPC Resolver 白名单形式同步给 EC2；
- 后续按照健康状态、优先级、回切冷却和分时规则自动更新 Route 53；
- 定期对账并修复 Route 53 漂移。

## 8. 发布后验证

### 8.1 Route 53 记录

```bash
aws route53 list-resource-record-sets \
  --hosted-zone-id <HOSTED_ZONE_ID> \
  --query "ResourceRecordSets[?Name=='<QUERY_DOMAIN>.']"
```

### 8.2 在 DoH EC2 内查询 VPC Resolver

```bash
dig @169.254.169.253 <QUERY_DOMAIN> A +noall +answer
```

应返回当前健康 IP。若 `status: NOERROR` 但 `ANSWER: 0`，表示私有区存在但该名称当前没有 A 记录。

### 8.3 查询 CloudFront DoH

```powershell
curl.exe -i -H "accept: application/dns-json" "https://<CLOUDFRONT_DOMAIN>/dns-query?name=<QUERY_DOMAIN>&type=A"
```

返回结果应与 Route 53 和 VPC Resolver 一致。`X-Cache: Miss from cloudfront` 与 `cache-control: no-store` 表示该响应不是 CloudFront 长时间缓存造成的旧值。

### 8.4 检查 EC2 快照

```bash
sudo cat /var/lib/private-doh/records.json
```

正确的 AWS 私有 DoH 条目类似：

```json
{
  "version": 2,
  "records": [
    {
      "name": "service.example.internal",
      "type": "A",
      "value": "0.0.0.0",
      "source": "vpc_resolver"
    }
  ]
}
```

`0.0.0.0` 只是白名单占位符，不会返回给客户端；真实结果由 VPC Resolver 提供。

## 9. 常见问题

### 创建输出后 AWS 控制台没有记录

首先看故障切换组是否有「当前健康源站」。没有健康源站时不会发布。其次确认选择的是正确托管区 ID、AWS 凭证没有 `AccessDenied`，再点击输出的「立即检查」查看错误。

### 删除 Route 53 记录很久后 DoH 仍返回旧 IP

若 `records.json` 是 `version: 1` 且包含真实 IP，返回值来自旧「DoH 故障切换」静态快照，而不是 Route 53。删除同名静态规则、升级到 PrivateDoH 2.0，并重新同步 AWS 输出。若快照已经是 `version: 2/source: vpc_resolver`，再依次比较 Route 53、VPC Resolver 和 DoH 三处结果。

### `dig` 显示 `NOERROR` 但没有 ANSWER

这通常表示私有托管区已匹配，但查询名称没有 A 记录。检查健康源站、输出最近错误以及 Route 53 记录集，不需要等待 30 分钟。

### 面板加载不到私有托管区

面板只列出凭证所属账号拥有的私有托管区。用同一身份执行 `aws sts get-caller-identity` 和 `aws route53 list-hosted-zones`，并确认策略允许读取区信息。

### DoH 返回 `REFUSED` / `Status: 5`

查询名称不在 EC2 白名单中。确认 AWS 输出已启用、同步成功，并检查 `records.json` 是否存在对应 `source: "vpc_resolver"` 条目。

## 10. 删除与回滚

- 从本项目删除 AWS 输出只会停止管理，不会自动删除 AWS 当前记录。
- 临时停用输出不会依赖 AWS 可用性，也不会删除现有记录。
- 需要彻底下线时，先停用客户端流量，再删除 Route 53 记录、删除输出、撤销 Access Key。
- 轮换密钥时先创建并验证新 Key，再停用旧 Key；确认无误后删除旧 Key。
