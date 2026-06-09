# azpanel / Xboard 自动换 IP 闭环

本项目负责判断源站是否疑似被墙，并在满足条件时调用 azpanel 更换云机器公网 IP。

Xboard 不需要改代码：如果 Xboard 后端已经会上报自己的公网 IP，并且 Xboard 面板已经会根据上报 IP 自动同步 Cloudflare 解析，那么换 IP 成功后等待后端重新上报即可形成闭环。

## 调用流程

```text
DNS 故障切换项目
  -> 当前正在使用的源站被判定 blocked
  -> 查找绑定的 azpanel 资源
  -> POST azpanel /api/internal/cloudflare-dns/change-ip
  -> azpanel 更换公网 IP
  -> 返回 new_ip
  -> 本项目更新绑定源站/IP 记录
  -> Xboard 后端恢复上报新公网 IP
  -> Xboard 自动同步节点 DNS
```

## 本项目里的配置

1. 打开「自动换 IP」
2. 配置 azpanel 地址和内部 API Token
3. 添加云资源：
   - `provider`: `azure` / `aws` / `linode`
   - `resource_id`: Azure 填 `vm_id`，AWS 填 `instance_id`
   - `account_id`: AWS 需要；Azure 可按 azpanel 内部实现决定
   - `region`: AWS 需要
   - 绑定对应的故障源站
4. 打开「Xboard 节点」
5. 绑定 Xboard 节点 ID 和 azpanel 云资源

Xboard 菜单默认不主动调用 Xboard API，只用于记录绑定关系和提供“一键更换节点 IP”的按钮。

## azpanel 需要提供的内部 API

本项目会调用：

```http
POST /api/internal/cloudflare-dns/change-ip
Authorization: Bearer <token>
Content-Type: application/json
```

请求体：

```json
{
  "provider": "azure",
  "resource_id": "vm-id-or-instance-id",
  "account_id": "optional-account-id",
  "region": "optional-region",
  "ip_version": "ipv4",
  "current_ip": "192.0.2.10",
  "port": 22,
  "reason": "www.example.com current origin is blocked",
  "source": "cloudflare_dns"
}
```

成功响应必须包含 `new_ip`：

```json
{
  "status": "success",
  "old_ip": "192.0.2.10",
  "new_ip": "198.51.100.20",
  "message": "changed"
}
```

失败响应建议：

```json
{
  "status": "failed",
  "message": "quota exceeded"
}
```

## 安全建议

- 这个内部 API 不要暴露给所有人，至少使用强随机 Token。
- 建议只允许本项目服务器 IP 访问 azpanel 的这个接口。
- azpanel Token 与本项目里的 Cloudflare Token 一样，会加密保存。
- 自动换 IP 有冷却时间，默认 1800 秒，避免误判后连续更换。

