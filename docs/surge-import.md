# 在 Surge 中导入 MUI 订阅节点

MUI 的 Surge 格式返回 `[Proxy]` 节点列表。它供代理组引用，不是完整的 Surge 配置；把它通过“从 URL 安装配置”导入会提示“规则必须以 FINAL 结尾”。

## 导入到现有配置

1. 在 MUI 的订阅列表点击 Surge 订阅的“查看链接”，复制“Surge 代理组配置”。
2. 在 Surge 中打开当前正常使用的配置进行文本编辑。
3. 找到已有的 `[Proxy Group]` 段，把复制的一行加入该段；已有该段时不要重复创建段标题。
4. 保存并重新加载配置，MUI 代理组会从订阅拉取节点。
5. 将 `MUI` 加入现有规则使用的代理组，再从 MUI 组中选择节点。仅增加代理组不会改变现有规则选择的策略。

示例（将 URL 换成面板复制的实际订阅链接）：

```ini
[Proxy Group]
MUI = select, policy-path=https://mui.example.com/s/YOUR_TOKEN, update-interval=3600
```

`update-interval` 单位为秒，此处每小时更新。原配置的 `[Rule]` 和 `FINAL` 继续使用，不需要为了导入节点而改写分流规则。若已有名为 `MUI` 的代理组，请更换组名并在引用处使用相同名称。

Surge 支持通过 `policy-path` 从外部文件的 `[Proxy]` 段读取节点，详见[官方说明](https://manual.nssurge.com/policy-groups/policy-including.html)。

## 只导入一次

也可以在订阅预览中复制 `[Proxy]` 段里的节点行，粘贴到现有配置的 `[Proxy]` 段。该方式不自动更新；后续节点变化需要重新复制。

订阅链接和节点行包含访问凭据，请妥善保管。
