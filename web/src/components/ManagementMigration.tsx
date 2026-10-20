export default function ManagementMigration({ command, onCopy }: { command?: string; onCopy: (value: string) => void }) {
  if (!command) return null;
  return <section className="installStep managementMigration">
    <h3>切换管理方式：先停用旧服务</h3>
    <p className="hint">先下载所需文件，再在目标机以 root 执行下方准备命令，最后执行安装命令。准备命令会停止旧服务、备份旧模式配置并保留固定发布公钥，不修改防火墙。转发会中断，完成安装后恢复；仅在面板保存不会切换目标机上的服务。</p>
    <pre className="installCommand">{command}</pre>
    <button type="button" className="ghost" onClick={() => onCopy(command)}>复制迁移准备命令</button>
  </section>;
}
