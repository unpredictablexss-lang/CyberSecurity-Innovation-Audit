# Windows 浏览器可达性补验

2026-10-22：用户报告 WSL 终端 `Uvicorn running on http://127.0.0.1:8765`，Windows Edge `localhost:8765` 返回 ERR_CONNECTION_REFUSED。

## 原因与原验收边界

Ubuntu 内部 `/api/v1/health` 返回 status=ok、worker_running=true；Windows curl 访问 localhost 和 127.0.0.1:8765 都失败。`netsh interface ipv4/ipv6 show excludedportrange protocol=tcp` 显示系统保留 **8709–8808**，包含 8765；Windows TcpListener 绑定报 SocketException/AccessDenied。没有删除该范围、重启整个 WSL 或修改系统网络配置。

原 Windows 自测从 CMD 进入 WSL 后，所有 HTTP 请求仍在 WSL 内执行；其 passed 证明内部部署/扫描，不证明 Windows 宿主机可达。此补验纠正该边界，保留原始结果与日志，不将旧结果改写为宿主机通过。

## 最终行为

- 手册、Windows/Linux 一键部署、一键启动及核心服务均保持默认 **8765**；不自动选择其他端口。系统保留/占用时 Windows 启动前明确报错，避免 WSL 启动后让用户访问一个不可达地址。
- 若自行选择其他端口，需显式 `-Port` / `--port`；复验的 18872 和启动测试端口只用于本机排查，不是交付默认值。
- Windows 自测同时要求正式扫描/报告成功及宿主机健康接口、首页、app.js 可访问。不可达就失败，不仅检查 WSL 内部。
- 正常运行时宿主机可达检查成功后自动打开浏览器。新增 `start-windows.cmd` / `start-linux.sh`，只复用已有 venv/dist 启动，不重新安装、npm ci 或构建。首次仍使用 deploy 入口。

## 复验

1. 本机 Windows 默认 8765：预检明确失败；没有换端口或错误宣称成功。
2. Windows 显式 `-Port 18872 -SmokeTest`：宿主机健康/首页/静态资源通过；内部 Worker 完成固定 Git 合成样例扫描、生成 1 条候选和报告，服务退出 0，最终 `Windows host self-test passed`。
3. 宿主机负向检查：未监听的 65534，超时写 status=failed，退出非零。
4. Linux `bash start-linux.sh` 不传端口：实际启动 8765，Linux 内健康接口/Worker 通过，日志不包含安装或构建阶段。
5. Windows 一键启动的显式端口与新版源码包复验结果见同目录补验日志及 JSON。

当前机器的 Windows 8765 仍由系统保留，不能宣称 Windows 默认 8765 已访问成功；需要由系统释放该端口后再用默认入口。脚本不删除系统保留项。Linux 默认端口成功和 Windows 显式测试端口成功分别记录。
