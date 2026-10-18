[使用说明.md](https://github.com/user-attachments/files/33624276/default.md)
# GhostTrack GUI v4 · 使用说明

> OSINT 工具套件 —— GhostTrack + Seeker 图形界面
> 仅用于**合法授权**的安全测试与学习研究；未经同意收集他人位置或号码信息在多数地区违法。

## 一、启动

| 方式 | 操作 |
|------|------|
| **一键启动（推荐）** | 双击 `启动GhostTrackGUI.bat` |
| 命令行 | `python GhostTrackGUI.py` |

首次运行前确保已安装 Python 依赖：

```powershell
pip install requests phonenumbers psutil packaging pillow
```

> Seeker 功能另需 **PHP**（已随环境安装）。若缺失，Seeker 页会提示，其余功能不受影响。

## 二、功能一览（11 个标签页）

| 标签页 | 功能 | 数据源 |
|--------|------|--------|
| 🌍 IP | IP/域名 27 项查询 + 地图定位 | ipwho.is（在线） |
| 📞 号码 | 号码归属分析 | phonenumbers + **双库融合**（见下） |
| 🔍 用户名 | 24 个平台并发同名检测 | 各站点可达性（在线） |
| ✉ 邮箱 | 格式/提供商/一次性邮箱/MX/Gravatar | 本地库 + dns.google |
| 🏷 域名 | DNS 记录 / RDAP 注册信息 / crt.sh 子域名枚举 | dns.google / rdap.org / crt.sh |
| 🌐 Web | HTTP 头/重定向链/标题/TLS 证书/技术栈 | 被动请求目标站点 |
| ⚡ 批量 | 最多 200 个 IP 并发查询 + CSV 导出 | ipwho.is |
| 🛠 工具 | 端口检测 / 本机网络 / Ping / 路由追踪 / PTR / 哈希识别 | 本地 + ICMP |
| 🎯 Seeker | 8 种模板服务启停 + 日志 + 捕获结果查看 | 本地 PHP 服务 |
| 🕘 历史 | 全部查询自动持久化，双击回填重查，支持过滤 | 本地 JSON |
| ℹ 关于 | 环境信息 / 数据源状态 | — |

## 三、国内号码查询（双库融合）

| 库 | 条数 | 数据日期 | 作用 |
|----|------|---------|------|
| **XEngine_PhoneData**（主库） | 517,259 | 2025-08 | 覆盖最全，含 144/192 等新号段，格式支持携号转网 |
| **ls0f/phone**（补充） | 499,527 | 2023-12 | 独家提供邮政编码 |

查询结果包含：归属省份/城市/长途区号/邮编/双库运营商对照/携号转网记录/数据源标注。
虚拟运营商、广电、卫星、物联网号段会自动高亮提示。

## 四、Seeker 使用

1. 选择模板（NearYou / WhatsApp / Google Drive / Telegram / Zoom 等 8 种）
2. 填写模板参数（图片可点「浏览」选择本地文件）
3. 本机测试勾选「本地调试」→ 点「▶ 启动」
4. 局域网内其他设备访问 `http://你的IP:端口/index.html`；公网需端口转发或内网穿透
5. 采集结果自动保存到 `seeker/db/results.csv`，GUI 内嵌表格自动刷新

## 五、快捷键

- `Ctrl+1` ~ `Ctrl+9`：快速切换前 9 个标签页
- `Ctrl+Q`：退出
- 所有结果表：**右键** = 复制/导出 CSV/打开链接；**双击**历史条目 = 回填重查

## 六、目录结构

```
C:\deepseekharnessWORKPLACE\
├── GhostTrackGUI.py            # 主程序（单文件）
├── 启动GhostTrackGUI.bat        # 一键启动
├── 使用说明.md                  # 本文档
├── .ghosttrack_gui.json        # 窗口位置记忆（自动生成）
├── .ghosttrack_history.json    # 查询历史（自动生成）
├── GhostTrack/                 # 原版 CLI 工具
├── seeker/                     # Seeker（含 Windows 兼容修复）
└── phonedata/                  # 国内号码库（两份 .dat）
```

## 七、数据源与致谢

- [HunxByts/GhostTrack](https://github.com/HunxByts/GhostTrack)
- [thewhiteh4t/seeker](https://github.com/thewhiteh4t/seeker)
- [ls0f/phone](https://github.com/ls0f/phone)（MIT）
- [libxengine/XEngine_PhoneData](https://github.com/libxengine/XEngine_PhoneData)
- ipwho.is / dns.google / rdap.org / crt.sh 等公开被动数据源

## 八、免责声明

本工具所有查询均为**被动公开数据**（在线 API）或**本地离线数据库**，不包含任何入侵、漏洞利用或实时定位能力。使用者须自行确保符合适用法律法规。
