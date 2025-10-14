# awsui
<p align="center">
    <picture>
      <img src="images/logo.png" alt="awsui logo" width="400">
    </picture>
    <br>
</p>

<p align="center">
  <a href="https://pypi.org/project/awsui/"><img src="https://img.shields.io/pypi/v/awsui?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/awsui/"><img src="https://img.shields.io/pypi/status/awsui" alt="PyPI status"></a>
  <a href="https://pypi.org/project/awsui/"><img src="https://img.shields.io/pypi/pyversions/awsui" alt="Python versions"></a>
  <a href="https://pypi.org/project/awsui/"><img src="https://img.shields.io/pypi/dw/awsui" alt="Downloads"></a>
  <br>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://textual.textualize.io/"><img src="https://img.shields.io/badge/TUI-Textual-cyan.svg" alt="Textual"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/English-available-lightgrey" alt="English"></a>
  <a href="#"><img src="https://img.shields.io/badge/繁體中文-selected-blue" alt="繁體中文"></a>
</p>

<h3 align="center">
  強大且易用的 AWS Profile 與 SSO 管理終端介面工具。<br>
  使用 <a href="https://textual.textualize.io/">Textual</a> 打造現代化、高回應性的 TUI 體驗。
</h3>

<p align="center">
  <strong>⚡ 快速</strong> • <strong>🔐 安全</strong> • <strong>🤖 AI 驅動</strong> • <strong>🌍 雙語</strong>
</p>

## ✨ 為什麼選擇 awsui?
- **⚡ 極速快捷**：在數十個 AWS profiles 間毫秒級搜尋與切換
- **🔐 SSO 超簡單**：認證過期時自動重新登入 - 告別手動登入的煩惱
- **🤖 AI 加持**：整合 Amazon Q Developer CLI，提供智慧型 AWS 協助
- **🎯 聰明的 CLI**：內建 AWS CLI cheatsheet 的指令自動完成
- **🌍 雙語支援**：完整支援英文與繁體中文
- **📊 一目了然**：清楚顯示 profile 詳情、帳號資訊與當前身份
- **🎨 現代化介面**：美觀、鍵盤導向的介面，尊重您的終端主題

## 🎬 展示

<p align="center">
  <figure>
    <img src="images/demo01.png" alt="Profile 搜尋與切換" width="800">
    <figcaption><i>⚡ 快速的 profile 搜尋與切換，即時過濾</i></figcaption>
  </figure>
</p>

<p align="center">
  <figure>
    <img src="images/demo02.png" alt="AWS CLI 執行" width="800">
    <figcaption><i>🎯 智慧 CLI，具備指令自動完成與內嵌執行</i></figcaption>
  </figure>
</p>

<p align="center">
  <figure>
    <img src="images/demo03.png" alt="Amazon Q AI 助手" width="800">
    <figcaption><i>🤖 AI 驅動的 Amazon Q Developer 整合，支援串流回應</i></figcaption>
  </figure>
</p>

<p align="center">
  <figure>
    <img src="images/demo04.png" alt="AWS CLI cheatsheet" width="800">
    <figcaption><i>📚 內建 AWS CLI cheatsheet，15+ 項服務的快速參考</i></figcaption>
  </figure>
</p>

## 📋 功能特色

### 核心功能
- **快速 Profile 搜尋**：依名稱、帳號、角色或區域即時模糊搜尋過濾
- **SSO 認證**：認證過期時自動執行 `aws sso login` 或手動觸發
- **Profile 詳情**：檢視完整的 profile 資訊，包括帳號、角色、區域與 session

### AI 助手
- **Amazon Q 整合**：使用自然語言提問
- **情境感知**：自動包含您當前的 profile 與區域
- **串流回應**：Q 處理查詢時的即時輸出
- **指令建議**：取得常見任務的 AWS CLI 指令

### CLI 功能
- **指令歷史**：使用 ↑↓ 瀏覽先前的指令
- **智慧自動完成**：從 AWS CLI cheatsheet 取得建議
- **內嵌執行**：直接在 TUI 中執行 AWS CLI 指令
- **輸出擷取**：查看指令結果，包含執行時間與結束代碼
- **內建 Cheatsheet**：15+ 個 AWS 服務的快速參考

### 開發者體驗
- **結構化日誌**：輸出 JSON 格式日誌至 STDERR 便於除錯與監控
- **跨平台**：Linux、macOS、Windows (PowerShell)
- **鍵盤優先**：高效率的導航，無需使用滑鼠
- **可擴展**：乾淨的 Python 架構便於客製化

## ⚡ 快速開始

```bash
# 使用 uv 安裝（建議）
uv tool install --python 3.13 awsui

# 或使用 pip 安裝
pip install awsui

# 啟動 TUI
awsui
```

就這麼簡單！開始輕鬆管理您的 AWS profiles。🚀

## 📦 需求

- **Python**: >= 3.13, < 3.14
- **AWS CLI**: v2 (必要)
- **Amazon Q CLI**: 選用，用於 AI 協助 ([安裝指南](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html))
- **uv**: 建議用於相依性管理 ([安裝指南](https://docs.astral.sh/uv/))

## 🚀 安裝

### 方案 1：使用 uv 安裝（建議）

```bash
# 安裝為工具（隔離環境）
uv tool install --python 3.13 awsui

# 直接執行
awsui
```

### 方案 2：使用 pip 安裝

```bash
pip install awsui

# 執行
awsui
```

### 方案 3：開發環境設定

```bash
# Clone repository
git clone https://github.com/junminhong/awsui.git
cd awsui

# 固定 Python 版本
uv python install 3.13
uv python pin 3.13

# 安裝相依性
uv sync

# 從原始碼執行
uv run awsui
```

## 📖 使用方式

### 互動模式

啟動 TUI 來選擇與切換 profiles：

```bash
awsui
```

**鍵盤快捷鍵：**

| 分類 | 按鍵 | 功能 |
|----------|-----|--------|
| **🔍 導覽** | `/` | 聚焦搜尋框 |
| | `↑` `↓` | 導覽 profiles |
| | `Enter` | 套用選定的 profile |
| | `Esc` | 離開輸入欄位 |
| **💻 CLI 與工具** | `c` | 聚焦 CLI 輸入 |
| | `a` | 切換 AI 助手面板 |
| | `h` | 顯示 AWS CLI cheatsheet |
| | `t` | 切換左側面板（profile 列表） |
| **🔐 AWS** | `l` | 強制為選定的 profile 執行 SSO 登入 |
| | `w` | 顯示當前 AWS 身份 (WhoAmI) |
| **⚙️ 系統** | `Ctrl+L` | 清空 CLI 輸出 |
| | `Ctrl+U` | 清空 CLI 輸入 |
| | `?` | 顯示說明 |
| | `q` | 離開程式 |

### 預先選擇 Profile

略過互動式選擇：

```bash
# 啟動 TUI 前預選特定 profile
awsui --profile my-prod-admin
```

### 覆寫區域

暫時覆寫 AWS 區域：

```bash
awsui --profile my-profile --region us-west-2
```

### 語言選擇

```bash
# 英文（預設）
awsui --lang en

# 繁體中文
awsui --lang zh-TW
```

### 除錯模式

```bash
awsui --log-level DEBUG 2> awsui-debug.log
```

## 🤖 AI 助手（Amazon Q Developer）

### 設定

1. 安裝 Amazon Q Developer CLI：
   ```bash
   # 依循官方安裝指南
   # https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html
   ```

2. 驗證安裝：
   ```bash
   q --version
   ```

### 使用方式

1. 在 awsui 中按 `a` 開啟 AI 助手面板
2. 輸入您的問題（例如：「如何列出所有啟用加密的 S3 buckets？」）
3. 按 `Enter` 送出
4. 查看帶有 AWS 特定情境的串流回應
5. 再按一次 `a` 關閉面板

助手會自動包含您當前的 profile、區域與帳號情境，以提供更相關的答案。

## ⚙️ AWS 設定

### SSO Session 設定

`~/.aws/config`：

```ini
[sso-session my-company]
sso_start_url = https://my-company.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile production-admin]
sso_session = my-company
sso_account_id = 111111111111
sso_role_name = AdministratorAccess
region = us-east-1
output = json

[profile staging-developer]
sso_session = my-company
sso_account_id = 222222222222
sso_role_name = DeveloperAccess
region = us-west-2
output = json
```

### Assume Role 設定

```ini
[profile base]
region = us-east-1

[profile cross-account-admin]
source_profile = base
role_arn = arn:aws:iam::333333333333:role/AdminRole
region = us-east-1
```

### 傳統 SSO（沒有 sso-session）

```ini
[profile legacy-sso]
sso_start_url = https://my-company.awsapps.com/start
sso_region = us-east-1
sso_account_id = 444444444444
sso_role_name = ViewOnlyAccess
region = us-east-1
```

## 📁 專案結構

```
awsui/
├── awsui/                      # 主套件
│   ├── __init__.py
│   ├── app.py                  # 主要 Textual 應用程式
│   ├── models.py               # Profile 資料模型
│   ├── config.py               # AWS config 解析 (~/.aws/config)
│   ├── aws_cli.py              # AWS CLI 包裝器 (SSO, STS)
│   ├── q_assistant.py          # Amazon Q Developer CLI 整合
│   ├── autocomplete.py         # 指令自動完成引擎
│   ├── command_parser.py       # AWS CLI 指令解析器
│   ├── parameter_metadata.py   # AWS 參數 metadata 處理
│   ├── resource_suggester.py   # AWS 資源建議引擎
│   ├── service_model_loader.py # AWS 服務模型載入器
│   ├── cheatsheet.py           # AWS CLI 指令參考
│   ├── i18n.py                 # 國際化 (EN/ZH-TW)
│   └── logging.py              # 結構化 JSON 日誌
├── tests/                      # 測試套件
│   ├── __init__.py
│   ├── conftest.py             # Pytest 設定
│   ├── test_app.py
│   ├── test_autocomplete.py
│   ├── test_aws_cli.py
│   ├── test_cheatsheet.py
│   ├── test_command_parser.py
│   ├── test_config.py
│   ├── test_global_parameters.py
│   ├── test_i18n.py
│   ├── test_logging.py
│   ├── test_models.py
│   ├── test_q_assistant.py
│   ├── test_resource_suggester.py
│   ├── test_service_model_loader.py
│   ├── test_special_commands.py
│   └── test_special_commands_no_autocomplete.py
├── docs/                       # 文件網站
│   ├── index.html
│   ├── styles.css
│   ├── script.js
│   └── images/                 # 文件圖片
├── images/                     # README 圖片
│   ├── logo.png
│   ├── demo01.png
│   ├── demo02.png
│   ├── demo03.png
│   └── demo04.png
├── pyproject.toml              # 專案設定
├── uv.lock                     # 相依性鎖定檔案
├── LICENSE                     # MIT 授權
├── README.md                   # 英文文件
└── README_ZH_TW.md             # 繁體中文文件
```

## 🧪 開發

### 執行測試

```bash
uv run pytest
```

### 測試覆蓋率

```bash
uv run pytest --cov=awsui --cov-report=html
open htmlcov/index.html
```

### 安裝開發相依性

```bash
uv sync --dev
```

### 程式碼品質

```bash
# Linting（如已設定）
uv run ruff check awsui/

# Type checking（如已設定）
uv run mypy awsui/
```

## 🐛 疑難排解

<details>
<summary><strong>找不到 AWS CLI</strong> - <code>E_NO_AWS: AWS CLI v2 not detected</code></summary>

<br>

**解決方案：** 依循[官方指南](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)安裝 AWS CLI v2

驗證安裝：
```bash
aws --version  # 應顯示 "aws-cli/2.x.x ..."
```

</details>

<details>
<summary><strong>沒有可用的 Profiles</strong> - <code>E_NO_PROFILES: No profiles detected</code></summary>

<br>

**解決方案：** 至少設定一個 profile：
```bash
# 用於 SSO
aws configure sso-session

# 用於傳統 SSO
aws configure sso

# 用於靜態憑證
aws configure
```

</details>

<details>
<summary><strong>SSO 登入失敗</strong> - <code>E_LOGIN_FAIL: SSO login failed</code></summary>

<br>

**可能原因：**
- 網路連線問題
- 無效的 SSO start URL
- MFA/2FA 未完成
- 瀏覽器未開啟（檢查防火牆/權限）

**解決方案：**
```bash
# 先嘗試手動登入
aws sso login --profile your-profile-name

# 檢查瀏覽器權限
# 確保 port 8080-8090 範圍可用於 OAuth callback
```

</details>

<details>
<summary><strong>身份檢查失敗</strong> - <code>E_STS_FAIL: Unable to fetch identity</code></summary>

<br>

**可能原因：**
- 憑證過期（SSO token 或 assume-role session）
- 無效的 profile 設定
- 網路/VPC 問題
- 缺少 IAM 權限

**解決方案：**
```bash
# 強制重新認證
# 在 awsui 中按 'l' 觸發 SSO 登入

# 驗證 profile 設定
cat ~/.aws/config

# 手動測試
aws sts get-caller-identity --profile your-profile-name
```

</details>

<details>
<summary><strong>Amazon Q 不可用</strong> - <code>Amazon Q CLI not available</code></summary>

<br>

**解決方案：** 安裝 Amazon Q Developer CLI：
```bash
# macOS
brew install amazon-q

# 其他平台：依循官方指南
# https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html
```

驗證安裝：
```bash
q --version
```

</details>

## 🔒 安全性

awsui 遵循 AWS 安全最佳實踐：

- ✅ **憑證處理**：僅使用 AWS CLI 的憑證系統 - 不儲存或快取憑證
- ✅ **臨時憑證**：利用 AWS STS 與 SSO 取得短期 token
- ✅ **唯讀設定**：僅讀取 `~/.aws/config` 和 `~/.aws/credentials` - 從不寫入
- ✅ **日誌安全**：敏感資料（tokens、secrets）在日誌中自動遮罩
- ✅ **環境隔離**：支援 `AWS_CONFIG_FILE` 和 `AWS_SHARED_CREDENTIALS_FILE` 用於自訂設定位置
- ✅ **無網路呼叫**：所有 AWS 操作委派給官方 AWS CLI
- ✅ **子程序安全**：使用適當的跳脫進行安全的子程序執行

## 🎯 效能

目標指標：

- **啟動時間**：≤ 300ms（冷啟動）
- **搜尋回應**：≤ 50ms（按鍵到 UI 更新）
- **Profile 切換**：≤ 5s（包含 SSO 登入，如需要）

## 🤝 貢獻

歡迎貢獻！請隨時提交 issues、功能請求或 pull requests。

### 貢獻指南

1. Fork 此 repository
2. 建立功能分支（`git checkout -b feature/amazing-feature`）
3. 進行您的變更
4. 為新功能加入測試
5. 確保所有測試通過（`uv run pytest`）
6. Commit 您的變更（`git commit -m 'Add amazing feature'`）
7. Push 到分支（`git push origin feature/amazing-feature`）
8. 開啟 Pull Request

### 開發環境設定

參見上方[開發](#-開發)章節。

## 📄 授權

此專案使用 MIT License 授權 - 詳見 [LICENSE](LICENSE) 檔案。

## 🙏 致謝

- [Textual](https://textual.textualize.io/) - Python 現代化 TUI 框架
- [uv](https://docs.astral.sh/uv/) - 快速的 Python 套件安裝器與解析器
- [AWS CLI](https://aws.amazon.com/cli/) - 官方 AWS 命令列工具
- [Amazon Q Developer](https://aws.amazon.com/q/developer/) - AWS AI 助手

## 📚 參考資料

- [AWS CLI SSO Configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [AWS CLI Assume Role](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
- [Textual Documentation](https://textual.textualize.io/)
- [Amazon Q Developer CLI](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line.html)
- [Python 3.13 Documentation](https://docs.python.org/3.13/)

---

<h2 align="center">✨ 用 ❤️ 為 AWS 開發者打造 ✨</h2>

<p align="center">
  <strong>awsui</strong> - 讓 AWS Profile 切換變得愉快！🚀
</p>

<p align="center">
  如果您覺得此工具有用，請考慮在 GitHub 上給它一個 ⭐！
</p>

<p align="center">
  <a href="https://github.com/junminhong/awsui/stargazers">
    <img src="https://img.shields.io/github/stars/junminhong/awsui?style=social" alt="GitHub stars">
  </a>
  <a href="https://github.com/junminhong/awsui/fork">
    <img src="https://img.shields.io/github/forks/junminhong/awsui?style=social" alt="GitHub forks">
  </a>
</p>

<p align="center">
  <a href="https://github.com/junminhong/awsui/issues">回報問題</a>
  •
  <a href="https://github.com/junminhong/awsui/issues">功能請求</a>
  •
  <a href="https://pypi.org/project/awsui/">PyPI 套件</a>
</p>
