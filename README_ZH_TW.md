# awsui

<p align="center">
  <img src="docs/images/logo01.png" alt="awsui logo" width="400">
</p>

<p align="center">
  <a href="https://pypi.org/project/awsui/"><img src="https://img.shields.io/pypi/v/awsui?color=blue" alt="PyPI version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT license"></a>
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/English-available-lightgrey" alt="English"></a>
  <a href="#"><img src="https://img.shields.io/badge/繁體中文-selected-blue" alt="繁體中文"></a>
</p>

<p align="center">
  <a href="https://junminhong.github.io/awsui/">Website</a>
</p>

<h3 align="center">
  不必再替 AI 工具記住 AWS profile。<br>
  選擇環境，驗證帳號，再讓 Claude Code、Codex、Kiro、Terraform 或任何 CLI 在正確的 AWS context 中啟動。
</h3>

開發時，你通常想的是 `dev`、`staging` 或 `prod`，而不是
`company-payment-production-admin` 這類只在本機有意義的 profile 名稱。awsui
把專案環境對應到本機 AWS profile，確認目前登入的 account 正確後，才啟動你的工具。

![awsui CLI 工作流程總覽](docs/images/awsui-cli-promo-16x9.gif)

_從初始化專案、綁定 profile，到驗證 account 並啟動工具。_

## awsui 解決什麼問題？

你只要指定環境，其餘的 context 檢查交給 awsui：

- 以 `prod` 這類專案環境名稱操作，不必記住每台電腦不同的 profile 名稱。
- 啟動工具前，透過 AWS STS 取得並顯示目前實際登入的 account。
- AI agent、Terraform、AWS CLI、script 和 shell 都能使用相同的已驗證 context。
- 團隊只需共用各環境預期的 account 與 region；profile binding 留在本機。
- 登入失敗或 account 不符時，立即停止流程，不啟動目標指令。

> [!IMPORTANT]
> awsui 驗證的是工具啟動當下的 AWS context，並不是隔離執行環境的 security
> sandbox。工具啟動後，child process 仍可自行改寫環境變數，或明確指定其他
> profile。

## 快速上手

依序完成下面四個步驟，即可建立專案 context、驗證 AWS identity，並在正確的
context 中啟動工具。

### 開始之前

請先準備 Python 3.13、[AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)，
以及一個已透過 AWS CLI 設定完成的 AWS profile。認證方式建議優先使用 IAM
Identity Center（SSO）。

### 1. 安裝 awsui

建議使用 [uv](https://docs.astral.sh/uv/) 以隔離環境安裝：

```bash
uv tool install --python 3.13 awsui
```

也可以使用 pip 安裝到目前的 Python 環境：

```bash
pip install awsui
```

確認安裝結果：

```bash
awsui --version
```

若能看到版本號，表示安裝完成。

CLI 預設顯示英文。執行以下指令切換為繁體中文；awsui 會記住這項設定：

```bash
awsui --lang zh-TW
```

使用 `awsui --lang en` 可切回英文。`--lang` 也能和其他指令一起使用，例如
`awsui --lang zh-TW context prod`。語言偏好會寫入
`~/.config/awsui/settings.json`，該檔案不含 AWS credentials。若設定檔格式無效，
再次明確指定 `--lang` 即可重建設定。

### 2. 初始化專案 context

進入專案目錄並啟動設定流程：

```bash
cd payment-service
awsui init
```

awsui 會引導你命名專案、加入環境、選擇或建立本機 profile，並逐一驗證 AWS
identity。完成後會顯示類似以下的摘要：

```text
已建立 /path/to/payment-service/.awsui.yaml
專案: payment-service
  dev: 111111111111 · ap-northeast-1
  prod: 999999999999 · ap-northeast-1 · 受保護環境
```

awsui 會把團隊共用的 environment、account 與 region 寫入 `.awsui.yaml`；本機
profile binding 則保存在 repository 外，不會和其他人共用。

![初始化 awsui 專案 contexts](docs/images/awsui-init-16x9.gif)

_在 terminal 中建立團隊共用的專案 contexts。_

### 3. 啟動工具前先驗證環境

啟動工具前，先確認 `prod` 實際對應到哪個 AWS identity：

```bash
awsui context prod
```

輸出會列出預期與實際驗證到的 account：

```text
payment-service · PROD · 受保護環境
預期帳號: 999999999999
已驗證帳號: 999999999999
區域: ap-northeast-1
本機 Profile: company-payment-prod
狀態: ✓ 已驗證
```

確認「預期帳號」與「已驗證帳號」一致。看到「已驗證」表示 context 可用，但這個
指令只會顯示結果，不會啟動其他 process。

![使用 awsui 驗證 AWS context](docs/images/awsui-context-16x9.gif)

_啟動工具前，確認目前登入的是正確的 AWS account。_

### 4. 啟動你的工具

確認 context 後，即可啟動需要的工具：

```bash
awsui prod -- codex
awsui prod -- claude
awsui prod -- terraform plan
```

awsui 會在啟動前再次驗證 identity，並顯示即將交給 child process 的 context：

```text
payment-service · PROD · 受保護環境
帳號: 999999999999 ✓
區域: ap-northeast-1
正在啟動：codex
```

如果實際 account 與專案設定不符，awsui 會顯示 `AWS CONTEXT 不符` 與
`指令尚未啟動。`，並停止執行。

![在已驗證的 AWS context 中啟動 Codex](docs/images/awsui-run-shorthand-16x9.gif)

_只有在 context 驗證成功後，awsui 才會啟動 Codex。_

執行 `awsui --help` 可查看所有指令。若要開啟使用已驗證 context 的互動式 shell，
直接執行 `awsui dev`。

其他開發者取得 repository 後，只需把共用的 `prod` 環境綁定到自己的本機
profile：

```bash
awsui bind prod
awsui prod -- claude
```

![將本機 AWS profile 綁定到專案環境](docs/images/awsui-bind-16x9.gif)

_每位開發者都能將共用的環境名稱綁定到自己的本機 profile。_

## 團隊共用與本機保留的設定

將每個環境預期的 account 與 region 寫入 `.awsui.yaml`，並把這個檔案提交到
repository：

```yaml
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: ap-northeast-1
  qa:
    account: "222222222222"
    region: ap-northeast-1
  staging:
    account: "333333333333"
    region: ap-northeast-1
  prod:
    account: "999999999999"
    region: ap-northeast-1
    protected: true
```

所有開發者會使用相同的環境名稱與 account 驗證規則，但不需要共用 profile
名稱。各台電腦的 binding 會存放在 repository 外的
`~/.config/awsui/bindings.json`。`.awsui.yaml` 不得包含 credentials。

## 指令參考

以下是常用的 CLI 指令：

| 指令 | 用途 |
| --- | --- |
| `awsui` | 顯示 CLI 說明 |
| `awsui --lang <zh-TW\|en>` | 設定並記住 CLI 語言 |
| `awsui init` | 初始化專案 contexts |
| `awsui bind <environment>` | 將環境綁定到本機 AWS profile |
| `awsui bind ls` | 列出環境與本機 binding 狀態，不連線至 AWS |
| `awsui bind ls --json` | 以 JSON 輸出本機 binding 清單 |
| `awsui context ls` | 列出 contexts 與本機 binding 狀態，不連線至 AWS |
| `awsui context ls --json` | 以 JSON 輸出 context 清單 |
| `awsui context <environment>` | 登入、驗證並顯示 context |
| `awsui context <environment> --json` | 以 JSON 輸出已驗證的 context |
| `awsui <environment> -- <command> [args...]` | 驗證後執行指定指令 |
| `awsui <environment>` | 開啟已驗證的互動 shell |
| `awsui doctor` | 診斷本機設定，不觸發登入 |

`awsui context ls`／`list` 與 `awsui bind ls`／`list` 只讀取本機設定，不會呼叫
AWS。它們會列出各 context 的預期 account、region、受保護狀態與本機 profile。
需要透過 STS 驗證特定 context 時，再執行 `awsui context <environment>`。

也可以使用完整語法：

```bash
awsui run prod -- codex
awsui shell prod
```

`--` 後方的內容會直接以 argument vector 啟動，不會經過 shell 解析。若需要
pipe、redirect、`&&` 或其他 shell 組合語法，請先用 `awsui <environment>`
開啟已驗證的 shell，再執行組合指令。

## 還沒有需要的 AWS profile？

初始化或綁定環境時，若找不到需要的 profile，可選擇**建立新的 AWS Profile**。
建議優先使用 IAM Identity Center（SSO）。awsui 會呼叫官方的
`aws configure sso`、`aws login` 或 `aws configure` 流程；建立完成後，會回到
原本的操作並選取新 profile。

你也可以先自行設定並驗證 SSO profile：

```bash
aws configure sso
aws sso login --profile my-company-dev
aws sts get-caller-identity --profile my-company-dev
```

互動流程也支援 AWS Console Login 與 Access key 設定，但長期 Access key 並非
建議選項。awsui 使用 AWS CLI 管理的 credentials，本身不會保存 AWS
credentials。

## awsui 如何驗證啟動 context？

每次啟動工具前，awsui 都會執行以下流程：

1. 解析專案環境及其本機 profile binding。
2. 必要時登入所選的 profile。
3. 呼叫 STS `GetCallerIdentity`。
4. 比對實際 account 與預期的 12 位數 AWS account ID。
5. 建立已移除 credential overrides 的 child environment。
6. 確認 account 相符後才啟動 child process。

Account 不符或無法驗證 identity 時，awsui 都會停止執行。團隊共用的專案設定不會
包含 Access key、Secret key、Session token 或本機 profile 名稱。

## 需要協助或想參與貢獻？

若你發現 bug、遇到問題或有功能建議，歡迎建立
[GitHub Issue](https://github.com/junminhong/awsui/issues)。也歡迎直接提交 pull
request。

設定本機開發環境：

```bash
git clone https://github.com/junminhong/awsui.git
cd awsui
uv sync
```

提交 pull request 前，請執行：

```bash
uv run ruff check .
uv run pytest
uv build
```

## 授權

[MIT](LICENSE)
