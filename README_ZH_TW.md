# awsui

<p align="center">
  <img src="images/logo.png" alt="awsui logo" width="400">
</p>

<p align="center">
  <a href="https://pypi.org/project/awsui/"><img src="https://img.shields.io/pypi/v/awsui?color=blue" alt="PyPI version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT license"></a>
  <a href="https://textual.textualize.io/"><img src="https://img.shields.io/badge/TUI-Textual-cyan.svg" alt="Textual"></a>
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/English-available-lightgrey" alt="English"></a>
  <a href="#"><img src="https://img.shields.io/badge/繁體中文-selected-blue" alt="繁體中文"></a>
</p>

<p align="center">
  <a href="https://junminhong.github.io/awsui/">Website</a>
</p>

<h3 align="center">
  不要再告訴你的 AI 該用哪個 AWS profile。<br>
  讓 Claude Code、Codex、Kiro、Terraform 與任何 CLI 在正確且已驗證的 AWS context 中執行。
</h3>

你思考的是 `dev` 或 `prod`，AWS 工具要求的卻可能是
`company-payment-production-admin` 這種 profile 名稱。awsui 會連結兩者、驗證
真實的 AWS account，確認無誤後才把控制權交給你的工具。

![awsui Context Dashboard](docs/images/demo01.png)

## awsui 幫你處理什麼？

你只要選擇環境，awsui 會處理環境背後的 context：

- 你輸入的是 `prod`，不是只有這台電腦才知道的 profile 名稱。
- 工具啟動前，你會先看到 STS 回傳的真實 account。
- 你的 AI agent、Terraform、AWS CLI、script 與 shell 都使用同一個 context。
- 團隊共用 account 與 region 意圖，不需要共用本機 profile 名稱。
- 登入失敗或 account 不符時，你的指令絕對不會啟動。

> [!IMPORTANT]
> awsui 提供的是已驗證的 AWS 啟動 context，不是 security sandbox。
> Child process 仍能刻意覆蓋繼承到的環境，或明確指定其他 profile。

## 跟著跑一次 awsui

完成下面四個步驟後，你會擁有專案 context、已驗證的 AWS identity，以及一個
在該 context 中執行的工具。

### 開始之前

你需要 Python 3.13、[AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)，
以及已透過 AWS CLI 設定的 AWS profile。建議使用 IAM Identity Center（SSO）
進行認證。

### 1. 安裝 awsui

使用 [uv](https://docs.astral.sh/uv/) 將它安裝成隔離工具：

```bash
uv tool install --python 3.13 awsui
```

偏好 pip？也可以安裝到目前的 Python 環境：

```bash
pip install awsui
```

接著確認指令已經可以使用：

```bash
awsui --version
```

看到 awsui 印出目前安裝的版本後，就可以開始設定專案。

### 2. 設定你的專案 contexts

進入專案並啟動引導式設定：

```bash
cd payment-service
awsui init
```

awsui 會請你命名專案、加入環境、選擇或建立本機 profile，並驗證每個 identity。
設定完成後，你會看到類似下面的摘要：

```text
Created /path/to/payment-service/.awsui.yaml
Project: payment-service
  dev: 111111111111 · ap-northeast-1
  prod: 999999999999 · ap-northeast-1 · PROTECTED
```

**剛剛發生了什麼？** awsui 將團隊共用的 account 與 region 意圖寫入
`.awsui.yaml`，但這台機器專屬的 profile binding 仍然放在 repository 外。

### 3. 啟動工具前先驗證環境

在啟動任何工具前，先請 awsui 顯示 `prod` 背後的真實 identity：

```bash
awsui context prod
```

純文字輸出會列出你真正需要確認的資訊：

```text
payment-service · PROD · PROTECTED
Expected account: 999999999999
Authenticated account: 999999999999
Region: ap-northeast-1
Local profile: company-payment-prod
Status: ✓ VERIFIED
```

請確認 expected 與 authenticated account 相同。`VERIFIED` 代表 context 已準備好，
這一步還不會啟動任何 child process。

### 4. 啟動你的工具

現在可以帶上任何你想使用的工具：

```bash
awsui prod -- codex
awsui prod -- claude
awsui prod -- terraform plan
```

啟動前一刻，awsui 會再次驗證 identity，並顯示即將交給 process 的 context：

```text
payment-service · PROD · PROTECTED
Account: 999999999999 ✓
Region: ap-northeast-1
Launching: codex
```

如果登入的 account 不正確，你會看到 `AWS CONTEXT MISMATCH` 與
`Command was not started.`，工具不會拿到錯誤的 context。

這樣就完成了。想使用視覺化的 Context Dashboard 時執行 `awsui`；想開啟已驗證
的互動 shell 時，直接執行 `awsui dev`。

要讓另一位開發者加入？他只需沿用已提交的專案意圖，再將 `prod` 綁定到自己的
本機 profile：

```bash
awsui bind prod
awsui prod -- claude
```

## 團隊要共用什麼？

團隊先決定每個環境預期的 account 與 region，再將這份共用意圖提交為
`.awsui.yaml`：

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

你的隊友會拿到相同的環境名稱與 account guardrails，但不需要知道你的 profile
名稱。awsui 會將每台機器的 private bindings 存放在 repository 外的
`~/.config/awsui/bindings.json`；`.awsui.yaml` 絕對不能包含 credentials。

## 偏好視覺化操作？

在你的專案內執行 `awsui`，就能在不呼叫 AWS 的情況下檢視所有環境，再用鍵盤
完成驗證或啟動。Launch 與 Shell 都會在 child process 啟動前再次驗證身份。

找不到專案時，**初始化**會開啟全畫面的設定 wizard。你可以命名專案、加入環境、
選擇或建立本機 profile、透過 STS 驗證每個身份，並在寫入設定前確認結果。

| 按鍵 | 動作 |
| --- | --- |
| `↑` / `↓` | 選擇環境 |
| `Enter` / `v` | 登入並透過 STS 驗證 |
| `b` | 綁定本機 profile |
| `l` | 啟動 AI agent、CLI 或自訂指令 |
| `s` | 開啟已驗證的 context shell |
| `d` | 執行本機診斷 |
| `r` | 重新載入專案與 profile 狀態 |
| `i` | 找不到專案時進行初始化 |
| `?` | 顯示說明 |
| `q` | 離開 |

Dashboard 會區分 `UNBOUND`、`PROFILE MISSING`、`READY TO VERIFY`、
`VERIFYING`、`VERIFIED`、`MISMATCH` 與 `ERROR`。受保護環境會醒目顯示，
且仍需要明確執行 launch 動作。

## 偏好直接輸入指令？

你也可以完全透過 command line 操作：

| 指令 | 用途 |
| --- | --- |
| `awsui` | 開啟 Context Dashboard |
| `awsui init` | 初始化專案的已驗證 contexts |
| `awsui bind <environment>` | 將環境綁定到本機 AWS profile |
| `awsui context <environment>` | 登入、驗證並顯示 context |
| `awsui context <environment> --json` | 以 JSON 輸出已驗證的 context |
| `awsui <environment> -- <command> [args...]` | 驗證後執行 child command |
| `awsui <environment>` | 開啟已驗證的互動 shell |
| `awsui doctor` | 不觸發登入，診斷本機設定 |

完整命令形式仍然可用：

```bash
awsui run prod -- codex
awsui shell prod
```

Dashboard 的自訂指令欄只接受 command 與 arguments，不接受 shell 語法。
Pipe、redirect、`&&` 等 operator 會被拒絕；需要組合 shell 指令時，請開啟
已驗證的 shell。

## 還沒有需要的 AWS profile？

初始化或綁定時，如果需要的 profile 不存在，可以選擇**建立 Profile**。
建議優先使用 IAM Identity Center（SSO）。awsui 會將 profile 建立工作交給官方
`aws configure sso`、`aws login` 或 `aws configure` 指令，完成後再回到
原本的流程並選取新的 profile。

也可以在開啟 awsui 前自行設定 SSO：

```bash
aws configure sso
aws sso login --profile my-company-dev
aws sts get-caller-identity --profile my-company-dev
```

互動流程也提供 AWS Console Login 與 access key 設定；access key 會標示為
不建議。awsui 使用 AWS CLI 管理的 credentials，本身不會保存 AWS credentials。

## 每次啟動前發生什麼事？

以下是 awsui 啟動你的 process 前一定會做的事：

1. 解析專案環境與本機 profile binding。
2. 必要時登入指定 profile。
3. 呼叫 STS `GetCallerIdentity`。
4. 比對實際與預期的 12 位數 AWS account ID。
5. 建立經過清理的 child environment。
6. 僅在 account 相符時啟動 process。

Account 不符與無法驗證身份都會阻擋執行。共用專案設定絕不包含 access key、
secret key、session token 或本機 profile 名稱。

## 需要協助或想參與貢獻？

發現 bug、有問題，或想提出功能建議？歡迎建立
[GitHub Issue](https://github.com/junminhong/awsui/issues)。如果你想直接完成修改，
也歡迎提交 pull request。

建立開發環境：

```bash
git clone https://github.com/junminhong/awsui.git
cd awsui
uv sync
```

提交 pull request 前請執行：

```bash
uv run ruff check .
uv run pytest
uv build
```

## 授權

[MIT](LICENSE)
