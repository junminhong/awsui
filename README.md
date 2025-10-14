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
  <a href="#"><img src="https://img.shields.io/badge/English-selected-blue" alt="English"></a>
  <a href="README_ZH_TW.md"><img src="https://img.shields.io/badge/繁體中文-available-lightgrey" alt="繁體中文"></a>
</p>

<h3 align="center">
  A powerful, user-friendly terminal interface for AWS Profile and SSO management.<br>
  Built with <a href="https://textual.textualize.io/">Textual</a> for a modern, responsive TUI experience.
</h3>

<p align="center">
  <strong>⚡ Fast</strong> • <strong>🔐 Secure</strong> • <strong>🤖 AI-Powered</strong> • <strong>🌍 Bilingual</strong>
</p>

## ✨ Why awsui?

- **⚡ Lightning Fast**: Search and switch between dozens of AWS profiles in milliseconds
- **🔐 SSO Made Easy**: Automatic re-authentication when credentials expire - no manual login headaches
- **🤖 AI-Powered**: Integrated Amazon Q Developer CLI for intelligent AWS assistance
- **🎯 Smart CLI**: Command autocomplete with AWS CLI cheatsheet built-in
- **🌍 Bilingual**: Full support for English and Traditional Chinese
- **📊 Clear Visibility**: See profile details, account info, and current identity at a glance
- **🎨 Modern UX**: Beautiful, keyboard-driven interface that respects your terminal theme

## 🎬 Demo

<p align="center">
  <figure>
    <img src="images/demo01.png" alt="Profile search and switching" width="800">
    <figcaption><i>⚡ Fast profile search and switching with real-time filtering</i></figcaption>
  </figure>
</p>

<p align="center">
  <figure>
    <img src="images/demo02.png" alt="AWS CLI execution" width="800">
    <figcaption><i>🎯 Smart CLI with command autocomplete and inline execution</i></figcaption>
  </figure>
</p>

<p align="center">
  <figure>
    <img src="images/demo03.png" alt="Amazon Q AI assistant" width="800">
    <figcaption><i>🤖 AI-powered Amazon Q Developer integration with streaming responses</i></figcaption>
  </figure>
</p>

<p align="center">
  <figure>
    <img src="images/demo04.png" alt="AWS CLI cheatsheet" width="800">
    <figcaption><i>📚 Built-in AWS CLI cheatsheet with quick reference for 15+ services</i></figcaption>
  </figure>
</p>

## 📋 Features

### Core Features
- **Fast Profile Search**: Filter by name, account, role, or region with real-time fuzzy matching
- **SSO Authentication**: Automatic `aws sso login` when tokens expire or on manual trigger
- **Profile Details**: View comprehensive profile information including account, role, region, and session

### AI Assistant
- **Amazon Q Integration**: Ask questions in natural language
- **Context-Aware**: Automatically includes your current profile and region
- **Streaming Responses**: Real-time output as Q processes your query
- **Command Suggestions**: Get AWS CLI commands for common tasks

### CLI Features
- **Command History**: Browse previous commands with ↑↓
- **Smart Autocomplete**: Suggestions from AWS CLI cheatsheet
- **Inline Execution**: Run AWS CLI commands directly in the TUI
- **Output Capture**: See command results with timing and exit codes
- **Built-in Cheatsheet**: Quick reference for 15+ AWS services

### Developer Experience
- **Structured Logging**: JSON logs to STDERR for debugging and monitoring
- **Cross-Platform**: Linux, macOS, Windows (PowerShell)
- **Keyboard-First**: Efficient navigation without touching the mouse
- **Extensible**: Clean Python architecture for customization

## ⚡ Quick Start

```bash
# Install with uv (recommended)
uv tool install --python 3.13 awsui

# Or install with pip
pip install awsui

# Launch the TUI
awsui
```

That's it! Start managing your AWS profiles with ease. 🚀

## 📦 Requirements

- **Python**: >= 3.13, < 3.14
- **AWS CLI**: v2 (required)
- **Amazon Q CLI**: Optional, for AI assistance ([installation guide](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html))
- **uv**: Recommended for dependency management ([installation guide](https://docs.astral.sh/uv/))

## 🚀 Installation

### Option 1: Install with uv (Recommended)

```bash
# Install as a tool (isolated environment)
uv tool install --python 3.13 awsui

# Run directly
awsui
```

### Option 2: Install with pip

```bash
pip install awsui

# Run
awsui
```

### Option 3: Development Setup

```bash
# Clone the repository
git clone https://github.com/junminhong/awsui.git
cd awsui

# Pin Python version
uv python install 3.13
uv python pin 3.13

# Install dependencies
uv sync

# Run from source
uv run awsui
```

## 📖 Usage

### Interactive Mode

Launch the TUI to select and switch profiles:

```bash
awsui
```

**Keyboard Shortcuts:**

| Category | Key | Action |
|----------|-----|--------|
| **🔍 Navigation** | `/` | Focus search box |
| | `↑` `↓` | Navigate profiles |
| | `Enter` | Apply selected profile |
| | `Esc` | Leave input field |
| **💻 CLI & Tools** | `c` | Focus CLI input |
| | `a` | Toggle AI assistant panel |
| | `h` | Show AWS CLI cheatsheet |
| | `t` | Toggle left pane (profile list) |
| **🔐 AWS** | `l` | Force SSO login for selected profile |
| | `w` | Show current AWS identity (WhoAmI) |
| **⚙️ System** | `Ctrl+L` | Clear CLI output |
| | `Ctrl+U` | Clear CLI input |
| | `?` | Show help |
| | `q` | Quit |

### Pre-select Profile

Skip interactive selection:

```bash
# Pre-select a profile when launching the TUI
awsui --profile my-prod-admin
```

### Override Region

Temporarily override AWS region:

```bash
awsui --profile my-profile --region us-west-2
```

### Language Selection

```bash
# English (default)
awsui --lang en

# Traditional Chinese
awsui --lang zh-TW
```

### Debug Mode

```bash
awsui --log-level DEBUG 2> awsui-debug.log
```

## 🤖 AI Assistant (Amazon Q Developer)

### Setup

1. Install Amazon Q Developer CLI:
   ```bash
   # Follow official installation guide
   # https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html
   ```

2. Verify installation:
   ```bash
   q --version
   ```

### Usage

1. Press `a` in awsui to open AI assistant panel
2. Type your question (e.g., "How do I list all S3 buckets with encryption enabled?")
3. Press `Enter` to submit
4. View streaming response with AWS-specific context
5. Press `a` again to close panel

The assistant automatically includes your current profile, region, and account context for more relevant answers.

## ⚙️ AWS Configuration

### SSO Session Configuration

`~/.aws/config`:

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

### Assume Role Configuration

```ini
[profile base]
region = us-east-1

[profile cross-account-admin]
source_profile = base
role_arn = arn:aws:iam::333333333333:role/AdminRole
region = us-east-1
```

### Legacy SSO (without sso-session)

```ini
[profile legacy-sso]
sso_start_url = https://my-company.awsapps.com/start
sso_region = us-east-1
sso_account_id = 444444444444
sso_role_name = ViewOnlyAccess
region = us-east-1
```

## 📁 Project Structure

```
awsui/
├── awsui/                      # Main package
│   ├── __init__.py
│   ├── app.py                  # Main Textual application
│   ├── models.py               # Profile data models
│   ├── config.py               # AWS config parsing (~/.aws/config)
│   ├── aws_cli.py              # AWS CLI wrapper (SSO, STS)
│   ├── q_assistant.py          # Amazon Q Developer CLI integration
│   ├── autocomplete.py         # Command autocomplete engine
│   ├── command_parser.py       # AWS CLI command parser
│   ├── parameter_metadata.py   # AWS parameter metadata handling
│   ├── resource_suggester.py   # AWS resource suggestion engine
│   ├── service_model_loader.py # AWS service model loader
│   ├── cheatsheet.py           # AWS CLI command reference
│   ├── i18n.py                 # Internationalization (EN/ZH-TW)
│   └── logging.py              # Structured JSON logging
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Pytest configuration
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
├── docs/                       # Documentation website
│   ├── index.html
│   ├── styles.css
│   ├── script.js
│   └── images/                 # Documentation images
├── images/                     # README images
│   ├── logo.png
│   ├── demo01.png
│   ├── demo02.png
│   ├── demo03.png
│   └── demo04.png
├── pyproject.toml              # Project configuration
├── uv.lock                     # Dependency lock file
├── LICENSE                     # MIT License
├── README.md                   # English documentation
└── README_ZH_TW.md             # Traditional Chinese documentation
```

## 🧪 Development

### Run Tests

```bash
uv run pytest
```

### Test Coverage

```bash
uv run pytest --cov=awsui --cov-report=html
open htmlcov/index.html
```

### Install Dev Dependencies

```bash
uv sync --dev
```

### Code Quality

```bash
# Linting (if configured)
uv run ruff check awsui/

# Type checking (if configured)
uv run mypy awsui/
```

## 🐛 Troubleshooting

<details>
<summary><strong>AWS CLI Not Found</strong> - <code>E_NO_AWS: AWS CLI v2 not detected</code></summary>

<br>

**Solution:** Install AWS CLI v2 following the [official guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)

Verify installation:
```bash
aws --version  # Should show "aws-cli/2.x.x ..."
```

</details>

<details>
<summary><strong>No Profiles Available</strong> - <code>E_NO_PROFILES: No profiles detected</code></summary>

<br>

**Solution:** Configure at least one profile:
```bash
# For SSO
aws configure sso-session

# For legacy SSO
aws configure sso

# For static credentials
aws configure
```

</details>

<details>
<summary><strong>SSO Login Fails</strong> - <code>E_LOGIN_FAIL: SSO login failed</code></summary>

<br>

**Possible causes:**
- Network connectivity issues
- Invalid SSO start URL
- MFA/2FA not completed
- Browser not opening (check firewall/permissions)

**Solution:**
```bash
# Try manual login first
aws sso login --profile your-profile-name

# Check browser permissions
# Ensure port 8080-8090 range is available for OAuth callback
```

</details>

<details>
<summary><strong>Identity Check Fails</strong> - <code>E_STS_FAIL: Unable to fetch identity</code></summary>

<br>

**Possible causes:**
- Credentials expired (SSO token or assume-role session)
- Invalid profile configuration
- Network/VPC issues
- Missing IAM permissions

**Solution:**
```bash
# Force re-authentication
# Press 'l' in awsui to trigger SSO login

# Verify profile configuration
cat ~/.aws/config

# Test manually
aws sts get-caller-identity --profile your-profile-name
```

</details>

<details>
<summary><strong>Amazon Q Not Available</strong> - <code>Amazon Q CLI not available</code></summary>

<br>

**Solution:** Install Amazon Q Developer CLI:
```bash
# macOS
brew install amazon-q

# Other platforms: follow official guide
# https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html
```

Verify installation:
```bash
q --version
```

</details>

## 🔒 Security

awsui follows AWS security best practices:

- ✅ **Credential Handling**: Only uses AWS CLI's credential system - no credential storage or caching
- ✅ **Temporary Credentials**: Leverages AWS STS and SSO for short-lived tokens
- ✅ **Read-Only Config**: Only reads `~/.aws/config` and `~/.aws/credentials` - never writes
- ✅ **Log Safety**: Sensitive data (tokens, secrets) automatically masked in logs
- ✅ **Environment Isolation**: Supports `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` for custom config locations
- ✅ **No Network Calls**: All AWS operations delegated to official AWS CLI
- ✅ **Subprocess Safety**: Secure subprocess execution with proper escaping

## 🎯 Performance

Target metrics:

- **Startup time**: ≤ 300ms (cold start)
- **Search response**: ≤ 50ms (keystroke to UI update)
- **Profile switch**: ≤ 5s (including SSO login if needed)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`uv run pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup

See [Development](#-development) section above.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Textual](https://textual.textualize.io/) - Modern TUI framework for Python
- [uv](https://docs.astral.sh/uv/) - Fast Python package installer and resolver
- [AWS CLI](https://aws.amazon.com/cli/) - Official AWS command-line tool
- [Amazon Q Developer](https://aws.amazon.com/q/developer/) - AI-powered assistant for AWS

## 📚 References

- [AWS CLI SSO Configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [AWS CLI Assume Role](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
- [Textual Documentation](https://textual.textualize.io/)
- [Amazon Q Developer CLI](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line.html)
- [Python 3.13 Documentation](https://docs.python.org/3.13/)

---

<h2 align="center">✨ Made with ❤️ for AWS Developers ✨</h2>

<p align="center">
  <strong>awsui</strong> - Making AWS Profile switching delightful! 🚀
</p>

<p align="center">
  If you find this tool useful, please consider giving it a ⭐ on GitHub!
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
  <a href="https://github.com/junminhong/awsui/issues">Report Bug</a>
  •
  <a href="https://github.com/junminhong/awsui/issues">Request Feature</a>
  •
  <a href="https://pypi.org/project/awsui/">PyPI Package</a>
</p>
