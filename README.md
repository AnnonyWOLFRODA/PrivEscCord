# 🛡️ PrivEscCord - Discord Security Audit Bot

**PrivEscCord** is a comprehensive Discord security audit bot designed to detect privilege escalation vulnerabilities, raid possibilities, and security misconfigurations in Discord servers.

## 🎯 Purpose

This bot helps Discord server administrators identify potential security risks by performing automated checks for:
- **Critical vulnerabilities** that could lead to server takeover or privilege escalation
- **Medium-risk issues** that could enable spam, flooding, or basic raiding
- **Permission misconfigurations** that bypass intended security measures

## 🚨 Security Levels

### 🔴 Critical Checks
Issues that could lead to complete server compromise:
- **Nuke capabilities** - Complete server destruction potential
- **Heavy raid possibilities** - Mass disruption capabilities  
- **Privilege escalation** - Escalation from @everyone/@player to @admin

### 🟡 Medium Checks
Issues that enable basic attacks:
- **Basic raiding** - Limited disruption capabilities
- **Spam/flooding** - Message or mention spam
- **Webhook abuse** - Unauthorized webhook exploitation

## 📋 Available Commands

### Critical Security Checks
- `$role_hierarchy_check` - Detects decorative roles above permission roles
- `$admin_leak_check` - Identifies unsupervised Administrator permissions
- `$dangerous_perm_check` - Scans all roles for critical permissions
- `$everyone_perm_check` - Audits @everyone permissions across all channels
- `$unprotected_webhooks` - Detects webhook abuse vulnerabilities
- `$server_settings_check` - Analyzes server security settings (2FA, verification level, content filters)

### Medium Security Checks
- `$spam_perm_check` - Identifies spam-capable roles
- `$mass_mention_check` - Analyzes mass mention capabilities
- `$webhook_overflow_check` - Counts webhooks per channel (10+ flagged)
- `$voice_damage_check` - Audits voice permission risks
- `$channel_deletion_check` - Analyzes channel management risks

### Utility Commands
- `$all_checks` - Executes all security checks at once
- `$reload_cogs` - Reloads bot modules without restart

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Discord.py 2.0+
- A Discord bot token

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/AnnonyWOLFRODA/PrivEscCord.git
   cd PrivEscCord
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   # Create .env file
   echo "TOKEN=your_bot_token_here" > .env
   ```

4. **Run the bot**
   ```bash
   python3 src/main.py
   ```

### Bot Setup

1. **Create Discord Application**
   - Go to [Discord Developer Portal](https://discord.com/developers/applications)
   - Create a new application
   - Go to "Bot" section and create a bot
   - Copy the token to your `.env` file

2. **Bot Permissions**
   Required permissions for full functionality:
   - `Administrator` (recommended for comprehensive audits)
   - Or minimum: `View Channels`, `Send Messages`, `Manage Webhooks`, `View Audit Log`

3. **Invite Bot**
   Use the OAuth2 URL generator with appropriate permissions.

## 🏗️ Project Structure

```
PrivEscCord/
├── src/
│   ├── main.py              # Main bot file
│   ├── cogs/
│   │   ├── criticals.py     # Critical security checks
│   │   └── medium.py        # Medium-level security checks
├── requirements.txt         # Python dependencies
├── .env                     # Environment variables (not in repo)
├── .gitignore              # Git ignore rules
├── README.md               # This file
├── COMMANDS_FR.md          # French command documentation
└── LICENSE                 # License file
```

## 🔧 Configuration

### Environment Variables
- `TOKEN` - Your Discord bot token (required)

### Customization
- Modify risk thresholds in cog files
- Add custom permission combinations
- Extend reporting formats

## 📊 Understanding Results

### Risk Indicators
- 🔴 **Critical** - Immediate security risk requiring urgent attention
- 🟡 **High** - Significant risk that should be addressed
- 🟢 **Low** - Normal configuration or minor concern

### Key Metrics
- **Member count** - Higher member counts increase risk severity
- **Role hierarchy** - Position in role hierarchy affects impact
- **Permission combinations** - Certain combinations create vulnerabilities

## 🛠️ Development

### Adding New Checks

1. **For Critical Checks** - Add to `src/cogs/criticals.py`
2. **For Medium Checks** - Add to `src/cogs/medium.py`

### Command Template
```python
@commands.hybrid_command(
    name="your_check_name",
    brief="Brief description",
    description="Detailed description"
)
@commands.has_permissions(administrator=True)
async def your_check(self, ctx):
    # Your security check logic here
    pass
```

### Testing
- Test commands in a controlled Discord server
- Verify permission checks work correctly
- Ensure proper error handling

## ⚠️ Important Notes

### Security Considerations
- **Administrator access required** - All commands require admin permissions
- **Read-only operations** - Bot only analyzes, never modifies permissions
- **Audit logging** - Consider enabling audit logs for transparency

### Limitations
- **Context matters** - Some flagged configurations may be intentional
- **False positives** - Manual review of results recommended
- **Permission scope** - Bot can only analyze what it has access to

### Best Practices
- Run audits regularly (weekly/monthly)
- Review results in context of server purpose
- Document any intentional security configurations
- Backup server settings before making changes

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- **Issues** - Open an issue on GitHub
- **Discussions** - Use GitHub Discussions for questions
- **Security** - Report security issues privately

## 🏆 Acknowledgments

- Discord.py community for excellent documentation
- Security researchers for Discord permission research
- Beta testers for feedback and bug reports

---

The bot on 
[![Discord Bots](https://top.gg/api/widget/1400810869683785850.svg)(https://top.gg//bot/1400810869683785850)

**⚠️ Disclaimer**: This bot is for legitimate security auditing purposes only. Ensure you have proper authorization before scanning Discord servers. The developers are not responsible for misuse of this tool.

*Made with 🛡️ for Discord security*