# BotPEASS

![](https://github.com/carlospolop/BotPEASS/raw/main/images/botpeas.png)

Use this bot to monitor new CVEs containing defined keywords and send alerts to Slack,  Telegram, and/or Discord.


## Fork Enhancements

This fork contains additional functionality not in the original project.


- Ability to configure `EXCLUDED_KEYWORDS` in the `bopteas.yaml` file, which is useful if your bot keeps spamming with CVE's from things like Source Codester open source projects. 

- Ability to filter using a `MIN_SCORE_THRESHOLD` defined in `bopteas.yaml`, which when applied, will filter out all new CVE's that are below that float type value. 

    - Config example: You will only see CVE's sent to your notifications that are of a CVSS Score 6.0 or higher.

```yaml
ENABLE_SCORE_FILTERING: True
MIN_SCORE_THRESHOLD: 6.0
```

- Ability to define a CVSS Score threshold that you ALWAYS receive notifications for if a CVE is at or above that score. This way, you have visibility over any CVE that is, say, 9.5 CVSS or higher.

In `bopteas.yaml`:
```yaml
INCLUDE_HIGH_SEVERITY: True
HIGH_SEVERITY_THRESHOLD: 9.5
```

- Integration of the MITRE Exploit-DB mapping dataset to identify if a new CVE is on the mapping for having an Exploit-DB entry. That dataset is updated every 'n' days, based on threshold defined in `bopteas.yaml`:

```yaml
MITRE_INTERVAL: 3
```

- TBD: Integration of EPSS score lookup for every new CVE. This will help to convey the exploitability of the CVE's in your notification.

- TBD: Hyperlink the CVE itself in notification to its NVD or MITRE CVE page for quick-click access to its full details

- TBD: Addition of a GitHub dork (pre-formed search URL) to quickly search for possible POC's in code on GitHub. Exclusions of common "vuln feed publishers" are excluded from results and are defined in `bopteas.yaml` like so:

```yaml
# Repo's to exclude when crafting the Github CVE search URL
GITDORK_REPO_EXCLUSIONS:
- CVEProject/cvelist
- CVEProject/cvelistV5
- EXP-Tools/threat-broadcast
```



## See it in action

Join the telegram group **[peass](https://t.me/peass)** to see the bot in action and be up to date with the latest privilege escalation vulnerabilities.

## Configure one for yourself

**Configuring your own BotPEASS** that notifies you about the new CVEs containing specific keywords is very easy!

- Fork this repo
- Modify the file `config/bopteas.yaml` to set your own keywords and preferences
- In the **github secrets** of your forked repo enter the following API keys:
    - **SLACK_WEBHOOK**: (Optional) Set the slack webhook to send messages to your slack group
    - **DISCORD_WEBHOOK_URL**: (Optional) Set the discord webhook to send messages to your discord channel
    - **TELEGRAM_BOT_TOKEN** and **TELEGRAM_CHAT_ID**: (Optional) Your Telegram bot token and the chat_id to send the messages to
- Check `.github/workflows/bopteas.yaml` and configure the cron (*once every 6 hours by default*)

*Note that the slack and telegram configurations are optional, but if you don't set any of them you won't receive any notifications*
