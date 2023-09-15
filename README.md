# BotPEASS

![](https://github.com/carlospolop/BotPEASS/raw/main/images/botpeas.png)

Use this bot to monitor new CVEs containing defined keywords and send alerts to Slack,  Telegram, and/or Discord.


## Fork Enhancements to BotPEASS

This fork contains additional functionality not in the original project. During buildout of this, code was moved outside of the original single-file bot, and so to leave that original in place, primary script run in this fork is *cvebot.py* instead of the original botpeas.py.

```bash
python cvebot.py
```

1. First, and foremost, this bot leverages *NIST NVD* to retrieve new CVE's instead of the cve.circl.lu used by the original project. The goal for doing this was to move closer towards an industry standard CVE data source. Now, the good news is that you don't need to worry about setting an API key, because each run of the bot only makes 1 request to NVD to get CVE's. Just don't blitz-fire run the bot over and over or you will exceed their required threshold of 6 seconds between requests without an API key. Even during testing of code changes, I've not seen any issues.

2. Ability to configure `EXCLUDED_KEYWORDS` in the `botpeas.yaml` file to reduce noise and have better fidelity over the amount of new CVE's sent to your notifications. For example, this is useful if your bot keeps spamming with CVE's from things like Source Codester open source projects. *NOTE:* This exclusion is case-sensitive, so include exact case spelling of keywords you want filtered out if they are found in the `Description` field of CVE's.

3. Ability to filter out CVE's using a `MIN_SCORE_THRESHOLD` defined in `botpeas.yaml`, which when applied, will filter out all new CVE's that are below that float type value. 

    - Config example: You will only see CVE's sent to your notifications that are of a CVSS Score 6.0 or higher.

```yaml
ENABLE_SCORE_FILTERING: True
MIN_SCORE_THRESHOLD: 6.0
```

4. Opposite of above where we *filter out* CVE's, also added in the ability to define a CVSS Score threshold (e.g. CVSS 9.5) that you ALWAYS receive notifications for if a CVE is at or above that score. This way, you have visibility over any CVE with what you consider a high CVSS score, such as 9.5 or higher in the example configuration below in `botpeas.yaml`:

    - *NOTE:* Out of caution, enabling this will also include CVE's with NO SCORE yet, so we don't miss something that is very new and not yet vetted for a score.

```yaml
INCLUDE_HIGH_SEVERITY: True
HIGH_SEVERITY_THRESHOLD: 9.5
```

5. Integration of the MITRE Exploit-DB mapping dataset to identify if a new CVE is on the mapping for having an Exploit-DB entry. That dataset is updated every 'n' days, based on threshold defined in `botpeas.yaml`:

    - *NOTE:* This may not really be useful for new CVE's, but it never hurts to include an Exploit-DB POC.

```yaml
# Retrive a new MITRE dataset every 'n' days configured in this setting
MITRE_INTERVAL: 3
```

6. Integration of EPSS score lookup for every new CVE. This can help to convey the exploitability of each CVE and quickly identify from your messages when one stands out as being unusually popular or exploitable.

7. Hyperlinked the CVE itself in the notification message to its <https://www.cvedetails.com/|CVE Details> page for quick-click access to its full details.

8. Addition of a GitHub dork (pre-formed search URL) to quickly search for possible POC's in code on GitHub related to the CVE. It also eliminates noise in GitHub search results by using defined exclusions of common "vuln feed publisher" repositories, which are excluded from results. You can define those _noisy_ repo's to exclude in `botpeas.yaml` like so:

```yaml
# Repo's to exclude when crafting the Github CVE search URL
GITDORK_REPO_EXCLUSIONS:
- CVEProject/cvelist
- CVEProject/cvelistV5
- EXP-Tools/threat-broadcast
```

That's it for the features for now, but always looking for ways to expand capabilities!



## See it in action

Join the telegram group **[peass](https://t.me/peass)** to see the bot in action and be up to date with the latest privilege escalation vulnerabilities.

## Configure one for yourself

**Configuring your own BotPEASS** that notifies you about the new CVEs containing specific keywords is very easy!

- Fork this repo
- Modify the file `config/botpeas.yaml` to set your own keywords and preferences
- In the **github secrets** of your forked repo enter the following API keys:
    - **SLACK_WEBHOOK**: (Optional) Set the slack webhook to send messages to your slack group
    - **DISCORD_WEBHOOK_URL**: (Optional) Set the discord webhook to send messages to your discord channel
    - **TELEGRAM_BOT_TOKEN** and **TELEGRAM_CHAT_ID**: (Optional) Your Telegram bot token and the chat_id to send the messages to
- Check `.github/workflows/botpeas.yaml` and configure the cron (*once every 6 hours by default*)

*Note that the slack and telegram configurations are optional, but if you don't set any of them you won't receive any notifications*
