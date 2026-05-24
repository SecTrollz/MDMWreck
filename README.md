This one's for you, Aaron Miller of the Colorado Department Of Early Childhood Development. (;

# Evan's MDM Toolkit 

## What is this?

A command-line tool to **detect**, **block**, **unblock**, and **audit** Android device management agents (MDM, stealth admins, etc.), even if they are hidden or concealed. It also allows sending formal notices to management servers using their own communication channels.

## Who is this for?

- Device owners who want to check for hidden management or stealth admins.
- Users comfortable with command-line interfaces.
- Power users and testers performing security audits.
- Not recommended for casual or inexperienced users.

## What does it do?

- **Detects** active or hidden management agents, device owner info, stealthy packages, URLs, and configurations.
- **Blocks** communication to known management servers/domains via NextDNS denylist.
- **Removes** domains from denylist.
- **Sends** formal legal notices directly into management consoles via protocols like OMA-DM, Apple MDM, Knox, or generic HTTP. 
- **Provides** setup instructions for configuring NextDNS on your device.
- **Performs** deep detection using privileged commands (`rish`) via Shizuku for full device info.
- **Hardens** your profile by disabling logs and enabling privacy features. **(NOT RECCOMENEDED IF PURSUEING LEGAL ACCOUNTABILITY)**

---

## Requirements

- Android 8.0+ (preferably 9+)
- Termux app installed
- Python 3.8+ installed in Termux
- A NextDNS account (free at nextdns.io)
- **RECOMMENDED:** Shizuku app + `rish` shell for advanced detection

---

## Setup Instructions

### 1. Install Termux

- Download from F-Droid: [https://f-droid.org/F-Droid.apk](https://f-droid.org/F-Droid.apk)
- Open Termux.

### 2. Install Python

```bash
pkg update && pkg upgrade
pkg install python
```

### 3. Install dependencies

```bash
pip install requests
```

### 4. Download the script

- Save `evanrocks.py` from your source.
- Copy it into Termux:

```bash
cp /sdcard/Download/evanrocks.py ~/evanrocks.py
```
or

```bash
git clone https://github.com/SecTrollz/MDMWreck.git
cd MDMWreck
```


### 5. Run the tool

```bash
python3 evanrocks.py
```

Follow the on-screen prompts to:

- Enter your NextDNS Profile ID and API Key.
- Choose actions: detect, block, unblock, send notices, view setup instructions, or exit.

---

## Advanced Detection (Optional)

To perform deep detection of hidden or stealth admins:

1. Install **Shizuku** from Play Store.
2. Start Shizuku with Wireless Debugging enabled.
3. Install **Termux** (via F-Droid).
4. Download and set up `rish` shell:

```bash
# In Termux
mkdir -p ~/shizuku
cd ~/shizuku
SHIZUKU_VER=$(curl -s https://api.github.com/repos/RikkaApps/Shizuku/releases/latest | grep '"tag_name"' | head -1 | cut -d'"' -f4)
wget -q "https://github.com/RikkaApps/Shizuku/releases/download/${SHIZUKU_VER}/rish_shizuku.dex" -O rish.dex
wget -q "https://github.com/RikkaApps/Shizuku/releases/download/${SHIZUKU_VER}/rish" -O rish
chmod +x rish
```

5. Verify:

```bash
sh rish -c "id"
```


6. Run the script with deep detection:

```bash
cd ..
cd MDMWreck
python evanrocks.py --deep
```

This executes `dumpsys device_policy` with full privileges, increasing detection reliability.

---

## Usage

Run in Termux:

```bash
python3 evanrocks.py
```

Follow menu options:

| Action | Description |
|---------|--------------|
| Detect | Check for hidden or active management agents and stealthy configuration |
| Block Domains | Add ~400 known management servers to denylist via NextDNS |
| Unblock Domains | Remove those domains from denylist |
| Send Notice | Send formal legal notices to management servers/consoles |
| Show Instructions | How to configure NextDNS DNS on your device |
| Exit | Quit the tool |

**Always confirm prompts** before applying actions.

---

## Notes & Best Practices

- This tool **won't** uninstall management apps; it only detects and blocks communication.
- Use only on devices you own or with explicit permission.
- Deep detection requires **`rish`** (Shizuku shell) to be installed and running.
- Detection can produce **false positives**; review output carefully.
- Use the **generated logs and notices** responsibly and legally.

---

## Troubleshooting

- **`rish` not detected:** Ensure Shizuku is installed, started, and set to "Start via Wireless ADB."
- **Detection not working:** Verify `rish` is executable and running.
- **False positives:** Add known safe packages to exception lists or review output.
- **No deep detection:** Confirm Shizuku is active and `rish` is working.

---

## Final Notes

This is a **power-user tool** for detection, blocking, and notification of device management agents. Use responsibly, follow instructions carefully, and review all outputs before acting.


NOTICE: SHIZUKU CAN BE DANGEROUS IF YOU DONT KNOW WHAT YOUR DOING. 

FOLLOW ALL LAWS
DO NOT MISUSE THIS TOOL.
THIS TOOL IS FOR DEFENSE EDUCATION AND RESEARCH
USE AT YOUR OWN RISK
BY USING THIS TOOL YOU AGREE THAT THE CREATOR, EVAN SAURAGE, IS NOT HELD RESPONSIBLE OR LIABLE  FOR ANY OF THE OUTCOMES WHICH MAY UNFOLDNDUE TO THE USE OF THIS TOOL.

DO NOT FORK OR MODIFY THIS CODE IN ANY WAY YOU DO NOT HAVE THE RIGHT TO.

---

### Last Laugh

ha.
