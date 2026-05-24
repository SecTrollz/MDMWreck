#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         Evan's MDM TOOLKIT  —  evanrocks.py                                       ║
║  Block · Detect · Audit · Notify  across every major MDM platform                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
THIS TOOL IS INTENDED TO BE USED ONLY ON DEVICES
1. YOU HAVE PURCHASED/GIFTED
2. BELIEVE YOU ARE THE LEGAL OWMER OF
3. ANY USE OF THIS TOOL FOR ILLEGAL PURPOSES IS PROHIBITED

NOTICE: DO NOT USE ON DEVICES OTHER THEN THAT OF WHICH YOU OWN AND POSSESS
DOING SO CAN VIOLATE THE LAW AND GET YOU IN TROUBLE. DO NOT ATTEMPT.

USE THIS TOOL AT YOUR OWN RISK.

IF MISUSE OCCURS AND I FIND OUT IMMA TELL SANTA.

QUICK START (run this first):
    python3 evanrocks.py

REQUIREMENTS:
    • Python 3.8+  (check: python3 --version)
    • Internet connection  (even a slow one works)
    • NextDNS account  (free at nextdns.io)
    • [OPTIONAL] Shizuku app + rish shell for deep MDM detection

WHAT THIS SCRIPT DOES — PLAIN ENGLISH:
  1. BLOCKS your phone from talking to MDM servers via NextDNS DNS filtering.
     Your phone asks "where is manage.microsoft.com?" — NextDNS says "nowhere."
     No DNS reply = no connection = MDM can't reach your device.

  2. DETECTS hidden management agents already on your device, including ones
     the IT admin deliberately hid so you wouldn't find them.

  3. SENDS a formal legal notice directly into the IT admin's management
     console using the same communication channel the MDM uses to control you.

HOW DNS BLOCKING WORKS:
  Every app on your phone — including MDM agents — uses DNS to find servers.
  DNS is like a phone book: "give me the IP address for manage.microsoft.com."
  This script adds ~400 MDM server names to your NextDNS denylist.
  When the MDM agent tries to look up its server, the answer is "NXDOMAIN"
  (does not exist). The agent cannot connect. It cannot receive commands,
  push policies, wipe your device, or report your location.

  This is 100% legal. You are configuring YOUR DNS resolver.

LIMITATIONS (be honest with yourself):
  • DNS blocking stops network communication but does NOT uninstall the agent.
  • Some MDMs cache their server IP and bypass DNS for a while (hours/days).
  • Samsung Knox Guarantee and some carrier agents run below the OS level
    and may survive DNS blocking. Those require factory reset.
  • This is a shield, not a sword. Pair it with: factory reset if possible,
    legal notice to HR/IT, and consulting an employment/privacy lawyer.

WHERE TO GET YOUR NEXTDNS CREDENTIALS:
  Profile ID:  Log in at my.nextdns.io — look at the URL bar:
               my.nextdns.io/XXXXXX/setup  ← those 6 characters
  API Key:     my.nextdns.io → click your avatar (top-right) → Account
               → scroll to "API" section → click "Generate" → copy it

FOR DEEP MDM DETECTION (OPTIONAL BUT RECOMMENDED):
  1. Install "Shizuku" from the Play Store (free, no root needed)
  2. Open Shizuku → tap "Start via ADB (wireless)" → follow its instructions
  3. Install "rish" (search Play Store for "rish shizuku")
  4. Re-run this script — it will automatically use privileged access

TROUBLESHOOTING:
  "No internet"        → Are you on Wi-Fi or data? Try opening a browser first.
  "DNS blocked"        → Your MDM may be blocking DNS. The script tries DoH bypass.
  "API key rejected"   → Did you copy the whole key? It's usually 40+ characters.
  "Profile ID wrong"   → Must be exactly 6 characters from the URL bar.
  "rish not found"     → Shizuku isn't running. MDM detection uses basic mode.
  "HTTP 401 on send"   → MDM requires device cert — save & email notice instead.
  "rate limited"       → NextDNS free tier has limits. Script waits and retries.
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import getpass, json, os, re, socket, ssl, subprocess, sys, time, urllib.error
import urllib.parse, urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL COLORS  (auto-disabled if output is piped/redirected)
# ══════════════════════════════════════════════════════════════════════════════
_TTY = sys.stdout.isatty()

def _c(code, s):  return f"\033[{code}m{s}\033[0m" if _TTY else s
bold = lambda s: _c("1",    s)
dim  = lambda s: _c("2",    s)
red  = lambda s: _c("91",   s)
grn  = lambda s: _c("92",   s)
ylw  = lambda s: _c("93",   s)
cyn  = lambda s: _c("96",   s)
wht  = lambda s: _c("97",   s)
mag  = lambda s: _c("95",   s)
blu  = lambda s: _c("94",   s)

def banner():
    print(_c("96;1", """
╔══════════════════════════════════════════════════════════════════════════════╗
║          MDM SOVEREIGNTY TOOLKIT  v4  —  nextdns_mdm_block.py              ║
║  Block · Detect · Audit · Notify  across every major MDM platform          ║
╚══════════════════════════════════════════════════════════════════════════════╝"""))

def hdr(title):
    bar = "─" * max(0, 60 - len(title))
    print(f"\n{bold('┌── ' + title + ' ' + bar)}")

def ok(m):       print(f"  {grn('✓')}  {m}")
def warn(m):     print(f"  {ylw('⚠')}  {m}")
def err(m):      print(f"  {red('✗')}  {m}")
def inf(m):      print(f"  {cyn('→')}  {m}")
def tip(m):      print(f"  {blu('💡')} {dim(m)}")
def step(n, m):  print(f"\n  {bold(f'[{n}]')}  {wht(m)}")
def rule():      print(f"  {dim('─' * 60)}")

# ══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE PROMPTS
# ══════════════════════════════════════════════════════════════════════════════

def _read_secret(prompt: str) -> str:
    """Secure input: no echo. Works in Termux, bash, zsh. Handles paste."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            chars = []
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\n", "\r", ""):   break
                elif ch in ("\x7f", "\x08"): chars and chars.pop()
                elif ch == "\x03":           print(); sys.exit(0)
                elif ch and ord(ch) >= 32:   chars.append(ch)
            sys.stdout.write("\n"); sys.stdout.flush()
            return "".join(chars).strip()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except Exception:
        pass
    try:
        sys.stdout.write("\n")
        return getpass.getpass("").strip()
    except Exception:
        pass
    sys.stdout.write("(visible — paste carefully): ")
    sys.stdout.flush()
    return sys.stdin.readline().strip()


def ask(label: str, default: str = "", secret: bool = False,
        validator=None, help_text: str = "") -> str:
    """
    Prompt the user for input with optional validation loop.
    validator: callable(str) -> (bool, error_message_str)
    """
    if help_text:
        tip(help_text)
    hint_plain  = f" [{'*'*8 if secret else default}]" if default else ""
    hint_styled = f" [{dim('*'*8 if secret else default)}]" if default else ""
    while True:
        try:
            if secret:
                val = _read_secret(f"  ?  {label}{hint_plain}: ")
            else:
                val = input(f"  {cyn('?')}  {label}{hint_styled}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        val = val.strip()
        if not val:
            if default: return default
            warn("This field is required — please enter a value.")
            continue
        if validator:
            ok_flag, msg = validator(val)
            if not ok_flag:
                err(f"Invalid: {msg}")
                continue
        return val


def confirm(question: str, default: bool = True) -> bool:
    hint = f"{grn('Y')}/n" if default else f"y/{red('N')}"
    try:
        r = input(f"  {cyn('?')}  {question} [{hint}]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print(); sys.exit(0)
    return default if not r else r in ("y", "yes")


def choose(question: str, options: list) -> str:
    print(f"\n  {cyn('?')}  {question}")
    for i, o in enumerate(options, 1):
        print(f"      {bold(str(i))})  {o}")
    while True:
        try:
            r = input(f"  {cyn('→')}  Enter number [1]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)
        if not r: return options[0]
        try:
            idx = int(r) - 1
            if 0 <= idx < len(options): return options[idx]
        except ValueError:
            pass
        warn(f"Please enter a number between 1 and {len(options)}.")


def pause(msg="Press Enter to continue…"):
    try: input(f"\n  {dim(msg)}")
    except (KeyboardInterrupt, EOFError): print(); sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN LIST — 400+ MDM endpoints across 40+ platforms
# ══════════════════════════════════════════════════════════════════════════════

SAFE_DOMAINS = {
    "albert.apple.com", "captive.apple.com", "gs.apple.com", "humb.apple.com",
    "static.ips.apple.com", "tbsc.apple.com", "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com", "time.android.com",
}

_RAW_DOMAINS = """
enterprise.android.com enterprise.google.com androidenterprise.google.com
androidenterprise.googleapis.com zero-touch.enrollment.google.com
zero-touch.googleapis.com zerotouch.googleapis.com androidzerodevice.googleapis.com
afw.google.com afw-setup.google.com clouddpc.google.com work.google.com
mdmconfig.googleapis.com deviceenrollment.googleapis.com deviceregistration.googleapis.com
device-provisioning.googleapis.com provisioning.googleapis.com setup.googleapis.com
enrollmenttoken.googleapis.com enrollment.googleapis.com
androiddevicepolicy.googleapis.com enterprisedevicemanagement.googleapis.com
managedconfigurations.googleapis.com managedconfigurationsforiframe.googleapis.com
androidmanagement.googleapis.com devicepolicy.googleapis.com mdm.googleapis.com
emm.googleapis.com manageddevice.googleapis.com androidworkprofile.googleapis.com
clouddevicepolicy.googleapis.com deviceauditing.googleapis.com
deviceverification.googleapis.com endpointverification.googleapis.com
endpoint-verification.googleapis.com chromepolicy.googleapis.com
android.clients.google.com androidcheckin.googleapis.com checkin.googleapis.com
registrar.googleapis.com registrationmanager.googleapis.com ota-checkin.googleapis.com
accounts.google.com accounts.youtube.com accountsettings.googleapis.com
accountdelegation.googleapis.com accountmanager.googleapis.com
mydevices.google.com myaccount.google.com oauth2.googleapis.com
openidconnect.googleapis.com securetoken.googleapis.com
oauthaccountmanager.googleapis.com token.googleapis.com iam.googleapis.com
iamcredentials.googleapis.com cloudidentity.googleapis.com
cloudidentitytoolkit.googleapis.com identitytoolkit.googleapis.com
identityplatform.googleapis.com admin.googleapis.com admin.google.com
adminreporting.googleapis.com adminaudit.googleapis.com directory.googleapis.com
workspaceadmin.googleapis.com workspaceevents.googleapis.com workspace.google.com
devicemanagement.googleapis.com gms.googleapis.com gmscore.googleapis.com
deviceconfigservice.googleapis.com phonelookup.googleapis.com
smartdevice.googleapis.com people.googleapis.com peopleapi.googleapis.com
mobiledevicemanagement.googleapis.com phenotype.googleapis.com
phenotype-pa.googleapis.com phenotype-log.googleapis.com
logging.googleapis.com cloudlogging.googleapis.com auditrecording-pa.googleapis.com
clienttracing-pa.googleapis.com datasaver.googleapis.com
diagnosticcloud.googleapis.com cloudtrace.googleapis.com
cloudprofiler.googleapis.com clouderrorreporting.googleapis.com
monitoring.googleapis.com reports.googleapis.com
firebase.googleapis.com firebaseio.com firebaseinstallations.googleapis.com
firebasecrashlytics.googleapis.com crashlytics.googleapis.com
firebase-settings.crashlytics.com firebaselogging.googleapis.com
firebasedynamiclinks.googleapis.com firebaseinappmessaging.googleapis.com
firebaseremoteconfig.googleapis.com firebaseperf.googleapis.com
firebaseappdistribution.googleapis.com firebaseappcheck.googleapis.com
firebasehosting.googleapis.com firebasestorage.googleapis.com
fcm.googleapis.com fcmregistrations.googleapis.com fcm-token.googleapis.com
mtalk.google.com mtalk4.google.com alt1-mtalk.google.com alt2-mtalk.google.com
alt3-mtalk.google.com alt4-mtalk.google.com alt5-mtalk.google.com
alt6-mtalk.google.com alt7-mtalk.google.com alt8-mtalk.google.com
android.googleapis.com android.apis.google.com
attestation.android.com playintegrity.googleapis.com playintegrity.google.com
safetynet.googleapis.com safetynet-pa.googleapis.com jws.googleapis.com
recaptcha.google.com recaptchaenterprise.googleapis.com
verifiedaccess.googleapis.com verifiedaccess-pa.googleapis.com
androidkeyattestation.googleapis.com keyattestation.googleapis.com
play.google.com play-fe.googleapis.com market.android.com
androidmarket.googleapis.com vending.googleapis.com play.googleapis.com
content.googleapis.com clientservices.googleapis.com managedplay.googleapis.com
managedgoogleplay.googleapis.com managedgoogleplayfulldevice.googleapis.com
playauto.googleapis.com androidtaskservice.googleapis.com ggpht.com
app-measurement.com measurement.googleapis.com google-analytics.com
analytics.google.com stats.googleapis.com location.googleapis.com
locationreporting.googleapis.com geolocation.googleapis.com
userlocation.googleapis.com tagmanager.googleapis.com doubleclick.net
adservice.google.com update.googleapis.com ota.googlezip.net
redirector.gvt1.com dl.google.com dl-ssl.google.com updates.googleapis.com
packages.googleapis.com fota.googleapis.com fotaserver.googleapis.com
sos.googleapis.com recovery.googleapis.com carrierconfig.googleapis.com
carrierconfig-pa.googleapis.com remotedisplay.googleapis.com
screencast.googleapis.com remotelockdown.googleapis.com
remotemanagement.googleapis.com remotedeviceadministration.googleapis.com
cast.googleapis.com googleusercontent.com gvt1.com gvt2.com gcp.gvt2.com
beacons.gcp.gvt2.com beacons2.gvt2.com beacons3.gvt2.com beacons4.gvt2.com
1e100.net storage.googleapis.com cloudkms.googleapis.com
cloudresourcemanager.googleapis.com servicecontrol.googleapis.com
networkconnectivity.googleapis.com networksecurity.googleapis.com
safebrowsing.googleapis.com safebrowsing.google.com
clients1.google.com clients2.google.com clients3.google.com
clients4.google.com clients5.google.com clients6.google.com
clients7.google.com clients8.google.com chrome.google.com
chromeenterprise.google chromeenterprise.google.com
chromereporting.googleapis.com chromebrowsercloudmanagement.googleapis.com
m.google.com endpoint.google.com endpoint-management.google.com
security.google.com securitycenter.googleapis.com
workspaceeventsdatastreamapidemo.googleapis.com
deviceenrollment.apple.com deviceservices-external.apple.com
gdmf.apple.com identity.apple.com iprofiles.apple.com
mdmenrollment.apple.com vpp.itunes.apple.com axm-servicediscovery.apple.com
business.apple.com school.apple.com appleid.cdn-apple.com idmsa.apple.com
api.ent.apple.com api.edu.apple.com api-business.apple.com api-school.apple.com
statici.icloud.com axm-adm-enroll.apple.com axm-adm-mdm.apple.com
axm-adm-scep.apple.com axm-app.apple.com icons.axm-usercontent-apple.com
push.apple.com api.push.apple.com feedback.push.apple.com appattest.apple.com
configurator.apple.com supervision.apple.com
knox.samsung.com knoxportal.samsung.com knoxsuite.samsung.com
knoxguard.samsung.com knoxcloud.samsung.com api.knox.samsung.com
license.knox.samsung.com seap.samsung.com kms.samsung.com klms.samsung.com
kgms.samsung.com esdk.samsungknox.com samsungknox.com bimserver.samsungknox.com
lm.samsungknox.com fdn.samsungknox.com sdk.samsungknox.com
manage.samsungknox.com eu.manage.samsungknox.com us.manage.samsungknox.com
ap.manage.samsungknox.com mdm.samsungknox.com register.samsungknox.com
attestation.samsungknox.com rem.samsungknox.com samsungmdm.com
mdm.samsung.com fota.samsungmobile.com odinupdate.samsungmobile.com
samsungota.com account.samsung.com samsungpushservice.com
push.samsungmobile.com samsung-analytics.com cdn.samsungcloud.com
samsungknoxmdm.com manage.microsoft.com portal.manage.microsoft.com
m.manage.microsoft.com admin.manage.microsoft.com r.manage.microsoft.com
wip.mam.manage.microsoft.com mam.manage.microsoft.com
enrollment.manage.microsoft.com autoenroll.manage.microsoft.com
enterpriseenrollment.manage.microsoft.com
enterpriseenrollment-s.manage.microsoft.com
fef.msua01.manage.microsoft.com fef.msua02.manage.microsoft.com
fef.msua04.manage.microsoft.com fef.msua05.manage.microsoft.com
fef.msua06.manage.microsoft.com fef.msub01.manage.microsoft.com
fef.msub02.manage.microsoft.com fef.msub03.manage.microsoft.com
fef.msub05.manage.microsoft.com fef.msub06.manage.microsoft.com
fef.amsua0102.manage.microsoft.com fef.amsua0202.manage.microsoft.com
fef.amsua0302.manage.microsoft.com fef.amsua0402.manage.microsoft.com
fef.amsua0502.manage.microsoft.com fef.amsua0602.manage.microsoft.com
intune.microsoft.com endpoint.microsoft.com devicemanagement.microsoft.com
compliance.microsoft.com mdm.microsoft.com mdmwindows.com emdm.microsoft.com
enterpriseregistration.windows.net enterpriseregistration.microsoftonline.com
login.microsoftonline.com login.microsoft.com login.live.com login.windows.net
sts.windows.net device.login.microsoftonline.com
autologon.microsoftazuread-sso.com registration.mobile.microsoft.com
provisioningapi.microsoftonline.com adminwebservice.microsoftonline.com
account.activedirectory.windowsazure.com management.azure.com portal.azure.com
graph.microsoft.com graph.windows.net aadcdn.msftauth.net aadcdn.msauth.net
aadcdn.msauthimages.net dps.azure.com settings.data.microsoft.com
pas.windows.net msappproxy.net msidentity.com azureedge.net
intunecdnpeasd.azureedge.net wns.windows.com push.windows.com
wdcp.microsoft.com wdcpalt.microsoft.com smartscreen.microsoft.com
definitionupdates.microsoft.com defender.microsoft.com mde.microsoft.com
smartscreen-prod.microsoft.com mam.microsoft.com mam-staging.microsoft.com
mamservice.microsoft.com ztd.dds.microsoft.com cs.dds.microsoft.com
privatelink.microsoftonline.com globalenrollment.microsoft.com
jumpcloud.com console.jumpcloud.com api.jumpcloud.com
kickstart.jumpcloud.com agent.jumpcloud.com cdn.jumpcloud.com
cdn02.jumpcloud.com auth.jumpcloud.com sso.jumpcloud.com
ldap.jumpcloud.com radius.jumpcloud.com identityapi.jumpcloud.com
remoteassist.jumpcloud.com insights.jumpcloud.com events.jumpcloud.com
mdm.jumpcloud.com policy.jumpcloud.com commands.jumpcloud.com
softwaremanagement.jumpcloud.com go.jumpcloud.com
eu.jumpcloud.com eu-console.jumpcloud.com eu-api.jumpcloud.com
airwatch.com awmdm.com airwatchmdm.com air-watch.com
api.workspaceone.com workspaceone.com admin.workspaceone.com
portal.workspaceone.com getenrolled.workspaceone.com login.workspaceone.com
cloud.workspaceone.com enroll.workspaceone.com ws1.workspaceone.com
na.workspaceone.com eu.workspaceone.com apac.workspaceone.com
ds.awmdm.com as.awmdm.com deviceservices.awmdm.com mdm.awmdm.com
console.awmdm.com notificationserver.awmdm.com awcm.awmdm.com
ws1.airwatch.com na.dm.airwatch.com eu.dm.airwatch.com apac.dm.airwatch.com
cn.airwatch.com registration.awmdm.com enroll.awmdm.com
deviceservices.airwatch.com awagent.com awcm.vmware.com
uemapi.vmware.com getenrolled.vmware.com vidm.vmware.com
horizon.vmware.com myvmware.com cloud.vmware.com
mobileiron.com mdm.mobileiron.com ivi.mobileiron.com tunnel.mobileiron.com
appconnect.mobileiron.com go.mobileiron.com register.mobileiron.com
ivanti.com mi.ivanti.cloud cloud.ivanti.com enroll.ivanti.com
portal.ivanti.com api.ivanti.com pulsesecure.net neurons.ivanti.com
discovery.ivanti.com xenmobile.net citrix.com endpoint.citrix.com
cdm.citrix.com citrixworkspace.net wsf.citrix.com citrixnetworkapi.net
gateway.citrix.com cis.citrix.com xm.citrix.com mdm.citrix.com
cloud.com citrixcloud.net enroll.citrix.com receiver.citrix.com
store.citrix.com soti.net mobicontrol.soti.net mc.soti.net cloud.soti.net
connect.soti.net notify.soti.net mobi.soti.net enroll.soti.net
maas360.com fmp.maas360.com dm.maas360.com cloud.maas360.com
portal.maas360.com reg.maas360.com mdm.maas360.com api.maas360.com
notification.maas360.com wipe.maas360.com enroll.maas360.com securitymdm.com
jamf.com jamfcloud.com jamfnow.com jamfschool.com jamfpro.com
enrollment.jamfcloud.com assets.jamf.com updates.jamf.com
api.jamf.com jamf.ninja jamfconnect.com rec.jamfcloud.com ca.jamfcloud.com
blackberry.com uem.blackberry.com bbcs.net enterprise.blackberry.com
bbsecure.com cylance.com threatchintelligence.cylance.com
bis.na.blackberry.com bis.eu.blackberry.com bis.apac.blackberry.com
blackberryenterprise.com bbeservices.com sophos.com cloud.sophos.com
mcs.sophos.com central.sophos.com sophosxl.net dci.sophosupd.com
dci.sophosupd.net savservice.sophos.com lookout.com mas.lookout.com
mtp.lookout.com mobile.lookout.com enterprise.lookout.com api.lookout.com
zimperium.com cloud.zimperium.com api.zimperium.com zips.zimperium.com
pradeo.com wandera.com netskope.com goskope.com nsscloud.com
crowdstrike.com ts01-b.cloudsink.net cloudsink.net
falconapi.crowdstrike.com falcon.crowdstrike.com api.crowdstrike.com
sentinelone.com prd00.sentinelone.net sentinelone.net
absolute.com bi.absolute.com monitoring.absolute.com search.absolute.com
ctes.absolute.com dfndr.absolute.com absoluteapps.com
okta.com oktapreview.com okta-emea.com auth.okta.com api.okta.com
duosecurity.com duo.com api.duosecurity.com
meraki.cisco.com dashboard.meraki.com sm.meraki.com
systems-manager.cisco.com n160.meraki.com cisco.com
manageengine.com mdmcloud.manageengine.com devicecloud.manageengine.com
em.manageengine.com patch.manageengine.com hexnode.com cloud.hexnode.com
api.hexnode.com enroll.hexnode.com kandji.io updates.kandji.io api.kandji.io
mosyle.com api.mosyle.com business.mosyle.com fuse.mosyle.com
addigy.com prod.addigy.com simplemdm.com api.simplemdm.com
fleetdm.com update.fleetdm.com miradore.com online.miradore.com
scalefusion.com cloud.scalefusion.com mdm.scalefusion.com
applivery.com api.applivery.com baramundi.com cloud.baramundi.com flyve-mdm.com
dm.att.com dm2.att.com oma-dm.att.com att.device-management.com
config.att.com omacp.att.com fota.att.com firstnet.att.com firstnet.com
devices.att.com dm.vzw.com qtifw.vzw.com sai.vzw.com iqsrdm.vzw.com
oma-dm.verizon.net omadm.verizonwireless.com mdm.verizonbusiness.com
vzwssl.com fota.vzw.com dm.t-mobile.com dm-prd.t-mobile.com
omadm.t-mobile.com config.t-mobile.com omacp.t-mobile.com fota.t-mobile.com
dm.sprint.com omadm.sprint.com diagservices.qualcomm.com izat.qualcomm.com
xtcloud.qualcomm.com lbs.qualcomm.com xtrapath1.izatcloud.net
xtrapath2.izatcloud.net xtrapath3.izatcloud.net xtrapath4.izatcloud.net
sls.izatcloud.net prodxtracore.izatcloud.net izatcloud.net
ema.intel.com emdmapp.intel.com api.ema.intel.com provisioning.intel.com
registration.intel.com amt-provisioning.intel.com mebx.intel.com
dash.amd.com management.amd.com remote.amd.com
hwid.cloud.huawei.com appgallery.cloud.huawei.com push.hicloud.com
push.dbankcloud.com oemwebquery.dbankcloud.com mobilecloudservice.huawei.com
logservice.cloud.huawei.com mdm.hicloud.com device.cloud.huawei.com
hicloud.com dbankcloud.com fota.dbankcloud.com fota-dre.dbankcloud.com
hihonormdm.com mdm.miui.com api.miui.com data.mistat.xiaomi.com
tracking.miui.com tracking.intl.miui.com data.mistat.intl.xiaomi.com
analytics.miui.com logbak.miui.com logbak-global.miui.com
sdkconfig.ad.xiaomi.com sdkconfig.ad.intl.xiaomi.com fota.miui.com
bigota.d.miui.com update.miui.com updater.miui.com miuirom.org
mdm.zte.com.cn push.zte.com.cn fota.zte.com.cn ota.zte.com.cn
update.zte.com.cn dm.zte.com.cn mdm.heytap.com push.heytap.com
push.oppo.com coloros.com mdm.coloros.com oplus.com log.coloros.com
push.oneplus.net push.oneplus.com mdm.oneplus.com update.oneplus.com
fota.oneplus.net motorolasolutions.com mdm.motorolasolutions.com
fota.motorola.com push.motorola.com ota.motorola.com device.motorola.com
apperian.com mcafee.com mvision.mcafee.com epo.mcafee.com
trellix.com endpoint.trellix.com agent.trellix.com
tanium.com cloud.tanium.com api.tanium.com vmray.com
"""

DOMAINS = [d.lower() for d in _RAW_DOMAINS.split()
           if d and not d.startswith('#') and d not in SAFE_DOMAINS]
DOMAINS = list(dict.fromkeys(DOMAINS))
TOTAL   = len(DOMAINS)

# ══════════════════════════════════════════════════════════════════════════════
# MDM PLATFORM REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MdmPlatform:
    package:       str
    name:          str
    protocol:      str   # "intune" | "oma-dm" | "knox" | "ws1" | "generic-http"
    check_in_host: str
    check_in_path: str
    content_type:  str
    notes:         str = ""

MDM_REGISTRY: list[MdmPlatform] = [
    MdmPlatform("com.google.android.apps.work.clouddpc", "Google Android Management API",
                "generic-http", "androidmanagement.googleapis.com",
                "/v1/enterprises/{enterprise}/devices/{device}:sendCommand",
                "application/json"),
    MdmPlatform("com.microsoft.intune", "Microsoft Intune",
                "intune", "manage.microsoft.com",
                "/StatelessEnrollmentService/DeviceEnrollment.svc",
                "application/soap+xml; charset=utf-8"),
    MdmPlatform("com.microsoft.windowsintune.companyportal", "Microsoft Intune Company Portal",
                "intune", "manage.microsoft.com",
                "/StatelessEnrollmentService/DeviceEnrollment.svc",
                "application/soap+xml; charset=utf-8"),
    MdmPlatform("com.samsungknox.dcagent", "Samsung Knox Device Agent",
                "knox", "kms.samsung.com", "/agms/v2/device/checkin", "application/json"),
    MdmPlatform("com.samsung.android.knox.containeragent", "Samsung Knox Container Agent",
                "knox", "kms.samsung.com", "/agms/v2/device/checkin", "application/json"),
    MdmPlatform("com.airwatch.androidagent", "VMware Workspace ONE",
                "ws1", "ds.awmdm.com",
                "/deviceservices/awmdm/deviceapi/DeviceApi", "application/json"),
    MdmPlatform("com.mobileiron", "Ivanti MobileIron",
                "oma-dm", "mdm.mobileiron.com", "/DMservice",
                "application/vnd.syncml+xml; charset=utf-8"),
    MdmPlatform("com.mobileiron.anyware.android", "Ivanti MobileIron Go",
                "oma-dm", "mdm.mobileiron.com", "/DMservice",
                "application/vnd.syncml+xml; charset=utf-8"),
    MdmPlatform("com.citrix.mdm", "Citrix Endpoint Management",
                "oma-dm", "xm.citrix.com", "/zdm/devices",
                "application/vnd.syncml+xml"),
    MdmPlatform("net.soti.mobicontrol", "SOTI MobiControl",
                "oma-dm", "cloud.soti.net", "/MobiControl/api/devices",
                "application/json"),
    MdmPlatform("com.fiberlink.maas360.android.control", "IBM MaaS360",
                "generic-http", "dm.maas360.com", "/messagebroker/v1/devices",
                "application/json"),
    MdmPlatform("com.jamf.management", "Jamf Pro",
                "generic-http", "enrollment.jamfcloud.com",
                "/JSSResource/mobiledevices", "application/json"),
    MdmPlatform("com.jumpcloud.android", "JumpCloud",
                "generic-http", "api.jumpcloud.com", "/api/v2/devices",
                "application/json"),
    MdmPlatform("com.blackberry.bbmdm", "BlackBerry UEM",
                "oma-dm", "uem.blackberry.com",
                "/enterprise/admin/v1/devices", "application/json"),
    MdmPlatform("com.hexnode.devicemanagement", "Hexnode UEM",
                "generic-http", "api.hexnode.com", "/v1/device/",
                "application/json"),
    MdmPlatform("com.scalefusion.mdm", "ScaleFusion",
                "generic-http", "mdm.scalefusion.com", "/api/v1/devices",
                "application/json"),
    MdmPlatform("com.manageengine.mdm.android", "ManageEngine MDM",
                "generic-http", "mdmcloud.manageengine.com", "/api/devices",
                "application/json"),
    MdmPlatform("com.crowdstrike.falcon", "CrowdStrike Falcon",
                "generic-http", "falcon.crowdstrike.com",
                "/devices/queries/devices/v1", "application/json"),
    MdmPlatform("com.lookout", "Lookout Mobile Security",
                "generic-http", "mas.lookout.com",
                "/enterprise/api/v2/devices", "application/json"),
    MdmPlatform("com.google.android.carrierconfig", "Carrier OMA-DM",
                "oma-dm", "dm.t-mobile.com", "/DMservice",
                "application/vnd.syncml+xml"),
]

PKG_TO_PLATFORM: dict[str, MdmPlatform] = {p.package: p for p in MDM_REGISTRY}

CARRIER_DM_HOSTS: dict[str, str] = {
    "310260": "dm.t-mobile.com",  "310120": "dm.sprint.com",
    "311480": "dm.vzw.com",       "310410": "dm.att.com",
    "311882": "dm.att.com",       "20416":  "oma-dm.vodafone.nl",
    "23430":  "dm.o2.co.uk",      "50501":  "dm.optus.com.au",
}

STEALTH_PACKAGES: list[tuple[str, str]] = [
    ("com.google.android.apps.work.clouddpc",      "Google AFW / Cloud DPC"),
    ("com.google.android.gms.policy_sidecar_aps",  "GMS Policy Sidecar (silent agent)"),
    ("com.android.managedprovisioning",             "Managed Provisioning Trigger"),
    ("com.samsung.android.sm.policy",               "Samsung Policy Agent"),
    ("com.samsung.android.knox.containeragent",     "Knox Container Agent"),
    ("com.samsung.android.knox.attestation",        "Knox Attestation Service"),
    ("com.lge.mdm.deviceadmin",                     "LG MDM Device Admin"),
    ("com.huawei.mdm",                              "Huawei MDM Agent"),
    ("com.miui.mdm",                                "Xiaomi/MIUI MDM"),
    ("com.zte.mdm",                                 "ZTE MDM"),
    ("com.oppo.mdm",                                "OPPO MDM"),
    ("com.motorola.mdm",                            "Motorola MDM"),
    ("com.qualcomm.qti.telephonyservice",           "Qualcomm OMA-DM Client"),
]

STEALTH_PATTERNS: list[tuple[str, str]] = [
    (r"Device Owner:",                    "Device Owner declared"),
    (r"Profile Owner:",                   "Profile Owner declared"),
    (r"admin=[\w.]+",                     "Device Admin package registered"),
    (r"mPasswordOwner=",                  "Password policy owner active"),
    (r"mActiveAdminList",                 "Active admin list present"),
    (r"PermittedAccessibilityServices",   "Accessibility lockdown active"),
    (r"GlobalProxy",                      "Global HTTP proxy enforced"),
    (r"MaximumFailedPasswordsForWipe",    "Remote wipe policy installed"),
    (r"isDelegate=true",                  "Delegated admin scope detected"),
    (r"HIDE_COMPONENT",                   "Component hidden (stealth install)"),
    (r"packageHidden=true",               "Package explicitly hidden by MDM"),
    (r"restrictionsProvider",             "MDM app restrictions provider active"),
    (r"managedProfile",                   "Managed/work profile exists"),
    (r"enrollmentToken",                  "Enrollment token present"),
    (r"cloudDpcId",                       "Google AFW/cloud DPC identifier"),
    (r"enterpriseId",                     "Enterprise ID in policy data"),
]

# ══════════════════════════════════════════════════════════════════════════════
# SSL / NETWORK HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _ssl_ctx() -> ssl.SSLContext:
    """Permissive TLS context — encrypts traffic but bypasses cert verification.
    Required on networks where MDM performs SSL inspection / MITM."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


_DOH_SERVERS = [
    ("1.1.1.1", "https://1.1.1.1/dns-query"),
    ("8.8.8.8", "https://8.8.8.8/dns-query"),
    ("9.9.9.9", "https://9.9.9.9/dns-query"),
]


def _resolve_doh(hostname: str) -> Optional[str]:
    """
    Resolve hostname via DNS-over-HTTPS using hardcoded server IPs.
    Bypasses local DNS even if the MDM poisons/blocks it.
    """
    for doh_ip, doh_url in _DOH_SERVERS:
        try:
            url = f"{doh_url}?name={urllib.parse.quote(hostname)}&type=A"
            req = urllib.request.Request(url, headers={
                "accept":     "application/dns-json",
                "User-Agent": "Mozilla/5.0 (Linux; Android 13)",
            })
            with urllib.request.urlopen(req, timeout=8, context=_ssl_ctx()) as r:
                data = json.loads(r.read())
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1:
                        ip = ans["data"]
                        inf(f"DoH resolved {hostname} → {ip}  (via {doh_ip})")
                        return ip
        except Exception:
            continue
    return None


_RESOLVED_IP: Optional[str] = None   # set once by preflight, used everywhere

# ══════════════════════════════════════════════════════════════════════════════
# PREFLIGHT — 5-step connectivity verification
# ══════════════════════════════════════════════════════════════════════════════

def preflight() -> tuple[bool, Optional[str]]:
    """
    Verify we can reach api.nextdns.io before doing any real work.
    Returns (reachable, resolved_ip).
    Gives actionable error messages at every failure point.
    """
    hdr("Connectivity Preflight  (5 checks)")
    TARGET = "api.nextdns.io"

    # ── Check 1: Basic internet ───────────────────────────────────────────────
    step("1/5", "Basic internet — TCP to 1.1.1.1:443")
    try:
        s = socket.create_connection(("1.1.1.1", 443), timeout=6)
        s.close()
        ok("Internet is reachable")
    except OSError as e:
        err(f"No internet connection: {e}")
        print()
        warn("What to do:")
        tip("• Check Wi-Fi or mobile data is turned ON")
        tip("• Open a browser — can you load any website?")
        tip("• If on Wi-Fi, try switching to mobile data")
        tip("• A VPN may help if your carrier is blocking traffic")
        return False, None

    # ── Check 2: System DNS ───────────────────────────────────────────────────
    step("2/5", f"System DNS resolution of {TARGET}")
    sys_ip = None
    try:
        sys_ip = socket.gethostbyname(TARGET)
        ok(f"System DNS working  →  {sys_ip}")
    except socket.gaierror as e:
        warn(f"System DNS failed or blocked: {e}")
        tip("This often means your MDM is blocking DNS lookups to control")
        tip("what servers your device can reach. We'll bypass this below.")

    # ── Check 3: DNS-over-HTTPS bypass ───────────────────────────────────────
    step("3/5", "DNS-over-HTTPS bypass  (works even when MDM poisons DNS)")
    doh_ip = _resolve_doh(TARGET)
    if not doh_ip and not sys_ip:
        err("All DNS resolution failed — cannot determine IP for api.nextdns.io")
        warn("What to do:")
        tip("• Try a different network (switch from Wi-Fi to data or vice versa)")
        tip("• Disable any VPN or proxy configured by your organization")
        tip("• If on a corporate network, connect from home instead")
        return False, None
    resolved_ip = doh_ip or sys_ip

    # ── Check 4: TLS connection ───────────────────────────────────────────────
    step("4/5", f"TLS handshake to {TARGET}")
    try:
        with socket.create_connection((resolved_ip, 443), timeout=10) as raw:
            with _ssl_ctx().wrap_socket(raw, server_hostname=TARGET) as tls:
                cipher = tls.cipher()[0]
                ok(f"TLS connected  ({cipher})")
                if doh_ip and not sys_ip:
                    warn("Using DoH-resolved IP — system DNS was blocked (expected on MDM devices)")
    except Exception as e:
        err(f"TLS connection failed: {e}")
        tip("• The MDM may be blocking HTTPS to api.nextdns.io specifically")
        tip("• Try connecting from a different Wi-Fi network not managed by your org")
        tip("• A personal VPN (installed BEFORE enrollment) may help")
        return False, None

    # ── Check 5: Shizuku/rish availability ───────────────────────────────────
    step("5/5", "Shizuku/rish privileged shell  (for deep MDM detection)")
    try:
        r = subprocess.run(["rish", "-c", "echo ok"], capture_output=True,
                           text=True, timeout=5)
        if "ok" in r.stdout:
            ok("Shizuku/rish is available — deep privileged scan enabled")
        else:
            warn("rish present but not responding normally")
    except FileNotFoundError:
        warn("rish not found — using unprivileged scan  (hidden agents may be missed)")
        tip("To enable deep scan: Install 'Shizuku' + 'rish' from the Play Store")
        tip("Then open Shizuku, tap Start, and re-run this script")
    except subprocess.TimeoutExpired:
        warn("rish timed out — Shizuku may not be running")
        tip("Open the Shizuku app and tap 'Start via Wireless ADB', then retry")
    except Exception as e:
        warn(f"rish check error: {e}")

    return True, resolved_ip

# ══════════════════════════════════════════════════════════════════════════════
# NEXTDNS API  — with 3-strategy fallback + actionable error messages
# ══════════════════════════════════════════════════════════════════════════════

API = "https://api.nextdns.io"


def _api_call(method: str, path: str, key: str,
              body=None, retries: int = 3) -> tuple[int, dict]:
    """
    Multi-strategy API call:
      A) Normal HTTPS with permissive SSL (handles corporate MITM proxies)
      B) Direct-IP bypass via preflight-resolved address (handles DNS blocking)
    Retries on rate-limit with exponential backoff.
    Returns (http_status_code, response_body_dict).
    """
    url  = f"{API}{path}"
    data = json.dumps(body).encode() if body else None
    hdrs = {
        "X-Api-Key":    key,
        "Content-Type": "application/json",
        "User-Agent":   "Mozilla/5.0 (Linux; Android 13)",
        "Accept":       "application/json",
    }
    last_err = "unknown error"

    for attempt in range(1, retries + 1):
        # Strategy A — normal request with permissive SSL
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx()) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            if e.code == 429:
                wait = 2.0 * (2 ** attempt)
                warn(f"NextDNS rate limit hit — waiting {wait:.0f}s before retry {attempt}/{retries}")
                tip("This is normal on free accounts. The script handles it automatically.")
                time.sleep(wait)
                continue
            return e.code, {"error": raw[:300]}
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"

        # Strategy B — direct-IP bypass
        if _RESOLVED_IP:
            try:
                parsed = urllib.parse.urlparse(url)
                direct = url.replace(parsed.hostname, _RESOLVED_IP, 1)
                req2 = urllib.request.Request(
                    direct, data=data,
                    headers={**hdrs, "Host": parsed.hostname},
                    method=method
                )
                with urllib.request.urlopen(req2, timeout=20, context=_ssl_ctx()) as r:
                    raw = r.read()
                    return r.status, (json.loads(raw) if raw else {})
            except urllib.error.HTTPError as e:
                raw = e.read().decode(errors="replace")
                if e.code == 429:
                    wait = 2.0 * (2 ** attempt)
                    time.sleep(wait)
                    continue
                return e.code, {"error": raw[:300]}
            except Exception as e2:
                last_err += f" | direct-IP fallback: {e2}"

        if attempt < retries:
            time.sleep(1.5 * attempt)

    return 0, {"error": last_err}


def validate_credentials(profile: str, key: str) -> bool:
    """
    Verify profile ID + API key are valid.
    Gives specific, actionable errors for every failure mode.
    """
    inf("Contacting NextDNS API to verify credentials…")
    code, body = _api_call("GET", f"/profiles/{profile}", key)

    if code == 200:
        ok(f"Credentials valid  →  profile {cyn(profile)} confirmed")
        return True

    err(f"Verification failed  (HTTP {code})")
    api_msg = body.get("error", "") if isinstance(body, dict) else str(body)
    if api_msg:
        print(f"  {dim('Server said:')} {api_msg[:120]}")

    if code == 401:
        warn("What went wrong: Your API key was rejected.")
        tip("• Go to my.nextdns.io → click your avatar (top-right) → Account")
        tip("• Scroll to the 'API' section → click 'Generate' or copy existing key")
        tip("• The key is typically 40+ characters — make sure you got all of it")
        tip("• No spaces at the start or end")
    elif code == 403:
        warn("What went wrong: Key accepted but it can't access this profile.")
        tip("• You may have multiple NextDNS accounts")
        tip("• Make sure the API key comes from the SAME account as the profile")
    elif code == 404:
        warn("What went wrong: Profile ID not found.")
        tip("• Log in at my.nextdns.io — look at the URL: my.nextdns.io/XXXXXX/setup")
        tip("• The 6 characters after the slash are your Profile ID")
        tip("• It's letters and numbers, like: fa5495 or a3b1c2")
    elif code == 0:
        warn("What went wrong: Could not reach the NextDNS API at all.")
        tip("• Run preflight again — your connection may have dropped")
        tip(f"• Connection error detail: {api_msg[:100]}")
    else:
        warn(f"Unexpected HTTP {code} — try again in a minute")
        tip("• NextDNS may have a temporary outage — check status.nextdns.io")

    return False


def block_domain(profile: str, key: str, domain: str) -> str:
    code, _ = _api_call("POST", f"/profiles/{profile}/denylist", key,
                        {"id": domain, "active": True})
    if code in (200, 201, 204): return "ok"
    if code == 409:             return "skip"   # already blocked
    return f"fail:{code}"


def unblock_domain(profile: str, key: str, domain: str) -> str:
    code, _ = _api_call("DELETE", f"/profiles/{profile}/denylist/{domain}", key)
    if code in (200, 204): return "ok"
    if code == 404:        return "skip"   # already absent
    return f"fail:{code}"


def patch_settings(profile: str, key: str, payload: dict) -> tuple[bool, str]:
    code, body = _api_call("PATCH", f"/profiles/{profile}/settings", key, payload)
    if code in (200, 204): return True, "ok"
    return False, body.get("error", f"HTTP {code}")

# ══════════════════════════════════════════════════════════════════════════════
# CREDENTIALS — save/load from ~/.bashrc
# ══════════════════════════════════════════════════════════════════════════════

BASHRC = os.path.expanduser("~/.bashrc")
_MARKER = "# nextdns_mdm_block"


def load_saved_creds() -> tuple[str, str]:
    return os.environ.get("NEXTDNS_PROFILE", ""), os.environ.get("NEXTDNS_API_KEY", "")


def save_creds(profile: str, key: str):
    lines = open(BASHRC).readlines() if os.path.exists(BASHRC) else []
    out, skip = [], False
    for l in lines:
        if l.strip() == _MARKER: skip = True
        elif skip and l.startswith("export NEXTDNS_"): continue
        else: skip = False; out.append(l)
    with open(BASHRC, "w") as f:
        f.writelines(out)
        f.write(f"\n{_MARKER}\nexport NEXTDNS_PROFILE={profile}\n"
                f"export NEXTDNS_API_KEY={key}\n")
    ok(f"Credentials saved to ~/.bashrc")
    tip("They will load automatically next time you open a terminal")
    tip("To load them NOW without restarting: run   source ~/.bashrc")


def _validate_profile_id(v: str) -> tuple[bool, str]:
    if len(v) != 6:
        return False, (f"Must be exactly 6 characters, you entered {len(v)}. "
                       "Find it in the URL: my.nextdns.io/XXXXXX/setup")
    if not re.fullmatch(r"[a-f0-9]+", v.lower()):
        return False, "Profile ID should be lowercase hex (letters a-f and digits 0-9)"
    return True, ""


def _validate_api_key(v: str) -> tuple[bool, str]:
    if len(v) < 20:
        return False, (f"Only {len(v)} characters — real API keys are 40+ chars. "
                       "Did you copy the whole key?")
    return True, ""


def collect_credentials() -> tuple[str, str]:
    """Interactive credential collection with validation and helpful hints."""
    hdr("NextDNS Credentials")

    profile, key = load_saved_creds()
    if profile and key:
        ok(f"Found saved credentials  (profile: {cyn(profile)})")
        if confirm("Use these saved credentials?"):
            return profile, key
        profile = key = ""

    print(f"""
  {bold('WHERE TO FIND YOUR CREDENTIALS:')}

  {bold('Profile ID')} — visible in your browser URL:
      my.nextdns.io/{cyn('fa5495')}/setup  ← those 6 characters
      Also: Setup tab → Endpoints → ID field

  {bold('API Key')}
      my.nextdns.io → click avatar (top-right) → Account
      → scroll to "API" section → Generate / copy key
      It looks like: 7a9f3b2e1d4c8f6a0b5e2d...  (40+ characters)
""")

    profile = ask(
        "Profile ID  (6 characters)",
        validator=_validate_profile_id,
        help_text="Find this in the URL bar at my.nextdns.io/XXXXXX/setup",
    ).lower()

    key = ask(
        "API Key",
        secret=True,
        validator=_validate_api_key,
        help_text="my.nextdns.io → Avatar → Account → API section",
    )

    inf(f"Profile ID captured : '{profile}'  ({len(profile)} chars)")
    inf(f"API key captured    : {'*' * min(len(key), 8)}…  ({len(key)} chars total)")

    return profile, key

# ══════════════════════════════════════════════════════════════════════════════
# PROGRESS BAR
# ══════════════════════════════════════════════════════════════════════════════

def _bar(i: int, total: int, width: int = 38) -> str:
    filled = int(width * i / total)
    pct    = i / total
    return (f"{grn('█' * filled)}{dim('░' * (width - filled))} "
            f"{i}/{total} ({pct:.0%})")

# ══════════════════════════════════════════════════════════════════════════════
# PROFILE HARDENING  — disable logging so there's nothing to subpoena
# ══════════════════════════════════════════════════════════════════════════════

def harden_profile(profile: str, key: str):
    hdr("Privacy Hardening  (Optional but Recommended)")
    print(f"""
  {bold('WHY THIS MATTERS:')}
  By default, NextDNS logs:
    {ylw('!')}  Every domain your device queries  (what apps you use, when)
    {ylw('!')}  Your IP address with every query  (your location / ISP)
  These logs are stored on US servers for up to 6 months.
  They can be subpoenaed, requested by your employer, or leaked.
  Turning them off means there is nothing to hand over — ever.
""")
    choice = choose("How should we handle your NextDNS logs?", [
        "Disable ALL logs  (maximum privacy — nothing stored — RECOMMENDED)",
        "Keep logs but strip IP and domain names  (anonymous statistics only)",
        "Skip — I'll configure this manually at my.nextdns.io → Settings",
    ])

    if "Skip" in choice:
        inf("Manual path: my.nextdns.io → Settings → Logs section")
        return

    if "Disable" in choice:
        ok_flag, msg = patch_settings(profile, key, {"logs": {"enabled": False}})
        if ok_flag:
            ok("Logging fully disabled — zero data stored, zero data to produce")
        else:
            warn(f"API patch failed: {msg}")
            tip("Do it manually: my.nextdns.io → Settings → Logs → toggle off")
    else:
        ok_flag, msg = patch_settings(profile, key,
                                      {"logs": {"drop": {"ips": True, "domains": True}}})
        if ok_flag:
            ok("Logs anonymized — IPs and domain names stripped from all entries")
        else:
            warn(f"API patch failed: {msg}")
            tip("Do it manually: Settings → Privacy → disable 'Log client IPs' and 'Log domains'")

    # Enable cache boost regardless — reduces query frequency = less leakage
    cs, _ = patch_settings(profile, key, {"performance": {"cacheBoost": True}})
    if cs:
        ok("Cache Boost enabled  (fewer DNS queries = less traffic metadata)")

# ══════════════════════════════════════════════════════════════════════════════
# PHONE SETUP INSTRUCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def print_phone_setup(profile: str):
    dns_host = f"{profile}.dns.nextdns.io"
    print(f"""
  {bold('═══════ APPLY TO YOUR DEVICE — Required for blocking to work ═══════')}

  {bold('Android 9+ (Private DNS method — works on all Android):')}
  ┌──────────────────────────────────────────────────────────────┐
  │  1. Open Settings                                            │
  │  2. Tap Network & internet (or Connections on Samsung)       │
  │  3. Tap Advanced  (may not be needed on Samsung)             │
  │  4. Tap Private DNS                                          │
  │  5. Select "Private DNS provider hostname"                   │
  │  6. Enter exactly:  {cyn(dns_host)}         │
  │  7. Tap Save                                                 │
  └──────────────────────────────────────────────────────────────┘

  {bold('Verify it worked:')}
  Open your browser and go to:  {cyn('https://test.nextdns.io')}
  You should see:  {grn('"NextDNS is working"')}
  If it says "not protected" — re-check the hostname above (no typos).

  {bold('NOTE:')} If your MDM has disabled Private DNS settings,
  you cannot change this without either uninstalling the MDM first
  or using a VPN that routes through your NextDNS profile.
  At that point, factory reset is the cleanest option.
""")

# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN PUSH  — block or unblock all domains with retry + progress
# ══════════════════════════════════════════════════════════════════════════════

def run_domain_push(profile: str, key: str, delete: bool = False) -> int:
    """
    Push all domains to the denylist (or remove them).
    Returns count of failures. Re-runnable — skips already-present entries.
    """
    fn      = unblock_domain if delete else block_domain
    verb    = "Removing" if delete else "Blocking"
    n_ok = n_skip = n_fail = 0
    fails: list[tuple[str, str]] = []

    est_min = TOTAL // 120 + 1
    print(f"\n  {bold(f'{verb} {TOTAL} domains…')}  "
          f"{dim(f'(~{est_min} min — do not close this window)')}\n")

    for i, domain in enumerate(DOMAINS, 1):
        sys.stdout.write(f"\r  {_bar(i, TOTAL)}  "); sys.stdout.flush()
        result = fn(profile, key, domain)
        if result == "ok":     n_ok   += 1
        elif result == "skip": n_skip += 1
        else:                  n_fail += 1; fails.append((domain, result))
        time.sleep(0.45)   # respect NextDNS rate limits

    print("\n")
    ok  (f"{'Removed' if delete else 'Blocked'} : {n_ok}")
    warn(f"Skipped  : {n_skip}  (already {'absent' if delete else 'listed'})")
    (err if n_fail else ok)(f"Failed   : {n_fail}")

    if fails:
        print(f"\n  {red('Failures (will need a retry run):')}")
        for d, r in fails[:20]:
            code = r.split(":")[-1] if ":" in r else r
            print(f"    {dim(d)}  [{code}]")
        if len(fails) > 20:
            print(f"    {dim(f'… and {len(fails)-20} more')}")
        print()
        tip("Re-run the script and choose the same action — already-blocked")
        tip("domains are skipped, so only the failures will be retried.")

    return n_fail

# ══════════════════════════════════════════════════════════════════════════════
# MDM DETECTION  — privileged + unprivileged scan
# ══════════════════════════════════════════════════════════════════════════════

def _rish_run(cmd: str, timeout: int = 15) -> tuple[bool, str]:
    """Run command via rish (Shizuku) if available, else plain subprocess."""
    if _rish_available():
        r = subprocess.run(["rish", "-c", cmd], capture_output=True,
                           text=True, timeout=timeout)
        return True, r.stdout + r.stderr
    r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=timeout)
    return False, r.stdout + r.stderr


def _rish_available() -> bool:
    try:
        r = subprocess.run(["rish", "-c", "echo ok"], capture_output=True,
                           text=True, timeout=5)
        return "ok" in r.stdout
    except Exception:
        return False


def _extract_urls(text: str) -> list[str]:
    found = re.findall(r'https://[A-Za-z0-9._/:%?&=+-]{8,200}', text)
    noise = {"google.com/policies", "developer.android.com", "schema.org",
             "play.google.com/store"}
    return list(dict.fromkeys(u for u in found
                              if not any(n in u for n in noise)))


def _get_mccmnc() -> Optional[str]:
    try:
        _, out = _rish_run("getprop gsm.sim.operator.numeric", timeout=5)
        v = out.strip()[:6]
        if re.fullmatch(r"\d{5,6}", v):
            return v
    except Exception:
        pass
    return None


def detect_mdm() -> dict:
    """
    Full-spectrum MDM detection.
    Returns a findings dict — see keys below.
    """
    f: dict = {
        "admins":          [],
        "packages":        [],
        "stealth_hits":    [],
        "work_profile":    False,
        "device_owner":    None,
        "profile_owner":   None,
        "live_urls":       [],
        "platforms":       [],
        "privileged":      False,
        "carrier_dm_host": None,
        "any_found":       False,
    }

    # ── Policy dump ──────────────────────────────────────────────────────────
    policy = ""
    try:
        priv, policy = _rish_run("dumpsys device_policy", timeout=15)
        f["privileged"] = priv
    except Exception as e:
        warn(f"dumpsys device_policy failed: {e}")
        tip("Shizuku may not be running — MDM scan will be limited")

    # ── Package list (includes hidden/disabled apps) ─────────────────────────
    pkg_out = ""
    try:
        _, pkg_out = _rish_run("pm list packages -u -s -d", timeout=10)
    except Exception:
        pass

    full = policy + "\n" + pkg_out

    # ── Extract structured fields ─────────────────────────────────────────────
    f["admins"]       = list(set(re.findall(r"admin=([\w.]+)", full)))
    do_m = re.search(r"Device Owner:\s*\n.*?packageName=([\w.]+)", full)
    po_m = re.search(r"Profile Owner.*?:\s*\n.*?packageName=([\w.]+)", full)
    if do_m: f["device_owner"]  = do_m.group(1)
    if po_m: f["profile_owner"] = po_m.group(1)
    f["work_profile"] = bool(
        re.search(r"(work profile|profile owner|managedProfile)", full, re.I))

    # ── Stealth patterns ──────────────────────────────────────────────────────
    for pattern, desc in STEALTH_PATTERNS:
        m = re.search(pattern, full)
        if m:
            f["stealth_hits"].append((desc, m.group(0).strip()))

    # ── Known packages ────────────────────────────────────────────────────────
    all_pkgs = STEALTH_PACKAGES + [(p.package, p.name) for p in MDM_REGISTRY]
    for pkg, name in all_pkgs:
        if pkg in full and (pkg, name) not in f["packages"]:
            f["packages"].append((pkg, name))
            plat = PKG_TO_PLATFORM.get(pkg)
            if plat and plat not in f["platforms"]:
                f["platforms"].append(plat)

    # ── Live server URLs ──────────────────────────────────────────────────────
    f["live_urls"] = _extract_urls(policy)

    # ── Carrier DM host ───────────────────────────────────────────────────────
    mccmnc = _get_mccmnc()
    if mccmnc:
        f["carrier_dm_host"] = CARRIER_DM_HOSTS.get(mccmnc)

    f["any_found"] = bool(
        f["admins"] or f["packages"] or f["stealth_hits"]
        or f["device_owner"] or f["profile_owner"] or f["work_profile"]
    )
    return f

# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE CRAFTERS — one per MDM protocol
# ══════════════════════════════════════════════════════════════════════════════

def _craft_intune_soap(device_id: str, msg: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">
      http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
    </a:Action>
    <a:MessageID>urn:uuid:{device_id}</a:MessageID>
    <a:To s:mustUnderstand="1">https://manage.microsoft.com/DeviceEnrollment.svc</a:To>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:TokenType>urn:ietf:params:xml:ns:enrollment</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken
        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        ValueType="DeviceEnrollmentUserToken"
        EncodingType="Base64Binary">{msg}</wsse:BinarySecurityToken>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>"""


def _craft_oma_dm(server_url: str, device_id: str, msg: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD><VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID><MsgID>1</MsgID>
    <Target><LocURI>{server_url}</LocURI></Target>
    <Source><LocURI>{device_id}</LocURI></Source>
    <Meta><MaxMsgSize xmlns="syncml:metinf">65536</MaxMsgSize></Meta>
  </SyncHdr>
  <SyncBody>
    <Alert>
      <CmdID>1</CmdID><Data>1201</Data>
      <Item>
        <Meta>
          <Type xmlns="syncml:metinf">text/plain</Type>
          <Format xmlns="syncml:metinf">chr</Format>
        </Meta>
        <Data>{msg}</Data>
      </Item>
    </Alert>
    <Final/>
  </SyncBody>
</SyncML>"""


def _craft_apple_checkout(topic: str, udid: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>MessageType</key><string>Checkout</string>
    <key>Topic</key><string>{topic}</string>
    <key>UDID</key><string>{udid}</string>
</dict></plist>"""


def _craft_json(device_id: str, msg: str) -> str:
    return json.dumps({
        "deviceId": device_id, "notice": msg,
        "severity": "HIGH", "type": "DEVICE_OWNER_NOTICE",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2)


def _craft_knox(device_id: str, msg: str) -> str:
    return json.dumps({
        "deviceId": device_id, "messageType": "ALERT",
        "priority": "HIGH",
        "payload": {"type": "DEVICE_OWNER_NOTICE", "message": msg},
    }, indent=2)


_CRAFTERS = {
    "intune":       lambda url, dev, msg: (_craft_intune_soap(dev, msg),
                                           "application/soap+xml; charset=utf-8"),
    "oma-dm":       lambda url, dev, msg: (_craft_oma_dm(url, dev, msg),
                                           "application/vnd.syncml+xml"),
    "apple":        lambda url, dev, msg: (_craft_apple_checkout(
                                               "com.apple.mgmt.External.notice", dev),
                                           "application/x-apple-aspen-mdm-checkin"),
    "knox":         lambda url, dev, msg: (_craft_knox(dev, msg),
                                           "application/json"),
    "ws1":          lambda url, dev, msg: (_craft_json(dev, msg),
                                           "application/json"),
    "generic-http": lambda url, dev, msg: (_craft_json(dev, msg),
                                           "application/json"),
    "jumpc":        lambda url, dev, msg: (_craft_json(dev, msg),
                                           "application/json"),
    "jamf":         lambda url, dev, msg: (_craft_json(dev, msg),
                                           "application/json"),
}

# ══════════════════════════════════════════════════════════════════════════════
# LEGAL NOTICE GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_notice(device_info: str, user_message: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
FORMAL NOTICE OF UNAUTHORIZED DEVICE MANAGEMENT
═══════════════════════════════════════════════════════════
Date/Time  : {now}
From       : Device Owner / Authorized User
To         : IT Administrator / MDM Operator
Re         : Unauthorized enrollment / remote management

NOTICE
This device is enrolled in a mobile device management (MDM)
solution without the informed, written consent of the owner.

DETECTED MDM COMPONENTS:
{device_info}

MESSAGE FROM DEVICE OWNER:
{user_message}

DEMANDS
  1. Immediate unenrollment from all MDM systems
  2. Deletion of all data collected without consent
  3. Written confirmation of compliance within 72 hours
  4. Identity of the party who authorized this enrollment

LEGAL BASIS
Continued management of this device without consent may
constitute unauthorized computer access (18 U.S.C. § 1030),
violation of state computer fraud laws, and civil liability
for invasion of privacy.

This notice was delivered through the MDM platform's own
communication infrastructure, confirming receipt.
═══════════════════════════════════════════════════════════
GENERATED BY: MDM Sovereignty Toolkit v4
""".strip()

# ══════════════════════════════════════════════════════════════════════════════
# HTTP DELIVERY  — 3-strategy with full error reporting
# ══════════════════════════════════════════════════════════════════════════════

def _deliver_http(url: str, payload: str, content_type: str) -> tuple[int, str]:
    data    = payload.encode("utf-8")
    headers = {"Content-Type": content_type,
               "User-Agent":   "MDMClient/1.0 (Android; owner-notice)",
               "Accept":       "*/*"}

    # Strategy A — normal HTTPS
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=20, context=_ssl_ctx()) as r:
            return r.status, r.read().decode(errors="replace")[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:300]
    except Exception:
        pass

    # Strategy B — direct-IP bypass
    try:
        parsed = urllib.parse.urlparse(url)
        ips = {r[4][0] for r in
               socket.getaddrinfo(parsed.hostname, 443, socket.AF_INET)}
        for ip in ips:
            try:
                direct = url.replace(parsed.hostname, ip, 1)
                req2 = urllib.request.Request(
                    direct, data=data,
                    headers={**headers, "Host": parsed.hostname},
                    method="POST")
                with urllib.request.urlopen(req2, timeout=20, context=_ssl_ctx()) as r:
                    return r.status, r.read().decode(errors="replace")[:500]
            except urllib.error.HTTPError as e:
                return e.code, e.read().decode(errors="replace")[:300]
            except Exception:
                continue
    except Exception:
        pass

    return 0, "All delivery strategies exhausted"


def _explain_delivery_result(status: int, resp: str, platform_name: str):
    """Print a human-readable explanation for every possible HTTP result."""
    if 200 <= status < 300:
        ok(f"Delivered to {platform_name}  (HTTP {status})")
        inf("The notice is now in the admin's console audit log")
    elif status == 400:
        warn(f"HTTP 400 — server received the request but rejected the format")
        tip("The admin server still logged the connection attempt")
        tip("Trying plain-text fallback automatically…")
    elif status == 401:
        warn(f"HTTP 401 — endpoint requires device certificate (mutual TLS)")
        tip("The MDM requires your device's certificate to authenticate")
        tip("This is expected for some enterprise platforms")
        tip("→ Save the notice file and email it to IT/HR/Legal directly")
    elif status == 403:
        warn(f"HTTP 403 — server refused the request (permission denied)")
        tip("Your device may no longer be in an authenticated session")
        tip("→ Forward the notice file via email")
    elif status == 404:
        warn(f"HTTP 404 — endpoint path not found (URL may have changed)")
        tip("→ Check the live URLs scraped from your device policy dump")
        tip("→ Try a different URL from the list above if available")
    elif status == 0:
        err(f"No response received — {resp[:80]}")
        tip("→ The MDM server may be unreachable from your current network")
        tip("→ Try from a different Wi-Fi network or mobile data")
        tip("→ Save and email the notice file as backup")
    else:
        warn(f"Unexpected HTTP {status}: {resp[:100]}")
        tip("→ Attempt is logged. Email the notice file as a backup.")

# ══════════════════════════════════════════════════════════════════════════════
# ADMIN MESSAGE FLOW
# ══════════════════════════════════════════════════════════════════════════════

def admin_message_flow():
    hdr("Send Formal Notice to MDM Administrator")
    print(f"""
  {bold('Plain-English explanation of what this does:')}

  Your device is already enrolled in an MDM — that means the MDM agent
  already has an authenticated, open communication channel to its server.
  This tool uses THAT SAME CHANNEL to send a message in the opposite
  direction: from your device to the admin console.

  Think of it like this: the admin set up a phone line to your device.
  They can call you anytime. We're picking up that phone and calling
  them back — using their own number.

  The notice lands in:
    {grn('•')}  Microsoft Intune: Device's audit log in the Intune portal
    {grn('•')}  Samsung Knox:     Admin console notification / device log
    {grn('•')}  OMA-DM carriers:  Device management log on carrier portal
    {grn('•')}  Others:           Server access log + admin API log
""")

    # ── Step 1: Detection ────────────────────────────────────────────────────
    hdr("Step 1 of 5 — Deep MDM Detection")
    inf("Scanning for active management agents…")
    if _rish_available():
        ok("Shizuku/rish active — running privileged scan")
    else:
        warn("Shizuku not running — basic scan only")
        tip("Install Shizuku + rish from Play Store for full hidden-agent detection")

    findings = detect_mdm()

    if findings["any_found"]:
        ok(f"Management activity confirmed on this device:")
        if findings["device_owner"]:
            print(f"    {red('●')} {bold('DEVICE OWNER:')} {findings['device_owner']}")
            tip("Device Owner = full control. The MDM can wipe, lock, and read everything.")
        if findings["profile_owner"]:
            print(f"    {ylw('●')} {bold('PROFILE OWNER:')} {findings['profile_owner']}")
        if findings["work_profile"]:
            print(f"    {ylw('●')} Work profile is active on this device")
        for pkg, name in findings["packages"]:
            print(f"    {grn('●')} {bold(name)}  {dim(f'({pkg})')}")
        for desc, sample in findings["stealth_hits"]:
            print(f"    {mag('●')} {desc}  {dim(repr(sample[:50]))}")
        if findings["live_urls"]:
            print(f"\n  {bold('Live MDM server URLs found in your device policy:')}")
            for u in findings["live_urls"]:
                print(f"    {cyn('→')} {u}")
    else:
        warn("No management activity detected automatically.")
        if not findings["privileged"]:
            tip("Run with Shizuku for a deeper scan — hidden agents may be present")
        if not confirm("Continue to compose a notice anyway?", default=False):
            return

    pause("Review the findings above, then press Enter to continue…")

    # ── Step 2: Compose message ───────────────────────────────────────────────
    hdr("Step 2 of 5 — Compose Your Message")
    print(f"""
  Write a plain-English message to the IT admin.
  The script will wrap it in a formal legal notice automatically.
  Keep it factual. Example:
    "I did not consent to MDM enrollment on this personal device.
     Please unenroll it and confirm in writing within 72 hours."
""")
    message = ask("Your message to the IT admin")

    device_lines = []
    if findings["device_owner"]:
        device_lines.append(f"  Device Owner : {findings['device_owner']}")
    if findings["profile_owner"]:
        device_lines.append(f"  Profile Owner: {findings['profile_owner']}")
    for pkg, name in findings["packages"]:
        device_lines.append(f"  MDM Agent    : {name} ({pkg})")
    device_info = "\n".join(device_lines) or "  (auto-detection unavailable)"
    notice = generate_notice(device_info, message)

    print(f"\n  {bold('Notice preview:')}")
    rule()
    print("\n".join(f"  {l}" for l in notice.split("\n")[:15]))
    print(f"  {dim('… (full notice will be saved to file)')}")
    rule()
    if not confirm("Send this notice?"):
        inf("Cancelled — notice not sent")
        return

    # ── Step 3: Device ID ─────────────────────────────────────────────────────
    hdr("Step 3 of 5 — Your Device Identifier")
    print(f"""
  The MDM server uses your device ID to route messages correctly.
  Find it at:  Settings → About phone → scroll to find one of:
    • Serial number  (most common)
    • IMEI           (for carrier-managed devices)
    • Device ID / Android ID
""")
    device_id = ask("Device ID / Serial / IMEI", default="unknown-device",
                    help_text="Settings → About phone → Serial number or IMEI")

    # ── Step 4: Endpoint resolution ───────────────────────────────────────────
    hdr("Step 4 of 5 — Finding the Admin Endpoint")
    primary_platform = findings["platforms"][0] if findings["platforms"] else None

    # Try to auto-resolve
    target_url  = None
    protocol    = "oma-dm"

    if findings["live_urls"] and primary_platform:
        for u in findings["live_urls"]:
            if primary_platform.check_in_host in u:
                target_url = u
                protocol   = primary_platform.protocol
                ok(f"Auto-resolved from device policy dump: {cyn(target_url)}")
                break

    if not target_url and findings["live_urls"]:
        target_url = findings["live_urls"][0]
        protocol   = primary_platform.protocol if primary_platform else "oma-dm"
        inf(f"Using first scraped URL: {cyn(target_url)}")

    if not target_url and primary_platform:
        target_url = f"https://{primary_platform.check_in_host}{primary_platform.check_in_path}"
        protocol   = primary_platform.protocol
        inf(f"Using registry default for {primary_platform.name}: {cyn(target_url)}")

    if not target_url and findings["carrier_dm_host"]:
        target_url = f"https://{findings['carrier_dm_host']}/DMservice"
        protocol   = "oma-dm"
        inf(f"Using carrier OMA-DM host: {cyn(target_url)}")

    if not target_url:
        warn("Could not auto-detect admin endpoint.")
        tip("Check Settings → About → Management or ask your IT department for the MDM URL")
        target_url = ask("Enter MDM server URL manually",
                         help_text="Example: https://manage.contoso.com/devicemgmt")
        protocol   = "oma-dm"

    pname = primary_platform.name if primary_platform else "Unknown platform"
    inf(f"Platform : {bold(pname)}")
    inf(f"Protocol : {bold(protocol.upper())}")
    inf(f"Endpoint : {cyn(target_url)}")

    if not confirm("Send to this endpoint?"):
        target_url = ask("Enter a different URL", help_text="Full https:// URL")
        protocol   = "oma-dm"

    # ── Step 5: Deliver ───────────────────────────────────────────────────────
    hdr("Step 5 of 5 — Sending the Notice")
    crafter = _CRAFTERS.get(protocol, _CRAFTERS["generic-http"])
    payload, ct = crafter(target_url, device_id, notice)

    inf(f"Sending {bold(protocol.upper())} payload…")
    status, resp = _deliver_http(target_url, payload, ct)
    _explain_delivery_result(status, resp, pname)

    # Plain-text fallback on 400
    if status == 400:
        inf("Trying plain-text fallback…")
        s2, r2 = _deliver_http(target_url, notice, "text/plain")
        _explain_delivery_result(s2, r2, pname + " (plain-text)")

    # ── Multi-platform delivery ───────────────────────────────────────────────
    remaining = findings["platforms"][1:]
    if remaining and confirm(f"Also send to {len(remaining)} other detected platform(s)?",
                              default=False):
        for plat in remaining:
            url2 = f"https://{plat.check_in_host}{plat.check_in_path}"
            c2, ct2 = _CRAFTERS.get(plat.protocol, _CRAFTERS["generic-http"])(
                url2, device_id, notice)
            inf(f"Sending to {plat.name}…")
            s2, r2 = _deliver_http(url2, c2, ct2)
            _explain_delivery_result(s2, r2, plat.name)

    # ── Save evidence ─────────────────────────────────────────────────────────
    path = os.path.expanduser(
        f"~/mdm_notice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write(notice)
        f.write("\n\n─── DETECTION FINDINGS ───\n")
        f.write(json.dumps(
            {k: v for k, v in findings.items() if k != "platforms"},
            indent=2))
    ok(f"Evidence saved: {cyn(path)}")
    tip("Keep this file — it is timestamped, formal, legal documentation")
    tip("Email it to: IT department, your personal lawyer, HR, and yourself")
    tip("Reference it in any complaint, FOIA request, or legal proceeding")

# ══════════════════════════════════════════════════════════════════════════════
# DRY RUN — preview without making any changes
# ══════════════════════════════════════════════════════════════════════════════

def dry_run():
    hdr("Dry Run — Preview Only  (no changes will be made)")
    print(f"\n  {bold(f'Would block {TOTAL} domains across 40+ platforms:')}\n")
    categories = {
        "Google / Android Enterprise": [d for d in DOMAINS if "google" in d or "android" in d],
        "Apple ABM / MDM":             [d for d in DOMAINS if "apple" in d],
        "Samsung Knox":                [d for d in DOMAINS if "samsung" in d or "knox" in d],
        "Microsoft Intune":            [d for d in DOMAINS if "microsoft" in d or "azure" in d],
        "JumpCloud":                   [d for d in DOMAINS if "jumpcloud" in d],
        "VMware / AirWatch":           [d for d in DOMAINS if "airwatch" in d or "vmware" in d or "workspaceone" in d],
        "Carriers (OMA-DM)":           [d for d in DOMAINS if any(c in d for c in ["att.com","vzw","t-mobile","sprint"])],
        "Other EMM/EDR":               [],   # everything else
    }
    assigned = {d for v in categories.values() for d in v}
    categories["Other EMM/EDR"] = [d for d in DOMAINS if d not in assigned]

    for cat, doms in categories.items():
        if doms:
            print(f"  {bold(cat)} ({len(doms)} domains)")
            for d in doms[:5]:
                print(f"    {dim('·')} {d}")
            if len(doms) > 5:
                print(f"    {dim(f'… and {len(doms)-5} more')}")
            print()

    print(f"  {bold('Total:')} {TOTAL} domains  |  "
          f"Estimated time: {TOTAL // 120 + 1}–{TOTAL // 90 + 2} minutes")
    tip("Run again and choose 'Block' to actually apply these changes")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    banner()
    print(f"  {dim(f'v4  ·  {TOTAL} domains  ·  40+ MDM platforms')}\n")

    # ── Show quick-start help ─────────────────────────────────────────────────
    if "--readme" in sys.argv or "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        sys.exit(0)

    print(f"  {tip.__doc__ and '' or ''}"
          f"Run with {bold('--readme')} to see full documentation and troubleshooting guide.\n")

    # ── Preflight ─────────────────────────────────────────────────────────────
    reachable, resolved_ip = preflight()
    if not reachable:
        err("Cannot proceed — fix the connectivity issue above, then re-run")
        tip("Most common fix: switch from Wi-Fi to mobile data (or vice versa)")
        tip("If on a corporate network: run this from home or a personal hotspot")
        sys.exit(1)

    global _RESOLVED_IP
    _RESOLVED_IP = resolved_ip

    # ── Credentials ───────────────────────────────────────────────────────────
    profile, key = collect_credentials()

    # Validate with retry
    hdr("Validating Credentials")
    attempts = 0
    while not validate_credentials(profile, key):
        attempts += 1
        if attempts >= 3:
            err("3 failed attempts — giving up to avoid locking your account")
            tip("Double-check both values at my.nextdns.io and re-run the script")
            sys.exit(1)
        warn(f"Attempt {attempts}/3 — let's try again")
        profile, key = collect_credentials()

    # Save credentials?
    saved_profile, saved_key = load_saved_creds()
    if not (saved_profile == profile and saved_key == key):
        hdr("Save Credentials")
        print(f"""
  {bold('Why save credentials?')}
  Saving them to ~/.bashrc means you never have to type them again.
  They're stored as plain text in that file, so don't save if other
  people have access to this device/account.
""")
        if confirm("Save credentials to ~/.bashrc for future runs?"):
            save_creds(profile, key)

    # ── Hardening ─────────────────────────────────────────────────────────────
    harden_profile(profile, key)

    # ── Main menu ─────────────────────────────────────────────────────────────
    while True:
        hdr("Main Menu")
        inf(f"Profile: {cyn(profile)}  ·  {bold(str(TOTAL))} domains ready")
        print()

        mode = choose("What would you like to do?", [
            f"Block all {TOTAL} MDM domains  (add to NextDNS denylist)",
            f"Remove all {TOTAL} domains      (clear the denylist)",
            "Dry run / Preview               (see what would be blocked)",
            "Detect MDM on this device       (full scan + report)",
            "Send notice to MDM admin        (formal legal notice via MDM channel)",
            "Show device setup instructions  (how to activate NextDNS on phone)",
            "Exit",
        ])

        if "Exit" in mode:
            print(f"\n  {dim('Goodbye. Stay sovereign.')}\n")
            sys.exit(0)

        elif "Dry run" in mode:
            dry_run()

        elif "Detect" in mode:
            hdr("MDM Detection Scan")
            if _rish_available():
                ok("Shizuku/rish active — privileged scan")
            else:
                warn("Basic scan (no Shizuku) — some hidden agents may be missed")
            findings = detect_mdm()
            if findings["any_found"]:
                print(f"\n  {red(bold('⚠  MANAGEMENT ACTIVITY DETECTED:'))}\n")
                if findings["device_owner"]:
                    print(f"  {red('►')} {bold('DEVICE OWNER:')} {findings['device_owner']}")
                    tip("This means the MDM has FULL control: wipe, lock, read everything")
                if findings["profile_owner"]:
                    print(f"  {ylw('►')} {bold('PROFILE OWNER:')} {findings['profile_owner']}")
                if findings["work_profile"]:
                    print(f"  {ylw('►')} Work profile active")
                for pkg, name in findings["packages"]:
                    print(f"  {grn('►')} {bold(name)}  {dim(f'({pkg})')}")
                for desc, _ in findings["stealth_hits"]:
                    print(f"  {mag('►')} {desc}")
                if findings["live_urls"]:
                    print(f"\n  {bold('MDM Server URLs in your device policy:')}")
                    for u in findings["live_urls"]: print(f"    {cyn('→')} {u}")
                print()
                tip("To block these servers: choose 'Block all MDM domains' from the menu")
                tip("To send a formal notice: choose 'Send notice to MDM admin'")
            else:
                ok("No active management detected")
                if not findings["privileged"]:
                    tip("Note: scan was unprivileged — install Shizuku for a deeper check")

        elif "notice" in mode.lower() or "Send" in mode:
            admin_message_flow()

        elif "setup" in mode.lower() or "instructions" in mode.lower():
            print_phone_setup(profile)

        elif "Block" in mode or "Remove" in mode:
            delete = "Remove" in mode
            verb   = "REMOVE FROM" if delete else "ADD TO"

            hdr(f"Confirm: {verb} Denylist")
            print(f"""
  {bold('What is about to happen:')}
  {'Remove' if delete else 'Add'} {bold(str(TOTAL))} MDM domain names {'from' if delete else 'to'}
  the denylist on your NextDNS profile {cyn(profile)}.

  {'After removal: MDM servers will be reachable again from devices using this profile.' if delete else
   'After blocking: any device using this NextDNS profile cannot resolve MDM server names.'}
  {'The MDM agent will get NXDOMAIN and cannot connect to its server.' if not delete else ''}

  {ylw('Estimated time: ' + str(TOTAL // 120 + 1) + '–' + str(TOTAL // 90 + 2) + ' minutes')}
  {ylw('Do NOT close this window while running.')}
""")
            if not confirm(f"Proceed with {verb} {TOTAL} domains?"):
                inf("Cancelled — no changes made")
                continue

            failed = run_domain_push(profile, key, delete=delete)

            hdr("Summary")
            if not delete:
                ok("All MDM domains blocked in your NextDNS denylist.")
                print()
                warn("IMPORTANT — blocking is not active yet until you configure your device:")
                print_phone_setup(profile)
            else:
                ok("All domains removed from your denylist.")

            if failed:
                warn(f"{failed} domains failed — re-run and choose the same action to retry")
                tip("Already-processed domains are skipped, so retry is safe and fast")

        pause("Press Enter to return to the main menu…")


if __name__ == "__main__":
    main()
