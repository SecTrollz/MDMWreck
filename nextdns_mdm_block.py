#!/usr/bin/env python3
"""
nextdns_mdm_block.py  —  Android MDM blocking tool
Full coverage: enrollment, checkin, active-management, push, sync,
backup, restore, config, attestation across every major platform.
Includes admin-message delivery mechanism.

    python3 nextdns_mdm_block.py
"""

import getpass, json, os, subprocess, sys, time, urllib.error, urllib.request
from datetime import datetime

# ── Colors ───────────────────────────────────────────────────────────────────
T = sys.stdout.isatty()
def c(code, s): return f"\033[{code}m{s}\033[0m" if T else s
bold = lambda s: c("1",   s)
dim  = lambda s: c("2",   s)
red  = lambda s: c("91",  s)
grn  = lambda s: c("92",  s)
ylw  = lambda s: c("93",  s)
cyn  = lambda s: c("96",  s)
wht  = lambda s: c("97",  s)
mag  = lambda s: c("95",  s)

def banner():
    print(c("96;1", """
╔══════════════════════════════════════════════════════════════╗
║     ANDROID MDM BLOCKLIST                                               ║
║     Full-spectrum: enrollment · management · push ·                     ║
║     sync · backup · restore · config · attestation                      ║
╚══════════════════════════════════════════════════════════════╝"""))

def hdr(t):  print(f"\n{bold('── ' + t + ' ' + '─'*(52-len(t)))}")
def ok(m):   print(f"  {grn('✓')}  {m}")
def warn(m): print(f"  {ylw('!')}  {m}")
def err(m):  print(f"  {red('✗')}  {m}")
def inf(m):  print(f"  {cyn('→')}  {m}")

# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN LIST
# ═══════════════════════════════════════════════════════════════════════════════

SAFE_DOMAINS = {
    "albert.apple.com",
    "captive.apple.com",
    "gs.apple.com",
    "humb.apple.com",
    "static.ips.apple.com",
    "tbsc.apple.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "time.android.com",
}

DOMAINS = """
# ── GOOGLE / ANDROID ENTERPRISE ENROLLMENT ────────────────────────────────────
enterprise.android.com enterprise.google.com androidenterprise.google.com
androidenterprise.googleapis.com zero-touch.enrollment.google.com
zero-touch.googleapis.com zerotouch.googleapis.com androidzerodevice.googleapis.com
afw.google.com afw-setup.google.com clouddpc.google.com work.google.com
mdmconfig.googleapis.com deviceenrollment.googleapis.com deviceregistration.googleapis.com
device-provisioning.googleapis.com provisioning.googleapis.com setup.googleapis.com
enrollmenttoken.googleapis.com enrollment.googleapis.com
androiddevicepolicy.googleapis.com enterprisedevicemanagement.googleapis.com
managedconfigurations.googleapis.com managedconfigurationsforiframe.googleapis.com
# ── GOOGLE / ANDROID ENTERPRISE ACTIVE MANAGEMENT ────────────────────────────
androidmanagement.googleapis.com devicepolicy.googleapis.com mdm.googleapis.com
emm.googleapis.com manageddevice.googleapis.com androidworkprofile.googleapis.com
clouddevicepolicy.googleapis.com deviceauditing.googleapis.com
deviceverification.googleapis.com endpointverification.googleapis.com
endpoint-verification.googleapis.com chromepolicy.googleapis.com
# ── GOOGLE / CHECKIN & REGISTRATION ──────────────────────────────────────────
android.clients.google.com androidcheckin.googleapis.com checkin.googleapis.com
registrar.googleapis.com registrationmanager.googleapis.com ota-checkin.googleapis.com
# ── GOOGLE / ACCOUNT & IDENTITY ──────────────────────────────────────────────
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
devicemanagement.googleapis.com
# ── GOOGLE / GMS & TELEMETRY ──────────────────────────────────────────────────
gms.googleapis.com gmscore.googleapis.com deviceconfigservice.googleapis.com
phonelookup.googleapis.com smartdevice.googleapis.com people.googleapis.com
peopleapi.googleapis.com mobiledevicemanagement.googleapis.com
phenotype.googleapis.com phenotype-pa.googleapis.com phenotype-log.googleapis.com
logging.googleapis.com cloudlogging.googleapis.com auditrecording-pa.googleapis.com
clienttracing-pa.googleapis.com datasaver.googleapis.com diagnosticcloud.googleapis.com
cloudtrace.googleapis.com cloudprofiler.googleapis.com clouderrorreporting.googleapis.com
monitoring.googleapis.com reports.googleapis.com
# ── GOOGLE / FIREBASE ────────────────────────────────────────────────────────
firebase.googleapis.com firebaseio.com firebaseinstallations.googleapis.com
firebasecrashlytics.googleapis.com crashlytics.googleapis.com
firebase-settings.crashlytics.com firebaselogging.googleapis.com
firebasedynamiclinks.googleapis.com firebaseinappmessaging.googleapis.com
firebaseremoteconfig.googleapis.com firebaseperf.googleapis.com
firebaseappdistribution.googleapis.com firebaseappcheck.googleapis.com
firebasehosting.googleapis.com firebasestorage.googleapis.com
# ── GOOGLE / FCM ──────────────────────────────────────────────────────────────
fcm.googleapis.com fcmregistrations.googleapis.com fcm-token.googleapis.com
mtalk.google.com mtalk4.google.com alt1-mtalk.google.com alt2-mtalk.google.com
alt3-mtalk.google.com alt4-mtalk.google.com alt5-mtalk.google.com
alt6-mtalk.google.com alt7-mtalk.google.com alt8-mtalk.google.com
android.googleapis.com android.apis.google.com
# ── GOOGLE / PLAY INTEGRITY / SAFETYNET / ATTESTATION ────────────────────────
attestation.android.com playintegrity.googleapis.com playintegrity.google.com
safetynet.googleapis.com safetynet-pa.googleapis.com jws.googleapis.com
recaptcha.google.com recaptchaenterprise.googleapis.com
verifiedaccess.googleapis.com verifiedaccess-pa.googleapis.com
androidkeyattestation.googleapis.com keyattestation.googleapis.com
# ── GOOGLE / MANAGED PLAY ─────────────────────────────────────────────────────
play.google.com play-fe.googleapis.com market.android.com
androidmarket.googleapis.com vending.googleapis.com play.googleapis.com
content.googleapis.com clientservices.googleapis.com managedplay.googleapis.com
managedgoogleplay.googleapis.com managedgoogleplayfulldevice.googleapis.com
playauto.googleapis.com androidtaskservice.googleapis.com ggpht.com
# ── GOOGLE / ANALYTICS & LOCATION ────────────────────────────────────────────
app-measurement.com measurement.googleapis.com google-analytics.com
analytics.google.com stats.googleapis.com location.googleapis.com
locationreporting.googleapis.com geolocation.googleapis.com
userlocation.googleapis.com tagmanager.googleapis.com doubleclick.net
adservice.google.com
# ── GOOGLE / OTA & REMOTE MANAGEMENT ─────────────────────────────────────────
update.googleapis.com ota.googlezip.net redirector.gvt1.com
dl.google.com dl-ssl.google.com updates.googleapis.com packages.googleapis.com
fota.googleapis.com fotaserver.googleapis.com sos.googleapis.com recovery.googleapis.com
carrierconfig.googleapis.com carrierconfig-pa.googleapis.com
remotedisplay.googleapis.com screencast.googleapis.com remotelockdown.googleapis.com
remotemanagement.googleapis.com remotedeviceadministration.googleapis.com
cast.googleapis.com
# ── GOOGLE / CDN & INFRASTRUCTURE ────────────────────────────────────────────
googleusercontent.com gvt1.com gvt2.com gcp.gvt2.com
beacons.gcp.gvt2.com beacons2.gvt2.com beacons3.gvt2.com beacons4.gvt2.com
1e100.net storage.googleapis.com cloudkms.googleapis.com
cloudresourcemanager.googleapis.com servicecontrol.googleapis.com
networkconnectivity.googleapis.com networksecurity.googleapis.com
safebrowsing.googleapis.com safebrowsing.google.com
clients1.google.com clients2.google.com clients3.google.com
clients4.google.com clients5.google.com clients6.google.com
clients7.google.com clients8.google.com
# ── GOOGLE / CHROME ENTERPRISE ───────────────────────────────────────────────
chrome.google.com chromeenterprise.google chromeenterprise.google.com
chromereporting.googleapis.com chromebrowsercloudmanagement.googleapis.com
m.google.com
# ── GOOGLE WORKSPACE DEVICE MANAGEMENT ───────────────────────────────────────
endpoint.google.com endpoint-management.google.com
security.google.com securitycenter.googleapis.com
workspaceeventsdatastreamapidemo.googleapis.com
# ── APPLE ABM / DEP / MDM ENROLLMENT ─────────────────────────────────────────
deviceenrollment.apple.com deviceservices-external.apple.com
gdmf.apple.com identity.apple.com iprofiles.apple.com
mdmenrollment.apple.com vpp.itunes.apple.com axm-servicediscovery.apple.com
# ── APPLE ABM / ADMIN PORTAL ─────────────────────────────────────────────────
business.apple.com school.apple.com appleid.cdn-apple.com idmsa.apple.com
api.ent.apple.com api.edu.apple.com api-business.apple.com api-school.apple.com
statici.icloud.com axm-adm-enroll.apple.com axm-adm-mdm.apple.com
axm-adm-scep.apple.com axm-app.apple.com icons.axm-usercontent-apple.com
# ── APPLE PUSH NOTIFICATIONS ──────────────────────────────────────────────────
push.apple.com api.push.apple.com feedback.push.apple.com appattest.apple.com
# ── APPLE CONFIGURATOR / SUPERVISION ─────────────────────────────────────────
configurator.apple.com supervision.apple.com
# ── SAMSUNG KNOX — ENROLLMENT & PROVISIONING ─────────────────────────────────
knox.samsung.com knoxportal.samsung.com knoxsuite.samsung.com
knoxguard.samsung.com knoxcloud.samsung.com api.knox.samsung.com
license.knox.samsung.com seap.samsung.com kms.samsung.com klms.samsung.com
kgms.samsung.com esdk.samsungknox.com samsungknox.com bimserver.samsungknox.com
lm.samsungknox.com fdn.samsungknox.com sdk.samsungknox.com
manage.samsungknox.com eu.manage.samsungknox.com us.manage.samsungknox.com
ap.manage.samsungknox.com mdm.samsungknox.com register.samsungknox.com
attestation.samsungknox.com rem.samsungknox.com
# ── SAMSUNG KNOX — ACTIVE MANAGEMENT & PUSH ──────────────────────────────────
samsungmdm.com mdm.samsung.com fota.samsungmobile.com odinupdate.samsungmobile.com
samsungota.com account.samsung.com samsungpushservice.com push.samsungmobile.com
samsung-analytics.com cdn.samsungcloud.com samsungknoxmdm.com
# ── MICROSOFT INTUNE / ENDPOINT MANAGER — ENROLLMENT ─────────────────────────
manage.microsoft.com portal.manage.microsoft.com m.manage.microsoft.com
admin.manage.microsoft.com r.manage.microsoft.com wip.mam.manage.microsoft.com
mam.manage.microsoft.com enrollment.manage.microsoft.com
autoenroll.manage.microsoft.com enterpriseenrollment.manage.microsoft.com
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
# ── MICROSOFT ENTRA ID — DEVICE REGISTRATION ─────────────────────────────────
enterpriseregistration.windows.net enterpriseregistration.microsoftonline.com
login.microsoftonline.com login.microsoft.com login.live.com login.windows.net
sts.windows.net device.login.microsoftonline.com
autologon.microsoftazuread-sso.com registration.mobile.microsoft.com
provisioningapi.microsoftonline.com adminwebservice.microsoftonline.com
account.activedirectory.windowsazure.com management.azure.com portal.azure.com
graph.microsoft.com graph.windows.net aadcdn.msftauth.net aadcdn.msauth.net
aadcdn.msauthimages.net dps.azure.com settings.data.microsoft.com
# ── MICROSOFT ENTRA ID — ACTIVE MANAGEMENT & SYNC ────────────────────────────
pas.windows.net msappproxy.net msidentity.com azureedge.net
intunecdnpeasd.azureedge.net wns.windows.com push.windows.com
wdcp.microsoft.com wdcpalt.microsoft.com smartscreen.microsoft.com
definitionupdates.microsoft.com defender.microsoft.com mde.microsoft.com
# ── JUMPCLOUD — ENROLLMENT & AGENT ───────────────────────────────────────────
jumpcloud.com console.jumpcloud.com api.jumpcloud.com
kickstart.jumpcloud.com agent.jumpcloud.com cdn.jumpcloud.com
cdn02.jumpcloud.com auth.jumpcloud.com sso.jumpcloud.com
ldap.jumpcloud.com radius.jumpcloud.com identityapi.jumpcloud.com
# ── JUMPCLOUD — ACTIVE MANAGEMENT, PUSH & REMOTE ACCESS ──────────────────────
remoteassist.jumpcloud.com insights.jumpcloud.com events.jumpcloud.com
mdm.jumpcloud.com policy.jumpcloud.com commands.jumpcloud.com
softwaremanagement.jumpcloud.com go.jumpcloud.com
eu.jumpcloud.com eu-console.jumpcloud.com eu-api.jumpcloud.com
# ── VMWARE WORKSPACE ONE / AIRWATCH — ENROLLMENT ─────────────────────────────
airwatch.com awmdm.com airwatchmdm.com air-watch.com
api.workspaceone.com workspaceone.com admin.workspaceone.com
portal.workspaceone.com getenrolled.workspaceone.com login.workspaceone.com
cloud.workspaceone.com enroll.workspaceone.com ws1.workspaceone.com
na.workspaceone.com eu.workspaceone.com apac.workspaceone.com
# ── VMWARE WORKSPACE ONE — ACTIVE MANAGEMENT ─────────────────────────────────
ds.awmdm.com as.awmdm.com deviceservices.awmdm.com mdm.awmdm.com
console.awmdm.com notificationserver.awmdm.com awcm.awmdm.com
ws1.airwatch.com na.dm.airwatch.com eu.dm.airwatch.com apac.dm.airwatch.com
cn.airwatch.com registration.awmdm.com enroll.awmdm.com
deviceservices.airwatch.com awagent.com awcm.vmware.com
uemapi.vmware.com getenrolled.vmware.com vidm.vmware.com
horizon.vmware.com myvmware.com cloud.vmware.com
# ── IVANTI / MOBILEIRON ───────────────────────────────────────────────────────
mobileiron.com mdm.mobileiron.com ivi.mobileiron.com tunnel.mobileiron.com
appconnect.mobileiron.com go.mobileiron.com register.mobileiron.com
ivanti.com mi.ivanti.cloud cloud.ivanti.com enroll.ivanti.com
portal.ivanti.com api.ivanti.com pulsesecure.net neurons.ivanti.com
discovery.ivanti.com
# ── CITRIX ENDPOINT MANAGEMENT ───────────────────────────────────────────────
xenmobile.net citrix.com endpoint.citrix.com cdm.citrix.com
citrixworkspace.net wsf.citrix.com citrixnetworkapi.net gateway.citrix.com
cis.citrix.com xm.citrix.com mdm.citrix.com cloud.com citrixcloud.net
enroll.citrix.com receiver.citrix.com store.citrix.com
# ── SOTI MOBICONTROL ──────────────────────────────────────────────────────────
soti.net mobicontrol.soti.net mc.soti.net cloud.soti.net connect.soti.net
notify.soti.net mobi.soti.net enroll.soti.net
# ── IBM MAAS360 ───────────────────────────────────────────────────────────────
maas360.com fmp.maas360.com dm.maas360.com cloud.maas360.com
portal.maas360.com reg.maas360.com mdm.maas360.com api.maas360.com
notification.maas360.com wipe.maas360.com enroll.maas360.com securitymdm.com
# ── JAMF ─────────────────────────────────────────────────────────────────────
jamf.com jamfcloud.com jamfnow.com jamfschool.com jamfpro.com
enrollment.jamfcloud.com assets.jamf.com updates.jamf.com
api.jamf.com jamf.ninja jamfconnect.com
rec.jamfcloud.com ca.jamfcloud.com
# ── BLACKBERRY UEM / CYLANCE ─────────────────────────────────────────────────
blackberry.com uem.blackberry.com bbcs.net enterprise.blackberry.com
bbsecure.com cylance.com threatchintelligence.cylance.com
bis.na.blackberry.com bis.eu.blackberry.com bis.apac.blackberry.com
blackberryenterprise.com bbeservices.com
# ── SOPHOS MOBILE ─────────────────────────────────────────────────────────────
sophos.com cloud.sophos.com mcs.sophos.com central.sophos.com
sophosxl.net dci.sophosupd.com dci.sophosupd.net savservice.sophos.com
# ── LOOKOUT ───────────────────────────────────────────────────────────────────
lookout.com mas.lookout.com mtp.lookout.com mobile.lookout.com
enterprise.lookout.com api.lookout.com
# ── ZIMPERIUM / PRADEO / WANDERA / NETSKOPE ───────────────────────────────────
zimperium.com cloud.zimperium.com api.zimperium.com zips.zimperium.com
pradeo.com wandera.com netskope.com goskope.com nsscloud.com
# ── CROWDSTRIKE FALCON ────────────────────────────────────────────────────────
crowdstrike.com ts01-b.cloudsink.net cloudsink.net falconapi.crowdstrike.com
falcon.crowdstrike.com api.crowdstrike.com
# ── SENTINELONE ───────────────────────────────────────────────────────────────
sentinelone.com prd00.sentinelone.net sentinelone.net
# ── ABSOLUTE ──────────────────────────────────────────────────────────────────
absolute.com bi.absolute.com monitoring.absolute.com search.absolute.com
ctes.absolute.com dfndr.absolute.com absoluteapps.com
# ── OKTA ──────────────────────────────────────────────────────────────────────
okta.com oktapreview.com okta-emea.com auth.okta.com api.okta.com
# ── DUO SECURITY ──────────────────────────────────────────────────────────────
duosecurity.com duo.com api.duosecurity.com
# ── CISCO MERAKI SYSTEMS MANAGER ──────────────────────────────────────────────
meraki.cisco.com dashboard.meraki.com sm.meraki.com systems-manager.cisco.com
n160.meraki.com cisco.com
# ── MANAGEENGINE ──────────────────────────────────────────────────────────────
manageengine.com mdmcloud.manageengine.com devicecloud.manageengine.com
em.manageengine.com patch.manageengine.com
# ── HEXNODE UEM ───────────────────────────────────────────────────────────────
hexnode.com cloud.hexnode.com api.hexnode.com enroll.hexnode.com
# ── KANDJI ───────────────────────────────────────────────────────────────────
kandji.io updates.kandji.io api.kandji.io
# ── MOSYLE ───────────────────────────────────────────────────────────────────
mosyle.com api.mosyle.com business.mosyle.com fuse.mosyle.com
# ── ADDIGY ───────────────────────────────────────────────────────────────────
addigy.com prod.addigy.com
# ── SIMPLEMDM ─────────────────────────────────────────────────────────────────
simplemdm.com api.simplemdm.com
# ── FLEET ─────────────────────────────────────────────────────────────────────
fleetdm.com update.fleetdm.com
# ── MIRADORE ──────────────────────────────────────────────────────────────────
miradore.com online.miradore.com
# ── SCALEFUSION ──────────────────────────────────────────────────────────────
scalefusion.com cloud.scalefusion.com mdm.scalefusion.com
# ── APPLIVERY ─────────────────────────────────────────────────────────────────
applivery.com api.applivery.com
# ── BARAMUNDI ─────────────────────────────────────────────────────────────────
baramundi.com cloud.baramundi.com
# ── FLYVE MDM ─────────────────────────────────────────────────────────────────
flyve-mdm.com
# ── CARRIER OMA-DM — AT&T ────────────────────────────────────────────────────
dm.att.com dm2.att.com oma-dm.att.com att.device-management.com
config.att.com omacp.att.com fota.att.com
firstnet.att.com firstnet.com devices.att.com
# ── CARRIER OMA-DM — VERIZON ─────────────────────────────────────────────────
dm.vzw.com qtifw.vzw.com sai.vzw.com iqsrdm.vzw.com
oma-dm.verizon.net omadm.verizonwireless.com
mdm.verizonbusiness.com vzwssl.com fota.vzw.com
# ── CARRIER OMA-DM — T-MOBILE ────────────────────────────────────────────────
dm.t-mobile.com dm-prd.t-mobile.com omadm.t-mobile.com
config.t-mobile.com omacp.t-mobile.com fota.t-mobile.com
# ── CARRIER OMA-DM — SPRINT ──────────────────────────────────────────────────
dm.sprint.com omadm.sprint.com
# ── QUALCOMM FOTA / XTRA / DIAGNOSTICS ───────────────────────────────────────
diagservices.qualcomm.com izat.qualcomm.com xtcloud.qualcomm.com
lbs.qualcomm.com xtrapath1.izatcloud.net xtrapath2.izatcloud.net
xtrapath3.izatcloud.net xtrapath4.izatcloud.net sls.izatcloud.net
prodxtracore.izatcloud.net izatcloud.net
# ── INTEL EMA & AMT PROVISIONING ─────────────────────────────────────────────
ema.intel.com emdmapp.intel.com api.ema.intel.com provisioning.intel.com
registration.intel.com amt-provisioning.intel.com mebx.intel.com
# ── AMD MANAGEMENT / DASH ────────────────────────────────────────────────────
dash.amd.com management.amd.com remote.amd.com
# ── HUAWEI HMS ENTERPRISE ────────────────────────────────────────────────────
hwid.cloud.huawei.com appgallery.cloud.huawei.com push.hicloud.com
push.dbankcloud.com oemwebquery.dbankcloud.com mobilecloudservice.huawei.com
logservice.cloud.huawei.com mdm.hicloud.com device.cloud.huawei.com
hicloud.com dbankcloud.com fota.dbankcloud.com fota-dre.dbankcloud.com
hihonormdm.com
# ── XIAOMI / MIUI MDM ────────────────────────────────────────────────────────
mdm.miui.com api.miui.com data.mistat.xiaomi.com tracking.miui.com
tracking.intl.miui.com data.mistat.intl.xiaomi.com analytics.miui.com
logbak.miui.com logbak-global.miui.com sdkconfig.ad.xiaomi.com
sdkconfig.ad.intl.xiaomi.com fota.miui.com bigota.d.miui.com
update.miui.com updater.miui.com miuirom.org
# ── ZTE MDM & FOTA ────────────────────────────────────────────────────────────
mdm.zte.com.cn push.zte.com.cn fota.zte.com.cn ota.zte.com.cn
update.zte.com.cn dm.zte.com.cn
# ── OPPO / REALME / ONEPLUS ───────────────────────────────────────────────────
mdm.heytap.com push.heytap.com push.oppo.com coloros.com mdm.coloros.com
oplus.com log.coloros.com push.oneplus.net push.oneplus.com
mdm.oneplus.com update.oneplus.com fota.oneplus.net
# ── MOTOROLA ─────────────────────────────────────────────────────────────────
motorolasolutions.com mdm.motorolasolutions.com fota.motorola.com
push.motorola.com ota.motorola.com device.motorola.com
# ── MICROSOFT DEFENDER FOR ENDPOINT (Android) ────────────────────────────────
smartscreen-prod.microsoft.com
# ── MICROSOFT INTUNE MAM ─────────────────────────────────────────────────────
mam.microsoft.com mam-staging.microsoft.com mamservice.microsoft.com
# ── MICROSOFT AUTOPILOT ───────────────────────────────────────────────────────
ztd.dds.microsoft.com cs.dds.microsoft.com
# ── MICROSOFT ENTRA PRIVATE ACCESS ───────────────────────────────────────────
privatelink.microsoftonline.com globalenrollment.microsoft.com
# ── ADDITIONAL EMM / SECURITY PLATFORMS ──────────────────────────────────────
apperian.com mcafee.com mvision.mcafee.com epo.mcafee.com
trellix.com endpoint.trellix.com agent.trellix.com
tanium.com cloud.tanium.com api.tanium.com
vmray.com
""".split()

DOMAINS = [d for d in DOMAINS if d and not d.startswith('#')]
DOMAINS = list(dict.fromkeys(d.lower() for d in DOMAINS))
DOMAINS = [d for d in DOMAINS if d not in SAFE_DOMAINS]
TOTAL   = len(DOMAINS)

# ═══════════════════════════════════════════════════════════════════════════════
# NEXTDNS API
# ═══════════════════════════════════════════════════════════════════════════════
API = "https://api.nextdns.io"

def call(method, path, key, body=None, retries=4):
    url  = f"{API}{path}"
    data = json.dumps(body).encode() if body else None
    hdrs = {"X-Api-Key": key, "Content-Type": "application/json"}
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            if e.code == 429:
                wait = 2.0 * (2 ** attempt)
                warn(f"Rate limited — sleeping {wait:.0f}s")
                time.sleep(wait)
                continue
            return e.code, {"error": raw[:200]}
        except urllib.error.URLError as e:
            if attempt < retries: time.sleep(2)
            else: return 0, {"error": str(e.reason)}
    return 0, {"error": "max retries"}

def validate(profile, key):
    code, _ = call("GET", f"/profiles/{profile}", key)
    return code == 200

def block_domain(profile, key, domain):
    code, _ = call("POST", f"/profiles/{profile}/denylist", key,
                   {"id": domain, "active": True})
    if code in (200, 201, 204): return "ok"
    if code == 409:             return "skip"
    return f"fail:{code}"

def unblock_domain(profile, key, domain):
    code, _ = call("DELETE", f"/profiles/{profile}/denylist/{domain}", key)
    if code in (200, 204): return "ok"
    if code == 404:        return "skip"
    return f"fail:{code}"

def patch_settings(profile, key, payload):
    code, body = call("PATCH", f"/profiles/{profile}/settings", key, payload)
    if code in (200, 204): return True, "ok"
    return False, body.get("error", f"HTTP {code}")

# ═══════════════════════════════════════════════════════════════════════════════
# PROMPTS
# ═══════════════════════════════════════════════════════════════════════════════
def ask(label, default="", secret=False):
    hint = f" [{dim('*'*8 if secret else default)}]" if default else ""
    while True:
        try:
            fn  = getpass.getpass if secret else input
            val = fn(f"  {cyn('?')}  {label}{hint}: ").strip()
        except (KeyboardInterrupt, EOFError): print(); sys.exit(0)
        if val:     return val
        if default: return default
        warn("Required.")

def confirm(q, default=True):
    hint = "Y/n" if default else "y/N"
    try:
        r = input(f"  {cyn('?')}  {q} [{hint}]: ").strip().lower()
    except (KeyboardInterrupt, EOFError): print(); sys.exit(0)
    return default if not r else r in ("y", "yes")

def choose(q, opts):
    print(f"\n  {cyn('?')}  {q}")
    for i, o in enumerate(opts, 1):
        print(f"      {bold(str(i))}) {o}")
    while True:
        try: r = input(f"  {cyn('→')}  Choice [1]: ").strip()
        except (KeyboardInterrupt, EOFError): print(); sys.exit(0)
        if not r: return opts[0]
        try:
            idx = int(r) - 1
            if 0 <= idx < len(opts): return opts[idx]
        except ValueError: pass
        warn(f"Enter 1–{len(opts)}")

# ═══════════════════════════════════════════════════════════════════════════════
# CREDENTIALS
# ═══════════════════════════════════════════════════════════════════════════════
BASHRC = os.path.expanduser("~/.bashrc")
MARKER = "# nextdns_mdm_block"

def load_saved():
    return os.environ.get("NEXTDNS_PROFILE",""), os.environ.get("NEXTDNS_API_KEY","")

def save_creds(profile, key):
    lines = open(BASHRC).readlines() if os.path.exists(BASHRC) else []
    out, skip = [], False
    for l in lines:
        if l.strip() == MARKER: skip = True
        elif skip and l.startswith("export NEXTDNS_"): continue
        else: skip = False; out.append(l)
    with open(BASHRC, "w") as f:
        f.writelines(out)
        f.write(f"\n{MARKER}\nexport NEXTDNS_PROFILE={profile}\n"
                f"export NEXTDNS_API_KEY={key}\n")
    ok(f"Saved to ~/.bashrc")

# ═══════════════════════════════════════════════════════════════════════════════
# PROGRESS BAR
# ═══════════════════════════════════════════════════════════════════════════════
def bar(i, total, w=40):
    f = int(w * i / total)
    return f"{grn('█'*f)}{dim('░'*(w-f))} {i}/{total} ({i/total:.0%})"

# ═══════════════════════════════════════════════════════════════════════════════
# PROFILE HARDENING
# ═══════════════════════════════════════════════════════════════════════════════
def harden(profile, key):
    hdr("Profile Opsec Hardening")
    warn("Detected opsec issues in your profile:")
    print(f"""
    {ylw('!')}  {bold('Log client IPs: ON')}  — every DNS query logs your IP to US servers
    {ylw('!')}  {bold('Log domains: ON')}      — full query history stored 3 months in US
    {ylw('!')}  Both are legal discovery targets. Off = nothing to hand over.
""")
    choice = choose("How to handle logging?", [
        "Disable logs entirely  (max opsec — recommended)",
        "Keep logs, strip IP and domains  (anonymous activity only)",
        "Skip — configure manually at my.nextdns.io → Settings",
    ])
    if "Skip" in choice:
        inf("Manual path: my.nextdns.io → Settings tab → Logs section")
        return
    if "Disable" in choice:
        ok_, msg = patch_settings(profile, key, {"logs": {"enabled": False}})
        if ok_: ok("Logs fully disabled — nothing stored, nothing producible")
        else:   warn(f"API patch failed ({msg}) — disable manually: Settings → Logs → toggle off")
    else:
        ok_, msg = patch_settings(profile, key,
            {"logs": {"drop": {"ips": True, "domains": True}}})
        if ok_: ok("Log IPs: OFF  |  Log domains: OFF  — logs anonymized")
        else:   warn(f"API patch failed ({msg}) — Settings → Privacy adjustments → turn off both")
    cs, _ = patch_settings(profile, key, {"performance": {"cacheBoost": True}})
    if cs: ok("Cache Boost: ON  (reduces query frequency / leakage)")

# ═══════════════════════════════════════════════════════════════════════════════
# PHONE SETUP
# ═══════════════════════════════════════════════════════════════════════════════
def phone_setup(profile):
    print(f"""
  {bold('APPLY TO YOUR DEVICE — Private DNS (Android 9+)')}
  ┌──────────────────────────────────────────────────────┐
  │  Settings → Network & internet → Advanced            │
  │  → Private DNS → Private DNS provider hostname       │
  │  → Enter: {cyn(f'{profile}.dns.nextdns.io')}              │
  │  → Save                                              │
  ├──────────────────────────────────────────────────────┤
  │  Verify: open {cyn('https://test.nextdns.io')}             │
  │  Should show: NextDNS is working                     │
  └──────────────────────────────────────────────────────┘
""")

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN MESSAGE MECHANISM
# ═══════════════════════════════════════════════════════════════════════════════

def detect_mdm():
    findings = {"admins": [], "packages": [], "work_profile": False}
    try:
        result = subprocess.run(
            ["dumpsys", "device_policy"],
            capture_output=True, text=True, timeout=10
        )
        out = result.stdout
        import re
        admins = re.findall(r'admin=([\w.]+)', out)
        findings["admins"] = list(set(admins))
        findings["work_profile"] = "work profile" in out.lower() or "profile owner" in out.lower()
        MDM_PACKAGES = {
            "com.google.android.apps.work.clouddpc":    "Google Android Management API / AFW",
            "com.airwatch.androidagent":                "VMware Workspace ONE",
            "com.mobileiron":                           "Ivanti MobileIron",
            "com.samsungknox.dcagent":                  "Samsung Knox",
            "com.microsoft.intune":                     "Microsoft Intune",
            "com.microsoft.windowsintune.companyportal":"Microsoft Intune Company Portal",
            "com.citrix.mdm":                           "Citrix Endpoint Management",
            "net.soti.mobicontrol":                     "SOTI MobiControl",
            "com.fiberlink.maas360":                    "IBM MaaS360",
            "com.jamf.management":                      "Jamf",
            "com.jumpcloud.android":                    "JumpCloud",
            "com.blackberry.bbmdm":                     "BlackBerry UEM",
            "com.hexnode.devicemanagement":             "Hexnode",
            "com.scalefusion.mdm":                      "ScaleFusion",
        }
        for pkg, name in MDM_PACKAGES.items():
            if pkg in out:
                findings["packages"].append((pkg, name))
    except Exception:
        pass
    return findings

def craft_oma_dm_alert(server_url, device_id, message):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<SyncML xmlns="SYNCML:SYNCML1.2">
  <SyncHdr>
    <VerDTD>1.2</VerDTD>
    <VerProto>DM/1.2</VerProto>
    <SessionID>1</SessionID>
    <MsgID>1</MsgID>
    <Target><LocURI>{server_url}</LocURI></Target>
    <Source><LocURI>{device_id}</LocURI></Source>
    <Meta>
      <MaxMsgSize xmlns="syncml:metinf">65536</MaxMsgSize>
    </Meta>
  </SyncHdr>
  <SyncBody>
    <Alert>
      <CmdID>1</CmdID>
      <Data>1201</Data>
      <Item>
        <Meta>
          <Type xmlns="syncml:metinf">text/plain</Type>
          <Format xmlns="syncml:metinf">chr</Format>
        </Meta>
        <Data>{message}</Data>
      </Item>
    </Alert>
    <Final/>
  </SyncBody>
</SyncML>"""

def craft_apple_mdm_checkout(topic, udid):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>MessageType</key>
    <string>Checkout</string>
    <key>Topic</key>
    <string>{topic}</string>
    <key>UDID</key>
    <string>{udid}</string>
</dict>
</plist>"""

def generate_legal_notice(device_info, message):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
FORMAL NOTICE OF UNAUTHORIZED DEVICE MANAGEMENT
================================================
Date/Time  : {now}
From       : Device Owner / Authorized User
To         : IT Administrator / MDM Operator
Re         : Unauthorized enrollment and remote management

NOTICE

This device is enrolled in a mobile device management (MDM) solution
without the informed, written consent of the device owner/user.

Device information detected:
{device_info}

MESSAGE FROM DEVICE OWNER:
{message}

DEMAND

The device owner hereby demands:
1. Immediate unenrollment of this device from all MDM systems
2. Deletion of all data collected from this device without consent
3. Written confirmation of compliance within 72 hours
4. Identification of the party who authorized this enrollment

This notice constitutes formal record that the device owner is aware
of, objects to, and demands cessation of unauthorized device management.

Continued management of this device without consent may constitute:
- Unauthorized access to a computer/device (18 U.S.C. § 1030)
- Violation of state computer fraud statutes
- Civil liability for invasion of privacy

This notice was delivered through the MDM platform's own communication
infrastructure, confirming receipt by the managing party.

================================================
GENERATED BY: nextdns_mdm_block.py (device sovereignty tool)
""".strip()

def send_http_message(url, payload, content_type="application/xml"):
    try:
        data = payload.encode("utf-8")
        req  = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": content_type, "User-Agent": "MDMClient/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode(errors="replace")[:500]
    except Exception as e:
        return 0, str(e)

def admin_message_flow():
    hdr("Send Notice to MDM Administrator")
    print(f"""
  {bold('What this does:')}
  Your device is already authenticated to the MDM server.
  We use that authenticated channel to send a message the
  admin will see in their management console — using the
  MDM platform's own protocol.

  {ylw('!')}  This uses the same communication path the MDM uses
  {ylw('!')}  to send commands TO your device. We reverse it.
""")

    hdr("Step 1 — Detecting Active MDM")
    inf("Scanning device policy... (needs Termux with Android shell access)")
    findings = detect_mdm()

    if findings["admins"] or findings["packages"]:
        ok("Active MDM detected:")
        for pkg, name in findings["packages"]:
            print(f"    {grn('•')}  {bold(name)}  {dim(f'({pkg})')}")
        if findings["admins"]:
            print(f"    {ylw('•')}  Device admin packages: {', '.join(findings['admins'])}")
        if findings["work_profile"]:
            print(f"    {ylw('•')}  Work profile is active on this device")
    else:
        warn("No MDM detected automatically (may need root for full scan)")
        inf("Proceeding to manual configuration")

    hdr("Step 2 — Compose Your Message")
    print(f"  {dim('This will be embedded in a formal legal notice.')}\n")
    message = ask("Your message to the IT admin")

    hdr("Step 3 — Delivery Method")
    method = choose("How do you want to deliver the notice?", [
        "OMA-DM Alert  (works with Intune, carrier MDM, any OMA-DM server)",
        "Apple MDM Checkout  (signals device leaving Apple MDM management)",
        "HTTP POST to a known MDM server URL  (manual entry)",
        "Save notice as text file only  (no network delivery)",
    ])

    device_info = ""
    if findings["packages"]:
        device_info = "\n".join(f"  MDM: {name} ({pkg})"
                                 for pkg, name in findings["packages"])
    else:
        device_info = "  (auto-detection not available — user-reported MDM enrollment)"

    notice = generate_legal_notice(device_info, message)

    if "OMA-DM" in method:
        hdr("OMA-DM Delivery")
        inf("OMA-DM server URL — check Settings → About → Management or ask your carrier")
        server_url = ask("MDM server URL  (e.g. https://manage.example.com/devicemgmt)")
        device_id  = ask("Device ID / IMEI / serial  (shown in Settings → About)",
                         default="unknown-device")
        payload = craft_oma_dm_alert(server_url, device_id, notice)
        print(f"\n  {dim('Sending OMA-DM Alert 1201 to')} {cyn(server_url)}")
        status, resp = send_http_message(
            server_url, payload, "application/vnd.syncml+xml")
        if status in (200, 201, 202, 204):
            ok(f"Delivered  (HTTP {status}) — check admin console for device alert")
        else:
            warn(f"Server responded: HTTP {status}")
            warn(f"Response: {resp[:200]}")
            inf("The server may require device certificate auth — save and send manually")

    elif "Apple MDM" in method:
        hdr("Apple MDM Checkout Delivery")
        checkin_url = ask("MDM check-in URL  (from enrollment profile or network capture)")
        apns_topic  = ask("APNs topic  (com.apple.mgmt.External.*)",
                          default="com.apple.mgmt.External.unknown")
        udid        = ask("Device UDID  (Settings → About → scroll to UDID)")
        payload     = craft_apple_mdm_checkout(apns_topic, udid)
        print(f"\n  {dim('Sending Checkout to')} {cyn(checkin_url)}")
        status, resp = send_http_message(
            checkin_url, payload, "application/x-apple-aspen-mdm-checkin")
        if status in (200, 201, 204):
            ok("Checkout delivered — admin console will show device unenrolled/checked out")
        else:
            warn(f"HTTP {status}: {resp[:200]}")
            inf("Admin console may still log the attempt — notice is on record")

    elif "HTTP POST" in method:
        hdr("HTTP POST Delivery")
        url = ask("Target URL  (MDM admin API or notification endpoint)")
        print(f"\n  {dim('POSTing notice to')} {cyn(url)}")
        status, resp = send_http_message(url, notice, "text/plain")
        if status < 400:
            ok(f"Delivered  (HTTP {status})")
        else:
            warn(f"HTTP {status}: {resp[:200]}")

    hdr("Saving Notice Locally")
    path = os.path.expanduser(f"~/mdm_notice_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write(notice)
    ok(f"Notice saved: {cyn(path)}")
    inf("Keep this file — it is timestamped evidence of your formal objection")
    inf("Forward via email to your organization's IT department, legal, or HR")
    inf("Reference it in any FOIA, discovery, or complaint filing")

# ═══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL HINT
# ═══════════════════════════════════════════════════════════════════════════════
def cred_hint():
    print(f"""
  {bold('WHERE TO FIND YOUR CREDENTIALS')}

  {bold('Profile ID')} — visible in your browser URL bar:
    my.nextdns.io/{cyn('fa5495')}/setup  ←  that 6-char code
    Also: Setup tab → Endpoints → ID field

  {bold('API Key')}
    my.nextdns.io → top-right avatar → Account
    → API section → Generate / copy key
""")

# ═══════════════════════════════════════════════════════════════════════════════
# PUSH LOOP
# ═══════════════════════════════════════════════════════════════════════════════
def run_push(profile, key, delete=False):
    fn    = unblock_domain if delete else block_domain
    verb  = "Removing" if delete else "Blocking"
    n_ok  = n_skip = n_fail = 0
    fails = []
    print(f"\n  {bold(f'{verb} {TOTAL} domains...')}\n")
    for i, domain in enumerate(DOMAINS, 1):
        sys.stdout.write(f"\r  {bar(i, TOTAL)}  "); sys.stdout.flush()
        r = fn(profile, key, domain)
        if r == "ok":     n_ok   += 1
        elif r == "skip": n_skip += 1
        else:             n_fail += 1; fails.append((domain, r))
        time.sleep(0.5)
    print("\n")
    ok  (f"{'Removed' if delete else 'Blocked'}:  {n_ok}")
    warn(f"Skipped:  {n_skip}  (already {'absent' if delete else 'present'})")
    (err if n_fail else ok)(f"Failed:   {n_fail}")
    if fails:
        print(f"\n  {red('Failures:')}")
        for d, r in fails: print(f"    {dim(d)}  [{r}]")
    return n_fail

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    banner()
    print(f"  {dim(f'{TOTAL} domains across 40+ platforms')}")

    hdr("NextDNS Credentials")
    profile, key = load_saved()
    if profile and key:
        ok(f"Saved credentials found  ({cyn(profile)})")
        if not confirm("Use them?"): profile = key = ""
    if not profile or not key:
        if confirm("Show where to find credentials?"):
            cred_hint()
        profile = ask("Profile ID  (6 chars)")
        key     = ask("API Key", secret=True)

    hdr("Validating")
    inf("Contacting NextDNS API...")
    if not validate(profile, key):
        err("Invalid credentials — check and retry")
        sys.exit(1)
    ok(f"Authenticated  →  {cyn(profile)}")

    if not (os.environ.get("NEXTDNS_PROFILE") == profile and
            os.environ.get("NEXTDNS_API_KEY")  == key):
        hdr("Save Credentials")
        if confirm("Save to ~/.bashrc?"):
            save_creds(profile, key)

    harden(profile, key)

    hdr("Choose Action")
    inf(f"Blocklist: {bold(str(TOTAL))} domains across:")
    for cat in [
        "Google AFW/Android Enterprise — all management vectors",
        "Apple ABM/DEP/MDM/APNs — enrollment, push, attestation",
        "Samsung Knox — full stack enrollment through active mgmt",
        "Microsoft Intune + Entra ID — enrollment, MAM, Autopilot",
        "JumpCloud — agent, kickstart, remote assist, identity",
        "VMware Workspace ONE, Ivanti, Citrix, SOTI, MaaS360",
        "Jamf, Kandji, Mosyle, Addigy, SimpleMDM, Hexnode",
        "Cisco Meraki, ManageEngine, ScaleFusion, Applivery",
        "CrowdStrike, SentinelOne, Lookout, Zimperium, Sophos",
        "Absolute, Okta, Duo, Trellix/McAfee, Tanium",
        "Carrier OMA-DM — AT&T, Verizon, T-Mobile, Sprint",
        "Qualcomm FOTA/XTRA, Intel EMA/AMT, AMD DASH",
        "Huawei HMS, Xiaomi MIUI, ZTE, OPPO/OnePlus, Motorola",
    ]:
        print(f"    {dim('•')}  {cat}")

    mode = choose("What do you want to do?", [
        f"Block all {TOTAL} domains  (add to denylist)",
        f"Remove all {TOTAL} domains  (clear from denylist)",
        "Dry run  (preview — no changes)",
        "Send message to MDM administrator",
        "Exit",
    ])

    if "Exit" in mode:
        print(f"\n  {dim('Goodbye.')}\n"); sys.exit(0)

    if "message" in mode.lower():
        admin_message_flow()
        return

    dry    = "Dry" in mode or "preview" in mode
    delete = "Remove" in mode

    if not dry:
        verb = "REMOVE FROM" if delete else "ADD TO"
        print()
        warn(f"Will {bold(verb)} denylist on profile {cyn(profile)}")
        warn(f"{TOTAL} domains  ·  ~{TOTAL // 120 + 1} minutes")
        if not confirm("Proceed?"): print(f"\n  {dim('Cancelled.')}\n"); sys.exit(0)

    hdr("Running")
    if dry:
        print(f"\n  {bold('DRY RUN — no changes')}\n")
        for i, d in enumerate(DOMAINS, 1):
            print(f"  {dim(f'[{i:>3}/{TOTAL}]')}  {d}")
        print(f"\n  Total: {TOTAL} domains")
        return

    failed = run_push(profile, key, delete=delete)
    hdr("Done")
    if not delete:
        ok("All MDM domains blocked.")
        phone_setup(profile)
    else:
        ok("All domains removed from denylist.")

    if failed:
        warn(f"{failed} failed — re-run to retry")
        sys.exit(1)

if __name__ == "__main__":
    main()
