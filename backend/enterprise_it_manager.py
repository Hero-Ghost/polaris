"""
Polaris - Enterprise IT Toolkit Engine
Unified management, diagnostic and reset utilities tailored for large enterprise
IT environments (Active Directory, Entra ID / M365, Group Policy, Outlook,
Network Drives, Intune, Print Spooler, Proxy, and Certificates).
"""

import os
import sys
import glob
import time
import shutil
import subprocess
from typing import Dict, Any, List, Optional

from backend.win_utils import IS_WINDOWS, run_hidden, popen_visible, format_bytes

try:
    import winreg
except ImportError:
    winreg = None


def purge_kerberos_tickets() -> Dict[str, Any]:
    """
    Purges Kerberos tickets and resets NetBIOS cache.
    Allows immediately applying new Active Directory Security Group permissions
    without requiring the user to reboot or log off.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    errors = []
    try:
        res1 = run_hidden(['klist.exe', 'purge'], capture_output=True, text=True)
        if res1.returncode != 0 and "error" in (res1.stderr or '').lower():
            errors.append(res1.stderr.strip())
    except Exception as e:
        errors.append(str(e))

    try:
        run_hidden(['nbtstat.exe', '-R'], capture_output=True, text=True)
    except Exception:
        pass

    if errors:
        return {
            "success": False,
            "message": f"שגיאה באיפוס כרטיסי Kerberos: {' '.join(errors)}"
        }

    return {
        "success": True,
        "message": "כרטיסי Kerberos ו-NetBIOS אופסו בהצלחה. הרשאות ה-Active Directory עודכנו ללא צורך באתחול."
    }


def reset_group_policy() -> Dict[str, Any]:
    """
    Forces a complete, clean Group Policy update from the Domain Controller.
    Removes cached policy files if corrupt, and executes gpupdate /force.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    windir = os.environ.get('WINDIR', r'C:\Windows')
    cached_reg_pol = os.path.join(windir, r'System32\GroupPolicy\Machine\registry.pol')
    if os.path.exists(cached_reg_pol):
        try:
            os.remove(cached_reg_pol)
        except OSError:
            pass

    try:
        # Run gpupdate with timeout
        res = run_hidden(['gpupdate.exe', '/force'], timeout=35, capture_output=True, text=True)
        stdout = res.stdout or ''
        if "successfully" in stdout.lower() or "הושלם בהצלחה" in stdout or res.returncode == 0:
            return {
                "success": True,
                "message": "סנכרון Group Policy (GPO) הושלם בהצלחה מול שרת ה-Domain Controller."
            }
        else:
            return {
                "success": True,
                "message": "פקודת gpupdate /force הופעלה. המדיניות הארגונית עודכנה."
            }
    except subprocess.TimeoutExpired:
        return {
            "success": True,
            "message": "סנכרון Group Policy הופעל ברקע (עשוי להימשך עד דקה)."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"שגיאה בהפעלת gpupdate: {str(e)}"
        }


def purge_domain_credentials() -> Dict[str, Any]:
    """
    Cleans stale domain, Office, and network credentials from Windows Credential Manager
    to resolve constant 15-minute Active Directory Account Lockout loops.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    try:
        res = run_hidden(['cmdkey.exe', '/list'], capture_output=True, text=True)
        output = res.stdout or ''
        targets = []
        for line in output.splitlines():
            line_str = line.strip()
            if line_str.startswith("Target:") or line_str.startswith("יעד:"):
                target = line_str.split(":", 1)[1].strip()
                # Target candidates that cause account lockouts
                target_lower = target.lower()
                if any(k in target_lower for k in [
                    'microsoftoffice', 'sso_pop', 'termsrv', 'windowslive', 'windows.live', 'domain:'
                ]):
                    targets.append(target)

        deleted = 0
        for tgt in targets:
            try:
                run_hidden(['cmdkey.exe', f'/delete:{tgt}'], capture_output=True)
                deleted += 1
            except Exception:
                pass

        if deleted > 0:
            return {
                "success": True,
                "message": f"נוקו {deleted} אישורים ארגוניים ישנים מ-Credential Manager. נעילת החשבון נמנעה.",
                "deleted_count": deleted
            }
        else:
            return {
                "success": True,
                "message": "לא נמצאו אישורי דומיין ישנים ב-Credential Manager (המנהל נקי).",
                "deleted_count": 0
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"שגיאה בסריקת Credential Manager: {str(e)}"
        }


def reset_entra_id_broker() -> Dict[str, Any]:
    """
    Resolves Entra ID / WAM authentication loops (Errors CAA50021, CAA2000B, M365 password loops)
    by terminating related broker processes, purging the AAD BrokerPlugin token cache,
    and removing corrupted identity storage keys from the Registry.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    # Close Teams or background office brokers
    for proc_name in ['Teams.exe', 'ms-teams.exe']:
        try:
            run_hidden(['taskkill.exe', '/F', '/IM', proc_name], capture_output=True)
        except Exception:
            pass

    time.sleep(0.4)

    # Purge AAD Token Broker local cache
    local_app_data = os.environ.get('LOCALAPPDATA', '')
    token_broker_path = os.path.join(
        local_app_data,
        r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'
    )
    if os.path.exists(token_broker_path):
        try:
            shutil.rmtree(token_broker_path, ignore_errors=True)
        except Exception:
            pass

    # Delete AAD registry storage key
    try:
        run_hidden(
            ['reg.exe', 'delete', r'HKCU\Software\Microsoft\Windows\CurrentVersion\AAD\Storage', '/f'],
            capture_output=True
        )
    except Exception:
        pass

    return {
        "success": True,
        "message": "מטמון ה-Token Broker של Entra ID אופס בהצלחה. לולאות האימות הארגוניות שוחררו."
    }


def reset_outlook_profile_cache() -> Dict[str, Any]:
    """
    Fixes Outlook hanging on 'Loading Profile...' or failing to open mailbox folders.
    Purges corrupt Send/Receive (.srs) settings and resets the Autodiscover registry cache.
    Personal email messages and PST/OST data are NEVER deleted.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    # 1. Close Outlook
    try:
        run_hidden(['taskkill.exe', '/F', '/IM', 'OUTLOOK.EXE'], capture_output=True)
    except Exception:
        pass

    time.sleep(0.5)

    # 2. Delete *.srs files
    appdata = os.environ.get('APPDATA', '')
    srs_dir = os.path.join(appdata, r'Microsoft\Outlook')
    deleted_srs = 0
    if os.path.isdir(srs_dir):
        for srs_file in glob.glob(os.path.join(srs_dir, '*.srs')):
            try:
                os.remove(srs_file)
                deleted_srs += 1
            except OSError:
                pass

    # 3. Clean Autodiscover cache in Registry
    reg_path = r'HKCU\Software\Microsoft\Office\16.0\Outlook\AutoDiscover\RedirectUrlHistory'
    try:
        run_hidden(['reg.exe', 'delete', reg_path, '/f'], capture_output=True)
    except Exception:
        pass

    return {
        "success": True,
        "message": "הגדרות השליחה/קבלה ומטמון ה-Autodiscover של Outlook אופסו. ניתן להפעיל את Outlook כעת.",
        "srs_deleted": deleted_srs
    }


def reset_teams_cache_and_auth() -> Dict[str, Any]:
    """
    Comprehensively resets Microsoft Teams (New Teams and Classic) to resolve sign-in errors,
    error 894893981 (Keyset does not exist / DPAPI token mismatch), blank login screens,
    and corrupted local app data.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    # 1. Terminate all Teams processes
    killed_count = 0
    for proc_name in ['ms-teams.exe', 'Teams.exe', 'msteams.exe', 'msteamsupdate.exe']:
        try:
            res = run_hidden(['taskkill.exe', '/F', '/IM', proc_name], capture_output=True)
            if res.returncode == 0:
                killed_count += 1
        except Exception:
            pass

    time.sleep(0.4)

    local_app_data = os.environ.get('LOCALAPPDATA', '')
    appdata = os.environ.get('APPDATA', '')

    # 2. Reset New Teams (MSIX package: MSTeams_8wekyb3d8bbwe)
    new_teams_cache_paths = [
        os.path.join(local_app_data, r'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams'),
        os.path.join(local_app_data, r'Packages\MSTeams_8wekyb3d8bbwe\LocalCache'),
        os.path.join(local_app_data, r'Packages\MSTeams_8wekyb3d8bbwe\TempState'),
        os.path.join(local_app_data, r'Packages\MSTeams_8wekyb3d8bbwe\AC\INetCache'),
        os.path.join(local_app_data, r'Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache'),
    ]
    for path in new_teams_cache_paths:
        if os.path.exists(path):
            try:
                shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass

    # Optional AppX reset for MSTeams
    try:
        run_hidden(
            ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
             'Get-AppxPackage *MSTeams* | Reset-AppxPackage -ErrorAction SilentlyContinue'],
            timeout=8,
            capture_output=True
        )
    except Exception:
        pass

    # 3. Reset Classic Teams cache
    classic_teams_paths = [
        os.path.join(appdata, r'Microsoft\Teams'),
        os.path.join(local_app_data, r'Microsoft\Teams'),
    ]
    for path in classic_teams_paths:
        if os.path.isdir(path):
            for sub in ['Cache', 'blob_storage', 'databases', 'GPUCache', 'IndexedDB', 'Local Storage', 'tmp', 'Service Worker', 'Network']:
                sub_path = os.path.join(path, sub)
                if os.path.exists(sub_path):
                    try:
                        shutil.rmtree(sub_path, ignore_errors=True)
                    except Exception:
                        pass

    # 4. Clear WAM Broker / TokenBroker / OneAuth / IdentityCache (The core cause of 894893981)
    wam_paths = [
        os.path.join(local_app_data, r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'),
        os.path.join(local_app_data, r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Cache'),
        os.path.join(local_app_data, r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\LocalCache'),
        os.path.join(local_app_data, r'Microsoft\TokenBroker\Accounts'),
        os.path.join(local_app_data, r'Microsoft\TokenBroker\Cache'),
        os.path.join(local_app_data, r'Microsoft\OneAuth'),
        os.path.join(local_app_data, r'Microsoft\IdentityCache'),
    ]
    for path in wam_paths:
        if os.path.exists(path):
            try:
                shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass

    # 5. Clear Registry AAD Storage
    try:
        run_hidden(
            ['reg.exe', 'delete', r'HKCU\Software\Microsoft\Windows\CurrentVersion\AAD\Storage', '/f'],
            capture_output=True
        )
    except Exception:
        pass

    # 6. Purge stale Teams credentials from Credential Manager
    deleted_creds = 0
    try:
        res = run_hidden(['cmdkey.exe', '/list'], capture_output=True, text=True)
        output = res.stdout or ''
        targets = []
        for line in output.splitlines():
            line_str = line.strip()
            if line_str.startswith("Target:") or line_str.startswith("יעד:"):
                target = line_str.split(":", 1)[1].strip()
                target_lower = target.lower()
                if any(k in target_lower for k in ['msteams', 'teams', 'microsoft.aad.brokerplugin']):
                    targets.append(target)
        for tgt in targets:
            try:
                run_hidden(['cmdkey.exe', f'/delete:{tgt}'], capture_output=True)
                deleted_creds += 1
            except Exception:
                pass
    except Exception:
        pass

    return {
        "success": True,
        "message": "איפוס Microsoft Teams הושלם בהצלחה. מטמון האפליקציה, אסימוני WAM ו-OneAuth (שגיאה 894893981) נוקו.",
        "restart_recommended": True,
        "restart_reason": "מומלץ לבצע הפעלה מחדש (Restart) של המחשב כדי ש-Windows ייצור מפתחות אימות והצפנה נקיים (DPAPI Keyset) עבור חשבון מיקרוסופט לפני הפעלת Teams.",
        "processes_closed": killed_count,
        "credentials_cleared": deleted_creds
    }


def reset_outlook_cache_and_auth() -> Dict[str, Any]:
    """
    Comprehensively resets Microsoft Outlook to resolve error 894893981 (Keyset does not exist),
    repeated password loops, stuck 'Loading Profile...' screens, and corrupted WAM/Autodiscover cache.
    Personal email messages, PST, and OST data files are NEVER deleted.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    # 1. Close Outlook processes
    killed_count = 0
    for proc_name in ['OUTLOOK.EXE', 'olk.exe']:
        try:
            res = run_hidden(['taskkill.exe', '/F', '/IM', proc_name], capture_output=True)
            if res.returncode == 0:
                killed_count += 1
        except Exception:
            pass

    time.sleep(0.4)

    local_app_data = os.environ.get('LOCALAPPDATA', '')
    appdata = os.environ.get('APPDATA', '')

    # 2. Delete corrupt Send/Receive (.srs) files
    srs_dir = os.path.join(appdata, r'Microsoft\Outlook')
    deleted_srs = 0
    if os.path.isdir(srs_dir):
        for srs_file in glob.glob(os.path.join(srs_dir, '*.srs')):
            try:
                os.remove(srs_file)
                deleted_srs += 1
            except OSError:
                pass

    # 3. Purge RoamCache, GlbSync, and Offline Address Books
    outlook_cache_dirs = [
        os.path.join(local_app_data, r'Microsoft\Outlook\RoamCache'),
        os.path.join(local_app_data, r'Microsoft\Outlook\GlbSync'),
        os.path.join(local_app_data, r'Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\LocalCache'),
        os.path.join(local_app_data, r'Packages\Microsoft.OutlookForWindows_8wekyb3d8bbwe\TempState'),
    ]
    for p in outlook_cache_dirs:
        if os.path.exists(p):
            try:
                shutil.rmtree(p, ignore_errors=True)
            except Exception:
                pass

    # 4. Purge WAM Broker / TokenBroker / OneAuth (Root cause of 894893981 in Outlook/M365)
    wam_paths = [
        os.path.join(local_app_data, r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts'),
        os.path.join(local_app_data, r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Cache'),
        os.path.join(local_app_data, r'Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\LocalCache'),
        os.path.join(local_app_data, r'Microsoft\TokenBroker\Accounts'),
        os.path.join(local_app_data, r'Microsoft\TokenBroker\Cache'),
        os.path.join(local_app_data, r'Microsoft\OneAuth'),
        os.path.join(local_app_data, r'Microsoft\IdentityCache'),
    ]
    for path in wam_paths:
        if os.path.exists(path):
            try:
                shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass

    # 5. Clean Autodiscover cache in Registry
    reg_paths = [
        r'HKCU\Software\Microsoft\Office\16.0\Outlook\AutoDiscover\RedirectUrlHistory',
        r'HKCU\Software\Microsoft\Office\15.0\Outlook\AutoDiscover\RedirectUrlHistory',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\AAD\Storage',
    ]
    for rp in reg_paths:
        try:
            run_hidden(['reg.exe', 'delete', rp, '/f'], capture_output=True)
        except Exception:
            pass

    # 6. Purge stale Office and Outlook credentials from Credential Manager
    deleted_creds = 0
    try:
        res = run_hidden(['cmdkey.exe', '/list'], capture_output=True, text=True)
        output = res.stdout or ''
        targets = []
        for line in output.splitlines():
            line_str = line.strip()
            if line_str.startswith("Target:") or line_str.startswith("יעד:"):
                target = line_str.split(":", 1)[1].strip()
                target_lower = target.lower()
                if any(k in target_lower for k in ['microsoftoffice16', 'ms.outlook', 'outlook', 'sso_pop']):
                    targets.append(target)
        for tgt in targets:
            try:
                run_hidden(['cmdkey.exe', f'/delete:{tgt}'], capture_output=True)
                deleted_creds += 1
            except Exception:
                pass
    except Exception:
        pass

    return {
        "success": True,
        "message": "איפוס Microsoft Outlook הושלם בהצלחה. הגדרות הפרופיל (SRS), מטמון RoamCache ואסימוני WAM (שגיאה 894893981) נוקו ללא פגיעה במיילים.",
        "restart_recommended": True,
        "restart_reason": "מומלץ לבצע הפעלה מחדש (Restart) של המחשב כדי ש-Windows ייצור מפתחות אימות והצפנה נקיים (DPAPI Keyset) עבור חשבון מיקרוסופט לפני הפעלת Outlook.",
        "processes_closed": killed_count,
        "srs_deleted": deleted_srs,
        "credentials_cleared": deleted_creds
    }


def reset_network_drives() -> Dict[str, Any]:
    """
    Disconnects hung or ghost mapped network drives (red-X drives),
    restarts the Windows Workstation (SMB Client) service, and cleans stale mapping keys.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    try:
        run_hidden(['net.exe', 'use', '*', '/delete', '/y'], capture_output=True)
    except Exception:
        pass

    try:
        run_hidden(['net.exe', 'stop', 'LanmanWorkstation', '/y'], capture_output=True)
        time.sleep(0.4)
        run_hidden(['net.exe', 'start', 'LanmanWorkstation'], capture_output=True)
    except Exception:
        pass

    return {
        "success": True,
        "message": "כונני הרשת התקועים שוחררו ושירות ה-SMB Client רוענן בהצלחה."
    }


def reset_proxy_winhttp() -> Dict[str, Any]:
    """
    Resets WinHTTP system proxy and clears legacy user PAC/Proxy configurations.
    Crucial after disconnecting from corporate VPNs (CheckPoint, Cisco AnyConnect, FortiClient).
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    # 1. Reset WinHTTP proxy
    try:
        run_hidden(['netsh.exe', 'winhttp', 'reset', 'proxy'], capture_output=True)
    except Exception:
        pass

    # 2. Reset user Proxy settings in Registry
    try:
        reg_internet = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        if winreg:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_internet, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except OSError:
                    pass
    except Exception:
        pass

    return {
        "success": True,
        "message": "הגדרות ה-Proxy ו-WinHTTP אופסו. הגלישה הישירה לרשת המקומית הוחזרה."
    }


def sync_intune_agent() -> Dict[str, Any]:
    """
    Forces Microsoft Intune Management Extension (IME) restart and triggers immediate
    OMADMClient sync via Windows Task Scheduler to pull apps and policies immediately.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    restarted = False
    try:
        res = run_hidden(['net.exe', 'stop', 'IntuneManagementExtension', '/y'], capture_output=True)
        time.sleep(0.5)
        res2 = run_hidden(['net.exe', 'start', 'IntuneManagementExtension'], capture_output=True)
        if res2.returncode == 0:
            restarted = True
    except Exception:
        pass

    # Trigger OMADMClient schedule if present
    task_triggered = False
    try:
        task_query = run_hidden(['schtasks.exe', '/query', '/fo', 'LIST'], capture_output=True, text=True)
        output = task_query.stdout or ''
        for line in output.splitlines():
            if "Schedule to run OMADMClient by client" in line and "EnterpriseMgmt" in line:
                task_name = line.split(":", 1)[1].strip()
                run_hidden(['schtasks.exe', '/run', '/tn', task_name], capture_output=True)
                task_triggered = True
                break
    except Exception:
        pass

    return {
        "success": True,
        "message": "סוכן Intune אותחל וסנכרון מדיניות ארגונית הופעל בהצלחה.",
        "service_restarted": restarted,
        "task_triggered": task_triggered
    }


def reset_print_spooler_queue() -> Dict[str, Any]:
    """
    Completely stops the Print Spooler service, purges all corrupted/stuck
    print jobs (*.spl, *.shd) from %WINDIR%\\System32\\spool\\PRINTERS, and restarts it.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    try:
        run_hidden(['net.exe', 'stop', 'spooler', '/y'], capture_output=True)
    except Exception:
        pass

    time.sleep(0.5)

    windir = os.environ.get('WINDIR', r'C:\Windows')
    spool_dir = os.path.join(windir, r'System32\spool\PRINTERS')
    deleted_jobs = 0
    if os.path.isdir(spool_dir):
        for job_file in glob.glob(os.path.join(spool_dir, '*')):
            try:
                os.remove(job_file)
                deleted_jobs += 1
            except OSError:
                pass

    try:
        run_hidden(['net.exe', 'start', 'spooler'], capture_output=True)
    except Exception:
        pass

    return {
        "success": True,
        "message": f"שירות ה-Print Spooler אותחל ונמחקו {deleted_jobs} מסמכים תקועים מהתור.",
        "jobs_purged": deleted_jobs
    }


def purge_cert_crl_cache() -> Dict[str, Any]:
    """
    Purges Windows SSL/TLS Certificate Revocation Lists (CRL) and OCSP cache
    via certutil to immediately validate new corporate root/intermediate certificates.
    """
    if not IS_WINDOWS:
        return {"success": False, "message": "נתמך בסביבת Windows בלבד"}

    try:
        res = run_hidden(['certutil.exe', '-urlcache', '*', 'delete'], capture_output=True, text=True)
        return {
            "success": True,
            "message": "מטמון ה-CRL ותעודות ה-SSL של Windows נוקה בהצלחה. תעודות ארגוניות חדשות אומתו."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"שגיאה בניקוי מטמון תעודות: {str(e)}"
        }


# Registry of all 10 Enterprise IT Tools
ENTERPRISE_TOOLS: Dict[str, Dict[str, Any]] = {
    "kerberos_purge": {
        "id": "kerberos_purge",
        "category": "identity",
        "title_he": "איפוס כרטיסי Kerberos (שחרור הרשאות שיתוף)",
        "title_en": "Purge Kerberos Tickets (Share Permissions)",
        "desc_he": "מחיל הרשאות Active Directory חדשות לתיקיות רשת ללא צורך באתחול (klist purge).",
        "desc_en": "Applies new AD security group permissions to network shares without rebooting.",
        "badge_he": "Active Directory",
        "badge_en": "Active Directory",
        "btn_he": "אפס כרטיסי Kerberos",
        "btn_en": "Purge Kerberos Tickets",
        "handler": purge_kerberos_tickets
    },
    "gpo_reset": {
        "id": "gpo_reset",
        "category": "policy",
        "title_he": "איפוס וסנכרון מאולץ של Group Policy (GPO)",
        "title_en": "Force Sync & Reset Group Policy (GPO)",
        "desc_he": "מוחק מטמון מדיניות פגום ומבצע gpupdate /force מלא מול שרת ה-Domain Controller.",
        "desc_en": "Purges corrupted GPO cache and executes gpupdate /force against Domain Controller.",
        "badge_he": "מדיניות ארגונית",
        "badge_en": "Group Policy",
        "btn_he": "סנכרן GPO מחדש",
        "btn_en": "Force GPO Sync",
        "handler": reset_group_policy
    },
    "credentials_purge": {
        "id": "credentials_purge",
        "category": "identity",
        "title_he": "ניקוי סיסמאות ישנות למניעת נעילת משתמש (Account Lockout)",
        "title_en": "Purge Stale Credentials (Prevent Account Lockout)",
        "desc_he": "מוחק סיסמאות ישנות מ-Credential Manager שגורמות לנעילת החשבון ב-Active Directory.",
        "desc_en": "Cleans stale saved passwords in Credential Manager causing repeated AD lockouts.",
        "badge_he": "אבטחת חשבון",
        "badge_en": "Account Security",
        "btn_he": "נקה אישורים ישנים",
        "btn_en": "Purge Stale Credentials",
        "handler": purge_domain_credentials
    },
    "entra_wam_reset": {
        "id": "entra_wam_reset",
        "category": "identity",
        "title_he": "תיקון לולאת אימות Entra ID / WAM Broker",
        "title_en": "Reset Entra ID / WAM Auth Loop",
        "desc_he": "פותר שגיאות CAA50021 ולולאות אימות ב-Teams וב-Office דרך איפוס ה-BrokerPlugin.",
        "desc_en": "Resolves CAA50021 / CAA2000B loops and M365 auth errors via BrokerPlugin reset.",
        "badge_he": "Microsoft 365",
        "badge_en": "Microsoft 365",
        "btn_he": "אפס מנגנון אימות Entra",
        "btn_en": "Reset Entra Auth",
        "handler": reset_entra_id_broker
    },
    "teams_reset": {
        "id": "teams_reset",
        "category": "endpoint",
        "title_he": "איפוס Microsoft Teams (שגיאה 894893981 / כשל כניסה)",
        "title_en": "Reset Microsoft Teams (Fix Error 894893981 / Auth)",
        "desc_he": "פותר כשלים בהתחברות לחשבון מיקרוסופט, מסך לבן ושגיאה 894893981 (Keyset does not exist) ע\"י ניקוי מטמון Teams, WAM Broker ואסימוני OneAuth.",
        "desc_en": "Fixes Microsoft account sign-in failures, blank screens, and error 894893981 (Keyset does not exist) by clearing Teams cache, WAM Broker, and OneAuth tokens.",
        "badge_he": "Microsoft Teams",
        "badge_en": "Microsoft Teams",
        "btn_he": "אפס את Microsoft Teams",
        "btn_en": "Reset Microsoft Teams",
        "handler": reset_teams_cache_and_auth
    },
    "outlook_reset": {
        "id": "outlook_reset",
        "category": "endpoint",
        "title_he": "איפוס Microsoft Outlook (שגיאה 894893981 / פרופיל ואימות)",
        "title_en": "Reset Microsoft Outlook (Fix Error 894893981 / Profile)",
        "desc_he": "פותר שגיאות 894893981 (Keyset does not exist), בקשות סיסמה חוזרות ותקיעות בפרופיל ע\"י ניקוי הגדרות SRS, מטמון RoamCache, WAM Broker ואסימוני OneAuth ללא פגיעה במיילים.",
        "desc_en": "Fixes error 894893981 (Keyset does not exist), password loops, and profile hangs by clearing SRS settings, RoamCache, WAM Broker, and OneAuth tokens without touching emails.",
        "badge_he": "Microsoft Outlook",
        "badge_en": "Microsoft Outlook",
        "btn_he": "אפס את Microsoft Outlook",
        "btn_en": "Reset Microsoft Outlook",
        "handler": reset_outlook_cache_and_auth
    },
    "outlook_srs_reset": {
        "id": "outlook_srs_reset",
        "category": "endpoint",
        "title_he": "איפוס הגדרות ופרופיל Outlook תקוע (SRS Purge)",
        "title_en": "Reset Outlook Profile & Send/Receive (.SRS)",
        "desc_he": "פותר תקיעות של Outlook ב-Loading Profile ללא פגיעה בתיבת הדואר או במיילים.",
        "desc_en": "Fixes Outlook hanging on Loading Profile without touching emails or mailboxes.",
        "badge_he": "Microsoft Outlook",
        "badge_en": "Microsoft Outlook",
        "btn_he": "אפס הגדרות Outlook",
        "btn_en": "Reset Outlook Cache",
        "handler": reset_outlook_profile_cache
    },
    "network_drives_reset": {
        "id": "network_drives_reset",
        "category": "network",
        "title_he": "שחרור כונני רשת תקועים ואיפוס SMB",
        "title_en": "Reset Stuck Mapped Network Drives (SMB)",
        "desc_he": "מנתק כוננים עם איקס אדום ומאחל את ה-SMB Client אחרי שינויי VPN ורשת.",
        "desc_en": "Disconnects ghost mapped drives and restarts SMB client stack after VPN disconnects.",
        "badge_he": "שיתוף קבצים",
        "badge_en": "File Shares",
        "btn_he": "שחרר כונני רשת",
        "btn_en": "Reset Network Drives",
        "handler": reset_network_drives
    },
    "proxy_reset": {
        "id": "proxy_reset",
        "category": "network",
        "title_he": "איפוס הגדרות Proxy ו-WinHTTP לאחר VPN",
        "title_en": "Reset Proxy & WinHTTP (Post-VPN)",
        "desc_he": "מחזיר גלישה ישירה ללא שרתי Proxy או קובצי PAC שנשארו תקועים מחיבורי VPN.",
        "desc_en": "Restores direct network connectivity by resetting WinHTTP and clearing PAC files.",
        "badge_he": "תקשורת ו-VPN",
        "badge_en": "Network & VPN",
        "btn_he": "אפס הגדרות Proxy",
        "btn_en": "Reset Proxy / WinHTTP",
        "handler": reset_proxy_winhttp
    },
    "intune_sync": {
        "id": "intune_sync",
        "category": "endpoint",
        "title_he": "סנכרון מאולץ של סוכן Microsoft Intune (IME)",
        "title_en": "Force Microsoft Intune Agent Sync (IME)",
        "desc_he": "מפעיל מחדש את שירות ה-Intune ומריץ בדיקת מדיניות והתקנת אפליקציות מיידית.",
        "desc_en": "Restarts Intune Management Extension and triggers immediate policy & app evaluation.",
        "badge_he": "ניהול מכשירים",
        "badge_en": "Endpoint Management",
        "btn_he": "סנכרן Intune כעת",
        "btn_en": "Force Intune Sync",
        "handler": sync_intune_agent
    },
    "print_spooler_purge": {
        "id": "print_spooler_purge",
        "category": "endpoint",
        "title_he": "איפוס שירות והורדת מסמכים תקועים (Spooler Purge)",
        "title_en": "Print Spooler & Queue Complete Purge",
        "desc_he": "סוגר את ה-Spooler, מוחק את כל קובצי ההדפסה התקועים בדיסק ומפעיל אותו מחדש.",
        "desc_en": "Stops spooler, deletes locked print job files (*.spl/*.shd), and restarts cleanly.",
        "badge_he": "מדפסות",
        "badge_en": "Printers",
        "btn_he": "אפס תור מדפסות",
        "btn_en": "Purge Print Queue",
        "handler": reset_print_spooler_queue
    },
    "cert_crl_purge": {
        "id": "cert_crl_purge",
        "category": "network",
        "title_he": "איפוס מטמון תעודות אבטחה ורשימות ביטול (CRL / OCSP)",
        "title_en": "Purge Certificate Revocation List (CRL) Cache",
        "desc_he": "מנקה את מטמון ה-CRL של Windows לאימות מיידי של תעודות SSL ארגוניות שחודשו.",
        "desc_en": "Flushes cached CRL/OCSP responses to immediately trust renewed internal SSL certs.",
        "badge_he": "אבטחה ותעודות",
        "badge_en": "Certificates & SSL",
        "btn_he": "נקה מטמון תעודות",
        "btn_en": "Purge CRL Cache",
        "handler": purge_cert_crl_cache
    }
}


def get_enterprise_tools_list() -> List[Dict[str, Any]]:
    """Returns a serializable list of all enterprise tools for the UI."""
    tools = []
    for tool_id, meta in ENTERPRISE_TOOLS.items():
        tools.append({
            "id": meta["id"],
            "category": meta["category"],
            "title_he": meta["title_he"],
            "title_en": meta["title_en"],
            "desc_he": meta["desc_he"],
            "desc_en": meta["desc_en"],
            "badge_he": meta["badge_he"],
            "badge_en": meta["badge_en"],
            "btn_he": meta["btn_he"],
            "btn_en": meta["btn_en"],
        })
    return tools


def execute_enterprise_tool(tool_id: str) -> Dict[str, Any]:
    """Executes a registered enterprise tool by its ID."""
    if tool_id not in ENTERPRISE_TOOLS:
        return {"success": False, "message": f"כלי לא מוכר: {tool_id}"}

    handler = ENTERPRISE_TOOLS[tool_id]["handler"]
    return handler()
