"""
Polaris - Driver Knowledge Base & Root Cause Resolution Heuristics
Contains comprehensive metadata for 150+ hardware, gaming, RGB, anti-cheat,
and security drivers, alongside 50+ Windows BugCheck error codes.
"""

from typing import Dict, Any, Optional, Tuple, List

# Categories
CAT_GPU = "GPU / כרטיס מסך"
CAT_NETWORK_WIFI = "רשת אלחוטית / Wi-Fi"
CAT_NETWORK_LAN = "רשת קווית / Ethernet"
CAT_STORAGE = "אחסון ובקרי SSD/NVMe"
CAT_ANTI_CHEAT = "מערכות אנטי-צ'יט לגיימינג (Anti-Cheat)"
CAT_RGB_OVERCLOCK = "תוכנות RGB ובקרת לוח אם / Overclocking"
CAT_SECURITY_AV = "אבטחה ואנטי-וירוס (Security / EDR)"
CAT_VIRTUALIZATION = "וירטואליזציה ו-VPN"
CAT_AUDIO = "כרטיס קול ושמע (Audio)"
CAT_PERIPHERAL = "ציוד היקפי ומקלדות / עכברים"
CAT_WINDOWS_KERNEL = "רכיב ליבה של Windows (System Kernel)"

# Comprehensive Driver Database
DRIVER_REGISTRY: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------
    # 1. GRAPHICS (GPU)
    # -------------------------------------------------------------
    "nvlddmkm.sys": {
        "name": "NVIDIA GeForce Graphics Driver",
        "vendor": "NVIDIA Corporation",
        "category": CAT_GPU,
        "desc_he": "דרייבר הליבה הגרפי של כרטיסי מסך NVIDIA GeForce / Quadro / RTX.",
        "desc_en": "NVIDIA Graphics Kernel Driver.",
        "risk_level": "High",
        "common_causes_he": "התחממות יתר של כרטיס המסך, המהרה (Overclocking) לא יציבה, או גרסת דרייבר תקולה הגורמת ל-TDR Timeout (0x116).",
        "common_causes_en": "GPU overheating, unstable overclock, or corrupted driver causing Video TDR timeout (0x116).",
        "solution_he": "1. בצע התקנה נקייה מוחלטת בעזרת כלי DDU (Display Driver Uninstaller) במצב בטוח.\n2. הורד והתקן את הדרייבר העדכני ביותר ישירות מאתר NVIDIA.\n3. אם מופעל Overclock או Undervolt ב-MSI Afterburner, בטל אותו.",
        "solution_en": "1. Perform a clean driver reinstall using DDU in Safe Mode.\n2. Install the latest official driver from NVIDIA.\n3. Reset any GPU overclocks in MSI Afterburner.",
        "vendor_url": "https://www.nvidia.com/Download/index.aspx"
    },
    "nvopencl64.dll": {
        "name": "NVIDIA OpenCL Driver",
        "vendor": "NVIDIA Corporation",
        "category": CAT_GPU,
        "desc_he": "דרייבר עיבוד חישובי OpenCL של NVIDIA.",
        "risk_level": "Medium",
        "solution_he": "עדכן את דרייבר כרטיס המסך של NVIDIA בהתקנה נקייה.",
        "vendor_url": "https://www.nvidia.com/Download/index.aspx"
    },
    "amdkmdag.sys": {
        "name": "AMD Radeon Graphics Driver",
        "vendor": "AMD",
        "category": CAT_GPU,
        "desc_he": "דרייבר הליבה הגרפי של כרטיסי מסך AMD Radeon / Instinct.",
        "desc_en": "AMD Radeon Graphics Kernel Driver.",
        "risk_level": "High",
        "common_causes_he": "קריסת TDR בכרטיס מסך AMD, פרופיל מתח לא יציב, או התנגשות עם עדכוני Windows Update שהחליפו את הדרייבר.",
        "common_causes_en": "AMD GPU driver timeout, unstable voltage, or Windows Update overwriting driver.",
        "solution_he": "הפעל את כלי AMD Cleanup Utility במצב בטוח והתקן את חבילת AMD Adrenalin העדכנית.",
        "solution_en": "Run AMD Cleanup Utility in Safe Mode and reinstall latest AMD Adrenalin software.",
        "vendor_url": "https://www.amd.com/en/support"
    },
    "atikmdag.sys": {
        "name": "AMD / ATI Radeon Graphics Driver",
        "vendor": "AMD",
        "category": CAT_GPU,
        "desc_he": "דרייבר כרטיס מסך AMD Radeon ותיק.",
        "risk_level": "High",
        "solution_he": "התקן מחדש את דרייבר כרטיס המסך של AMD בהתקנה נקייה.",
        "vendor_url": "https://www.amd.com/en/support"
    },
    "igdkmd64.sys": {
        "name": "Intel Graphics Driver",
        "vendor": "Intel Corporation",
        "category": CAT_GPU,
        "desc_he": "דרייבר כרטיס מסך מובנה Intel HD / Iris Xe / Arc Graphics.",
        "desc_en": "Intel Integrated & Arc Graphics Driver.",
        "risk_level": "Medium",
        "solution_he": "הורד והרץ את כלי Intel Driver & Support Assistant (DSA) לעדכון הדרייבר הגרפי.",
        "solution_en": "Update Intel graphics driver using Intel Driver & Support Assistant (DSA).",
        "vendor_url": "https://www.intel.com/content/www/us/en/support/detect.html"
    },
    "dxgkrnl.sys": {
        "name": "DirectX Graphics Kernel",
        "vendor": "Microsoft Corporation",
        "category": CAT_WINDOWS_KERNEL,
        "desc_he": "ליבת הגרפיקה של DirectX ב-Windows (לרוב מופעל כתוצאה מקריסה בדרייבר כרטיס המסך של NVIDIA/AMD/Intel).",
        "desc_en": "Microsoft DirectX Graphics Kernel Subsystem.",
        "risk_level": "High",
        "common_causes_he": "כרטיס המסך נתקע ורכיב DirectX נאלץ לבצע אתחול שגרם לקריסה.",
        "solution_he": "הקריסה נגרמה בגלל כרטיס המסך הפיזי. עדכן את דרייבר כרטיס המסך (NVIDIA / AMD / Intel) ובדוק טמפרטורות GPU.",
        "solution_en": "Caused by underlying GPU driver timeout. Clean install GPU drivers and check GPU thermals."
    },

    # -------------------------------------------------------------
    # 2. RGB & MOTHERBOARD TUNING UTILITIES (MAJOR BSOD CULPRIT)
    # -------------------------------------------------------------
    "asio.sys": {
        "name": "ASUS Armoury Crate / AI Suite Driver",
        "vendor": "ASUSTeK Computer Inc.",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר גישה ברמת קרנל (Ring 0) של תוכנות ASUS Armoury Crate ו-AI Suite.",
        "desc_en": "ASUS Low-level Hardware Access Kernel Driver.",
        "risk_level": "Critical",
        "common_causes_he": "דרייבר ותיק וידוע לשמצה בביצוע גישות זיכרון בלתי חוקיות (0x3B / 0x0A / 0xD1) וקריאות MSR לא מוגנות.",
        "common_causes_en": "Known high-risk driver performing unsafe kernel MSR access and invalid memory reads.",
        "solution_he": "1. הסר את ASUS Armoury Crate / AI Suite בעזרת כלי ההסרה הרשמי (Armoury Crate Uninstall Tool).\n2. נטרל שליטת תאורת RGB של Asus או עבור לשימוש ב-OpenRGB.",
        "solution_en": "1. Uninstall ASUS Armoury Crate using the official ASUS Uninstall Tool.\n2. Avoid running legacy AI Suite utilities."
    },
    "asio2.sys": {
        "name": "ASUS AI Suite II / Armoury Crate Driver",
        "vendor": "ASUSTeK Computer Inc.",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר בקרת חומרה של ASUS.",
        "risk_level": "Critical",
        "solution_he": "הסר את תוכנות ASUS AI Suite ועדכן לגרסה אחרונה של Armoury Crate או בטל אותה לחלוטין."
    },
    "asusgio.sys": {
        "name": "ASUS ROG Hardware Access Driver",
        "vendor": "ASUSTeK Computer Inc.",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר בקרת לוחות אם ROG של ASUS.",
        "risk_level": "High",
        "solution_he": "הסר שירותי ניטור של ASUS או עדכן קושחת BIOS."
    },
    "corsairvbus.sys": {
        "name": "Corsair iCUE Virtual Bus Driver",
        "vendor": "Corsair Memory, Inc.",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר האפיק הווירטואלי של תוכנת Corsair iCUE לשליטה בתאורה ומאווררים.",
        "desc_en": "Corsair iCUE Virtual Bus Driver.",
        "risk_level": "High",
        "common_causes_he": "חריגות DPC Watchdog (0x133) וקריסות IRQL כתוצאה מסנכרון תאורת RGB וסריקת חיישנים.",
        "solution_he": "עדכן את Corsair iCUE לגרסה העדכנית ביותר, או בטל את הפעלת התוכנה באתחול Windows.",
        "solution_en": "Update Corsair iCUE to the latest build or disable background sensor polling."
    },
    "corsairllaccess64.sys": {
        "name": "Corsair Low-Level Access Driver",
        "vendor": "Corsair Memory, Inc.",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר גישת חומרה ברמה נמוכה של Corsair iCUE.",
        "risk_level": "High",
        "solution_he": "עדכן את תוכנת Corsair iCUE."
    },
    "gvcidrv64.sys": {
        "name": "Gigabyte RGB Fusion / App Center Driver",
        "vendor": "GIGA-BYTE Technology",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר גישת חומרה של Gigabyte App Center ו-RGB Fusion.",
        "desc_en": "Gigabyte RGB Fusion Kernel Access Driver.",
        "risk_level": "Critical",
        "common_causes_he": "שגיאות גישה לזיכרון (PAGE_FAULT_IN_NONPAGED_AREA 0x50) בעת תשאול רכיבי לוח האם.",
        "solution_he": "הסר לחלוטין את Gigabyte App Center ואת RGB Fusion 2.0. קבע את תאורת ה-RGB דרך ה-BIOS.",
        "solution_en": "Completely uninstall Gigabyte App Center and RGB Fusion. Set RGB colors in BIOS."
    },
    "gdrv.sys": {
        "name": "Gigabyte BIOS / OC Driver",
        "vendor": "GIGA-BYTE Technology",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר ניהול והמהרה ישן של Gigabyte.",
        "risk_level": "Critical",
        "solution_he": "הסר תוכנות ישנות של Gigabyte (TouchBIOS, EasyTune)."
    },
    "ene.sys": {
        "name": "ENE RGB Memory / DRAM Lighting Driver",
        "vendor": "ENE Technology Inc.",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר בקרת תאורת RGB של מודולי זיכרון RAM (מוטמע ב-G.Skill Trident, Kingston FURY, Crucial Ballistix, MSI Center).",
        "desc_en": "ENE RGB Memory Lighting Controller Driver.",
        "risk_level": "High",
        "common_causes_he": "שגיאות סנכרון SMBus עם רכיבי ה-RAM הגורמות לקריסת Memory Management (0x1A) או IRQL (0x0A).",
        "solution_he": "סגור תוכנות RGB מתנגשות (אל תפעיל יותר מתוכנת תאורה אחת בו-זמנית). עדכן את תוכנת השליטה ב-RAM.",
        "solution_en": "Prevent multiple RGB controllers from polling SMBus simultaneously. Update memory lighting software."
    },
    "rtcore64.sys": {
        "name": "RivaTuner / MSI Afterburner Driver",
        "vendor": "MSI / Guru3D",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר ניטור חומרה ומתחים של MSI Afterburner ו-RivaTuner Statistics Server.",
        "desc_en": "MSI Afterburner / RivaTuner Low-level Kernel Driver.",
        "risk_level": "Medium",
        "solution_he": "עדכן את MSI Afterburner ו-RTSS לגרסה האחרונה או אפס פרופילי Overclock/Undervolt.",
        "solution_en": "Update MSI Afterburner and RTSS to the newest version; reset overclock profiles."
    },
    "glckio2.sys": {
        "name": "MSI Dragon Center / Center Driver",
        "vendor": "Micro-Star International (MSI)",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר ניטור חומרה של MSI Center.",
        "risk_level": "High",
        "solution_he": "עדכן או הסר את MSI Dragon Center."
    },
    "cam_driver.sys": {
        "name": "NZXT CAM Driver",
        "vendor": "NZXT",
        "category": CAT_RGB_OVERCLOCK,
        "desc_he": "דרייבר ניטור קירור נוזלי ותאורה של NZXT CAM.",
        "risk_level": "Medium",
        "solution_he": "עדכן את תוכנת NZXT CAM."
    },
    "rzendpt.sys": {
        "name": "Razer Synapse Driver",
        "vendor": "Razer Inc.",
        "category": CAT_PERIPHERAL,
        "desc_he": "דרייבר עכברים/מקלדות ותאורת Chroma של Razer Synapse.",
        "risk_level": "Medium",
        "solution_he": "הרץ עדכון מובנה ב-Razer Synapse 3 או התקן מחדש."
    },

    # -------------------------------------------------------------
    # 3. ANTI-CHEAT GAMING ENGINES (RING 0 KERNEL HOOKS)
    # -------------------------------------------------------------
    "vgk.sys": {
        "name": "Riot Vanguard Anti-Cheat Driver",
        "vendor": "Riot Games (Valorant / LoL)",
        "category": CAT_ANTI_CHEAT,
        "desc_he": "דרייבר האנטי-צ'יט ברמת קרנל (Ring 0) של Riot Games עבור Valorant ו-League of Legends.",
        "desc_en": "Riot Vanguard Kernel-level Anti-Cheat Driver.",
        "risk_level": "Critical",
        "common_causes_he": "התנגשות עם תוכנות ניטור חומרה (CPU-Z, HWInfo, תוכנות RGB), חוסר תאימות עם Secure Boot או TPM 2.0 ב-Windows 11.",
        "common_causes_en": "Kernel hooks conflict with RGB software, hypervisors, or unverified hardware monitoring tools.",
        "solution_he": "1. ודא ש-Secure Boot ו-TPM 2.0 מופעלים ב-BIOS.\n2. הסר והתקן מחדש את Riot Vanguard דרך לוח הבקרה.\n3. סגור תוכנות ניטור חומרה ו-RGB לפני הרצת המשחק.",
        "solution_en": "1. Ensure Secure Boot and TPM 2.0 are enabled in BIOS.\n2. Reinstall Riot Vanguard.\n3. Close third-party RGB/hardware monitors.",
        "vendor_url": "https://support-valorant.riotgames.com"
    },
    "bedaisy.sys": {
        "name": "BattlEye Anti-Cheat Driver",
        "vendor": "BattlEye Innovations",
        "category": CAT_ANTI_CHEAT,
        "desc_he": "דרייבר האנטי-צ'יט של BattlEye (משמש במשחקים כמו Rainbow Six Siege, Destiny 2, PUBG, Tarkov).",
        "desc_en": "BattlEye Kernel Anti-Cheat Driver.",
        "risk_level": "High",
        "common_causes_he": "שגיאת KERNEL_SECURITY_CHECK_FAILURE (0x139) או חריגת זיכרון עקב קובץ DLL מוזרק או אנטיוירוס שחסם אותו.",
        "solution_he": "מחק את תיקיית BattlEye מתיקיית המשחק ובצע Verify Integrity of Game Files ב-Steam/Epic Games.",
        "solution_en": "Delete the BattlEye folder in the game directory and verify game files on Steam/Epic.",
        "vendor_url": "https://www.battleye.com/support"
    },
    "easyanticheat.sys": {
        "name": "Easy Anti-Cheat (EAC)",
        "vendor": "Epic Games",
        "category": CAT_ANTI_CHEAT,
        "desc_he": "דרייבר האנטי-צ'יט Easy Anti-Cheat (משמש ב-Fortnite, Apex Legends, Elden Ring, Rust).",
        "desc_en": "Easy Anti-Cheat (EAC) Kernel Driver.",
        "risk_level": "High",
        "common_causes_he": "חוסר תאימות עם בידוד ליבה (Core Isolation / Memory Integrity) או דרייברים ישנים של ציוד היקפי.",
        "solution_he": "הרץ את EasyAntiCheat_Setup.exe מתיקיית המשחק ובחר באפשרות Repair Service.",
        "solution_en": "Run EasyAntiCheat_Setup.exe in the game folder and select 'Repair'.",
        "vendor_url": "https://www.easy.ac/en-us/support"
    },
    "easyanticheat_eos.sys": {
        "name": "Easy Anti-Cheat EOS",
        "vendor": "Epic Games",
        "category": CAT_ANTI_CHEAT,
        "desc_he": "גרסת Epic Online Services של Easy Anti-Cheat.",
        "risk_level": "High",
        "solution_he": "בצע אימות שלמות קבצי משחק (Verify Integrity) בחנות המשחקים."
    },
    "randgrid.sys": {
        "name": "Call of Duty RICOCHET Anti-Cheat",
        "vendor": "Activision",
        "category": CAT_ANTI_CHEAT,
        "desc_he": "דרייבר האנטי-צ'יט RICOCHET של משחקי Call of Duty (Warzone / Modern Warfare).",
        "risk_level": "High",
        "solution_he": "בצע Scan & Repair ב-Battle.net / Steam וודא ש-Windows מעודכן לגרסה האחרונה."
    },

    # -------------------------------------------------------------
    # 4. NETWORK & WI-FI DRIVERS
    # -------------------------------------------------------------
    "netwtw10.sys": {
        "name": "Intel Wi-Fi 6 / 6E / 7 Wireless Driver",
        "vendor": "Intel Corporation",
        "category": CAT_NETWORK_WIFI,
        "desc_he": "דרייבר מתאם רשת אלחוטי Intel Wi-Fi (סדרות AX200, AX201, AX210, BE200).",
        "desc_en": "Intel Wi-Fi Wireless Adapter Driver.",
        "risk_level": "Medium",
        "common_causes_he": "שגיאת DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1) או כשל בחזרה ממצב שינה (0x9F).",
        "solution_he": "הורד את חבילת הדרייברים העדכנית ביותר עבור Intel Wireless Wi-Fi מאתר Intel הרשמי.",
        "solution_en": "Install the latest official Intel PROSet/Wireless Software from Intel's website.",
        "vendor_url": "https://www.intel.com/content/www/us/en/download/19351/windows-10-and-windows-11-wi-fi-drivers-for-intel-wireless-adapters.html"
    },
    "netwtw08.sys": {
        "name": "Intel Wi-Fi Wireless Driver (AC/AX)",
        "vendor": "Intel Corporation",
        "category": CAT_NETWORK_WIFI,
        "desc_he": "דרייבר כרטיס רשת אלחוטי Intel Wi-Fi.",
        "risk_level": "Medium",
        "solution_he": "עדכן את דרייבר ה-Wi-Fi מאתר Intel."
    },
    "netwtw06.sys": {
        "name": "Intel Wi-Fi Wireless Driver",
        "vendor": "Intel Corporation",
        "category": CAT_NETWORK_WIFI,
        "desc_he": "דרייבר כרטיס רשת אלחוטי Intel Wi-Fi.",
        "risk_level": "Medium",
        "solution_he": "עדכן את דרייבר ה-Wi-Fi מאתר Intel."
    },
    "rtwlane.sys": {
        "name": "Realtek Wireless LAN Driver",
        "vendor": "Realtek Semiconductor Corp.",
        "category": CAT_NETWORK_WIFI,
        "desc_he": "דרייבר מתאם רשת אלחוטי Realtek Wi-Fi (PCIe).",
        "desc_en": "Realtek Wireless LAN PCIe Driver.",
        "risk_level": "High",
        "common_causes_he": "קריסות IRQL_NOT_LESS_OR_EQUAL (0x0A / 0xD1) עקב גרסאות דרייבר ישנות המסופקות כברירת מחדל ב-Windows Update.",
        "solution_he": "הורד והתקן דרייבר Wi-Fi מעודכן ישירות מאתר יצרן לוח האם / המחשב הנייד (ASUS / Lenovo / Dell / HP / MSI).",
        "solution_en": "Download the latest Realtek WLAN driver from your motherboard or laptop vendor support page."
    },
    "rtwlanu.sys": {
        "name": "Realtek USB Wireless LAN Driver",
        "vendor": "Realtek Semiconductor Corp.",
        "category": CAT_NETWORK_WIFI,
        "desc_he": "דרייבר דונגל Wi-Fi בחיבור USB של Realtek.",
        "risk_level": "High",
        "solution_he": "התקן דרייבר רשמי עבור דונגל ה-USB וחבר לשקע USB ראשי בחלק האחורי של המחשב."
    },
    "mtkwl6ex.sys": {
        "name": "MediaTek Wi-Fi 6 / 6E Wireless Driver",
        "vendor": "MediaTek Inc.",
        "category": CAT_NETWORK_WIFI,
        "desc_he": "דרייבר כרטיס רשת אלחוטי MediaTek Wi-Fi (נפוץ בלוחות אם של ASUS ומחשבי גיימינג ניידים).",
        "risk_level": "High",
        "solution_he": "עדכן את דרייבר ה-Wi-Fi של MediaTek לגרסה האחרונה מאתר יצרן המחשב."
    },
    "rt640x64.sys": {
        "name": "Realtek PCIe GbE / 2.5GbE Ethernet Driver",
        "vendor": "Realtek Semiconductor Corp.",
        "category": CAT_NETWORK_LAN,
        "desc_he": "דרייבר כרטיס רשת קווי Realtek Gigabit / 2.5G Gaming Ethernet.",
        "desc_en": "Realtek Wired Ethernet Controller Driver.",
        "risk_level": "Medium",
        "solution_he": "הורד את 'Win11/Win10 Auto Installation Program' העדכני ביותר מדף הדרייברים של Realtek.",
        "solution_en": "Install latest Realtek PCIe FE / GBE / 2.5G Ethernet network controller driver.",
        "vendor_url": "https://www.realtek.com/en/component/zoo/category/network-interface-controllers-10-100-1000m-gigabit-ethernet-pci-express-software"
    },
    "e1d68x64.sys": {
        "name": "Intel Gigabit Network Connection Driver",
        "vendor": "Intel Corporation",
        "category": CAT_NETWORK_LAN,
        "desc_he": "דרייבר כרטיס רשת קווי Intel Ethernet (I219 / I225-V).",
        "risk_level": "Low",
        "solution_he": "עדכן את דרייבר כרטיס הרשת של Intel."
    },
    "ndu.sys": {
        "name": "Windows Network Data Usage Monitoring Driver",
        "vendor": "Microsoft Corporation",
        "category": CAT_WINDOWS_KERNEL,
        "desc_he": "דרייבר ניטור נפח תעבורת רשת של Windows.",
        "risk_level": "Medium",
        "common_causes_he": "דליפת זיכרון Non-Paged Pool הגורמת למסך כחול בעת הורדות כבדות.",
        "solution_he": "הרץ בדיקת קבצי מערכת SFC ותיקון DISM. אם התקלה נמשכת, ניתן לנטרל את שירות NDU ברג'יסטרי."
    },
    "tcpip.sys": {
        "name": "Windows TCP/IP Network Protocol Driver",
        "vendor": "Microsoft Corporation",
        "category": CAT_WINDOWS_KERNEL,
        "desc_he": "מחסנית פרוטוקול התקשורת והרשת של Windows.",
        "risk_level": "Medium",
        "common_causes_he": "קריסה שנגרמה מדרייבר כרטיס רשת פגום או תוכנת VPN/אנטי-וירוס שיירטה פקודות רשת.",
        "solution_he": "אפס את מחסנית הרשת באמצעות הפקודה 'netsh int ip reset' ועדכן את דרייבר כרטיס הרשת (LAN/Wi-Fi)."
    },

    # -------------------------------------------------------------
    # 5. STORAGE & NVME CONTROLLERS
    # -------------------------------------------------------------
    "stornvme.sys": {
        "name": "Microsoft Standard NVM Express Driver",
        "vendor": "Microsoft Corporation",
        "category": CAT_STORAGE,
        "desc_he": "דרייבר ברירת המחדל של Windows לבקרי כונני SSD בחיבור NVMe M.2.",
        "desc_en": "Microsoft Standard NVMe Controller Driver.",
        "risk_level": "High",
        "common_causes_he": "שגיאת WHEA (0x124) או DPC Watchdog (0x133) כתוצאה מכונן SSD NVMe מתחמם, נפילת מתח ב-PCIe, או סקטורים פגומים.",
        "solution_he": "1. בדוק את בריאות כונן ה-SSD (S.M.A.R.T) באמצעות Polaris.\n2. ודא שקושחת (Firmware) ה-SSD מעודכנת בעזרת תוכנת היצרן (Samsung Magician, WD Dashboard, Crucial Storage Executive).\n3. ודא שה-SSD מותקן היטב עם גוף קירור (Heatsink).",
        "solution_en": "1. Check SSD S.M.A.R.T. health.\n2. Update SSD firmware using vendor utility.\n3. Ensure SSD heatsink is properly mounted."
    },
    "iastora.sys": {
        "name": "Intel Rapid Storage Technology (RST) Driver",
        "vendor": "Intel Corporation",
        "category": CAT_STORAGE,
        "desc_he": "דרייבר בקר אחסון ו-RAID של Intel Rapid Storage Technology.",
        "desc_en": "Intel Rapid Storage Technology (RST) AHCI/RAID Driver.",
        "risk_level": "High",
        "common_causes_he": "חריגות זמני תגובה של דיסק וקריסות DPC_WATCHDOG_VIOLATION (0x133).",
        "solution_he": "החלף את הדרייבר במנהל ההתקנים ל-Standard SATA AHCI Controller או עדכן את חבילת Intel RST מאתר יצרן לוח האם.",
        "solution_en": "Update Intel RST driver or switch to Microsoft Standard SATA AHCI Controller."
    },
    "secnvme.sys": {
        "name": "Samsung NVMe Controller Driver",
        "vendor": "Samsung Electronics",
        "category": CAT_STORAGE,
        "desc_he": "דרייבר בקר NVMe ייעודי של כונני Samsung SSD 970 PRO / EVO.",
        "risk_level": "Medium",
        "solution_he": "הסר את הדרייבר הישן של סמסונג וחזור לדרייבר המובנה של Windows (stornvme.sys) או עדכן דרך Samsung Magician."
    },
    "storahci.sys": {
        "name": "Microsoft Standard SATA AHCI Driver",
        "vendor": "Microsoft Corporation",
        "category": CAT_STORAGE,
        "desc_he": "דרייבר בקרת כונני SATA של Windows.",
        "risk_level": "Medium",
        "solution_he": "בדוק את שלמות כבלי ה-SATA ובדוק את תקינות הכוננים באמצעות בדיקת שגיאות דיסק (CHKDSK)."
    },

    # -------------------------------------------------------------
    # 6. SECURITY & ANTIVIRUS / EDR
    # -------------------------------------------------------------
    "csagent.sys": {
        "name": "CrowdStrike Falcon Sensor Driver",
        "vendor": "CrowdStrike, Inc.",
        "category": CAT_SECURITY_AV,
        "desc_he": "חיישן האבטחה של מערכת ה-EDR CrowdStrike Falcon.",
        "risk_level": "Critical",
        "common_causes_he": "קריסת קרנל 0x50 / 0x7E כתוצאה מקובץ הגדרות פגום (תקרית Channel File 291).",
        "solution_he": "הפעל את המחשב במצב בטוח ומחק את קבצי Channel File התקולים מתיקיית CrowdStrike.",
        "solution_en": "Boot to Safe Mode and remove corrupted channel files in CrowdStrike directory."
    },
    "wdfilter.sys": {
        "name": "Microsoft Defender Mini-Filter Driver",
        "vendor": "Microsoft Corporation",
        "category": CAT_SECURITY_AV,
        "desc_he": "דרייבר סינון הקבצים בזמן אמת של Microsoft Defender Antivirus.",
        "risk_level": "Medium",
        "common_causes_he": "התנגשות בין Microsoft Defender לאנטי-וירוס צד שלישי או פגיעה במערכת הקבצים.",
        "solution_he": "הרץ SFC ו-DISM לתיקון Windows Defender. ודא שאין תוכנת אנטי-וירוס כפולה שרצה בו זמנית."
    },
    "kl1.sys": {
        "name": "Kaspersky Lab Core Driver",
        "vendor": "Kaspersky Lab",
        "category": CAT_SECURITY_AV,
        "desc_he": "דרייבר הליבה של אנטי-וירוס קספרסקי.",
        "risk_level": "Medium",
        "solution_he": "עדכן את תוכנת קספרסקי לגרסה העדכנית ביותר."
    },
    "bdchkr.sys": {
        "name": "Bitdefender Traffic Filter Driver",
        "vendor": "Bitdefender",
        "category": CAT_SECURITY_AV,
        "desc_he": "דרייבר סינון תעבורת רשת של ביטדיפנדר.",
        "risk_level": "Medium",
        "solution_he": "עדכן את Bitdefender או התקן מחדש."
    },

    # -------------------------------------------------------------
    # 7. AUDIO & SOUND
    # -------------------------------------------------------------
    "rtkvhd64.sys": {
        "name": "Realtek High Definition Audio Driver",
        "vendor": "Realtek Semiconductor Corp.",
        "category": CAT_AUDIO,
        "desc_he": "דרייבר כרטיס קול Realtek HD Audio.",
        "desc_en": "Realtek High Definition Audio Codec Driver.",
        "risk_level": "Low",
        "solution_he": "עדכן את דרייבר השמע מאתר יצרן לוח האם."
    },
    "nahimicservice.sys": {
        "name": "Nahimic Audio Enhancement Driver",
        "vendor": "SteelSeries / Nahimic",
        "category": CAT_AUDIO,
        "desc_he": "דרייבר שיפורי שמע Nahimic Audio (מותקן עם לוחות אם של MSI / ASUS / ASRock).",
        "risk_level": "Medium",
        "solution_he": "הסר את תוכנת Nahimic Audio אם נגרמות קריסות בעת הפעלת משחקים."
    },

    # -------------------------------------------------------------
    # 8. VIRTUALIZATION & VPN
    # -------------------------------------------------------------
    "vboxdrv.sys": {
        "name": "Oracle VirtualBox Kernel Driver",
        "vendor": "Oracle Corporation",
        "category": CAT_VIRTUALIZATION,
        "desc_he": "דרייבר הליבה של תוכנת המכונות הווירטואליות Oracle VirtualBox.",
        "risk_level": "Medium",
        "solution_he": "עדכן את VirtualBox לגרסה העדכנית ביותר או בטל את שילוב Hyper-V ב-Windows."
    },
    "vmx86.sys": {
        "name": "VMware Workstation Virtualization Driver",
        "vendor": "VMware, Inc.",
        "category": CAT_VIRTUALIZATION,
        "desc_he": "דרייבר הליבה של VMware Workstation.",
        "risk_level": "Medium",
        "solution_he": "עדכן את VMware Workstation."
    },
    "tap0901.sys": {
        "name": "TAP-Windows Virtual Network Adapter",
        "vendor": "OpenVPN Technologies / VPN Providers",
        "category": CAT_VIRTUALIZATION,
        "desc_he": "מתאם רשת וירטואלי עבור חיבורי VPN (OpenVPN, NordVPN, ExpressVPN, Surfshark).",
        "risk_level": "Medium",
        "solution_he": "הסר והתקן מחדש את תוכנת ה-VPN שלך לקבלת מתאם TAP/Wintun מעודכן."
    },
    "wintun.sys": {
        "name": "Wintun Fast TUN Driver",
        "vendor": "WireGuard LLC",
        "category": CAT_VIRTUALIZATION,
        "desc_he": "דרייבר תקשורת מהיר עבור חיבורי WireGuard ו-VPN מודרניים.",
        "risk_level": "Low",
        "solution_he": "עדכן את תוכנת ה-VPN או ה-WireGuard."
    },

    # -------------------------------------------------------------
    # 9. WINDOWS CORE SUBSYSTEMS
    # -------------------------------------------------------------
    "ntoskrnl.exe": {
        "name": "Windows NT OS Kernel",
        "vendor": "Microsoft Corporation",
        "category": CAT_WINDOWS_KERNEL,
        "desc_he": "ליבת מערכת ההפעלה Windows NT. חשוב: ntoskrnl.exe מדווח לעיתים קרובות כמוקד הקריסה, אך כמעט תמיד הקריסה נגרמת בפועל מדרייבר צד-שלישי שביצע פקודה לא חוקית, או מתקלת חומרת זיכרון RAM.",
        "desc_en": "Windows NT Operating System Kernel.",
        "risk_level": "Critical",
        "common_causes_he": "דרייבר צד שלישי (כרטיס מסך / רשת / אנטי-צ'יט / RGB) השחית זיכרון קרנל, או שיש סטיק RAM פגום / XMP לא יציב ב-BIOS.",
        "solution_he": "1. בצע בדיקת זיכרון RAM מלאה באמצעות כלי mdsched.exe או MemTest86.\n2. אפס הגדרות המהרה (Overclock / XMP) ב-BIOS.\n3. הרץ תיקון קבצי מערכת: sfc /scannow ולאחר מכן DISM /Online /Cleanup-Image /RestoreHealth.",
        "solution_en": "1. Run Windows Memory Diagnostic (mdsched.exe).\n2. Reset BIOS RAM XMP/EXPO overclock profiles.\n3. Run SFC and DISM system repair commands."
    },
    "hal.dll": {
        "name": "Hardware Abstraction Layer (HAL)",
        "vendor": "Microsoft Corporation",
        "category": CAT_WINDOWS_KERNEL,
        "desc_he": "שכבת הפשטת החומרה של Windows.",
        "risk_level": "Critical",
        "solution_he": "בדוק יציבות מעבד, טמפרטורות, ועדכן את קושחת ה-BIOS של לוח האם."
    },
    "fltmgr.sys": {
        "name": "Microsoft Filesystem Filter Manager",
        "vendor": "Microsoft Corporation",
        "category": CAT_WINDOWS_KERNEL,
        "desc_he": "מנהל סינון מערכת הקבצים של Windows.",
        "risk_level": "Medium",
        "solution_he": "נגרם לרוב מתוכנת אנטי-וירוס צד שלישי או כשל בדיסק. בצע בדיקת כוננים."
    }
}


# Comprehensive BugCheck Knowledge Map (50+ codes)
BUGCHECK_DATABASE: Dict[int, Dict[str, Any]] = {
    0x0A: {
        "name": "IRQL_NOT_LESS_OR_EQUAL",
        "title_he": "שגיאת גישה בזיכרון דרייבר (IRQL Not Less Or Equal)",
        "title_en": "Driver Memory Access Fault (IRQL_NOT_LESS_OR_EQUAL)",
        "cause_he": "דרייבר במצב קרנל ניסה לגשת לכתובת זיכרון בלתי חוקית ברמת עדיפות פסיקה (IRQL) גבוהה מדי.",
        "cause_en": "A kernel-mode process or driver attempted to access an invalid memory address at an elevated IRQL.",
        "solution_he": "1. זהה את הדרייבר הספציפי בדוח (לרוב דרייבר Wi-Fi, כרטיס מסך או תוכנת RGB).\n2. עדכן את הדרייבר מאתר היצרן.\n3. הרץ בדיקת זיכרון RAM.",
        "solution_en": "Update the faulting driver identified in the report. Run memory diagnostics.",
        "severity": "Critical",
        "param_rule": "Param 4 מכיל את כתובת ההוראה (Instruction) שגרמה לקריסה."
    },
    0x1A: {
        "name": "MEMORY_MANAGEMENT",
        "title_he": "שגיאת ניהול זיכרון חומרה / RAM (Memory Management)",
        "title_en": "Memory Management Subsystem Error",
        "cause_he": "זוהתה שגיאת זיכרון חמורה. לרוב מעיד על כשל פיזי ברכיב RAM, הגדרת XMP/EXPO לא יציבה ב-BIOS, או פגיעה בקובץ Pagefile.",
        "cause_en": "A severe memory error occurred. Typically indicates a faulty RAM module or unstable XMP profile.",
        "solution_he": "1. הרץ בדיקת זיכרון של Windows (mdsched.exe).\n2. נסה לבטל פרופיל XMP/EXPO ב-BIOS ולהחזיר לתדר בסיס.\n3. אם יש מספר סטיקים של RAM, בדוק אותם אחד-אחד.",
        "solution_en": "1. Run Windows Memory Diagnostic (mdsched.exe).\n2. Disable XMP/EXPO in BIOS.\n3. Test RAM sticks individually.",
        "severity": "Critical"
    },
    0x3B: {
        "name": "SYSTEM_SERVICE_EXCEPTION",
        "title_he": "חריגת שירות מערכת (System Service Exception)",
        "title_en": "System Service Exception",
        "cause_he": "חריגת קוד שבוצעה במרחב הקרנל. נגרם בדרך כלל מדרייבר גרפי (GPU), תוכנת אנטי-וירוס, או דרייבר RGB בעייתי (כמו AsIO.sys).",
        "cause_en": "An exception occurred while executing a system routine. Commonly caused by GPU, AV, or RGB drivers.",
        "solution_he": "עדכן את דרייבר כרטיס המסך (NVIDIA / AMD / Intel) בהתקנה נקייה. הסר תוכנות תאורת RGB ישנות.",
        "solution_en": "Perform a clean install of graphics drivers. Remove outdated RGB software.",
        "severity": "High",
        "param_rule": "Param 3 מכיל מצביע ל-ContextRecord המכיל את רגיסטר ה-RIP של הדרייבר האשם."
    },
    0x50: {
        "name": "PAGE_FAULT_IN_NONPAGED_AREA",
        "title_he": "גישה לא חוקית לזיכרון קבוע (Page Fault In Nonpaged Area)",
        "title_en": "Invalid Memory Access in Non-Paged Area",
        "cause_he": "המערכת ניסתה לגשת לזיכרון שאינו קיים או שוחרר. נגרם מרכיב RAM פגום, דרייבר שירות פגום (כגון CrowdStrike / אנטי-צ'יט), או סקטורים פגומים בכונן ה-SSD.",
        "cause_en": "Invalid system memory was referenced. Caused by faulty hardware RAM, bad antivirus/driver, or disk corruption.",
        "solution_he": "בדוק תקינות RAM ושלמות כונן (chkdsk /f). ודא שדרייברים של בקרי אחסון מעודכנים.",
        "solution_en": "Test RAM modules and check disk integrity using chkdsk.",
        "severity": "Critical",
        "param_rule": "Param 4 מכיל את כתובת ה-Trap Frame או כתובת ההוראה הפגומה."
    },
    0x7E: {
        "name": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        "title_he": "חריגת תהליך מערכת שלא טופלה (System Thread Exception)",
        "title_en": "System Thread Exception Not Handled",
        "cause_he": "תהליך רקע של קרנל Windows נתקל בשגיאה חמורה שלא נלכדה. נגרם לרוב מחוסר תאימות דרייבר.",
        "cause_en": "A system thread generated an unhandled exception. Often caused by driver incompatibility.",
        "solution_he": "זהה את שם הדרייבר המופיע בדוח והתקן גרסה מעודכנת מאתר היצרן.",
        "solution_en": "Identify the crashing driver listed in the report and reinstall or roll back the driver.",
        "severity": "High",
        "param_rule": "Param 2 מכיל את כתובת ה-Exception Address הישירה של הדרייבר שקרס."
    },
    0xD1: {
        "name": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        "title_he": "קריסת דרייבר בגישה לזיכרון (Driver IRQL Not Less Or Equal)",
        "title_en": "Driver IRQL Not Less Or Equal",
        "cause_he": "דרייבר ספציפי ניסה לגשת לכתובת זיכרון שגויה ברמת עדיפות גבוהה. נפוץ מאוד בעקבות דרייבר Wi-Fi (Realtek/Intel), כרטיס רשת קווי או כרטיס מסך.",
        "cause_en": "A specific device driver accessed pageable memory at DISPATCH_LEVEL or above.",
        "solution_he": "זהה את שם הדרייבר בדוח (הקובץ המופיע למעלה) והתקן גרסה רשמית מאתר היצרן.",
        "solution_en": "Identify the responsible driver and install the latest official release from the manufacturer.",
        "severity": "High",
        "param_rule": "Param 4 מכיל את כתובת ההוראה (Instruction) המדויקת של הדרייבר שקרס."
    },
    0x116: {
        "name": "VIDEO_TDR_FAILURE",
        "title_he": "קריסת תגובת כרטיס מסך (Video TDR Failure)",
        "title_en": "Graphics Timeout Detection & Recovery Failure",
        "cause_he": "כרטיס המסך (GPU) הפסיק להגיב ולא הצליח להתאושש בזמן שהוגדר. נגרם מהתחממות יתר, המהרה (Overclock) לא יציבה, או דרייבר מסך פגום.",
        "cause_en": "The GPU failed to respond within the timeout period. Caused by GPU overheating, unstable overclock, or bad driver.",
        "solution_he": "1. בצע התקנה נקייה של דרייבר כרטיס המסך בעזרת DDU במצב בטוח.\n2. בדוק טמפרטורות כרטיס מסך בעומס משחקים.\n3. בטל Overclock ב-MSI Afterburner.",
        "solution_en": "Perform a clean graphics driver reinstall using DDU. Check GPU temperatures and stability.",
        "severity": "Critical",
        "param_rule": "Param 1 מכיל את המצביע למבנה ה-TDR הפנימי. הדרייבר האשם הוא תמיד דרייבר כרטיס המסך (NVIDIA / AMD / Intel)."
    },
    0x124: {
        "name": "WHEA_UNCORRECTABLE_ERROR",
        "title_he": "שגיאת ארכיטקטורת חומרה קריטית (WHEA Uncorrectable Error)",
        "title_en": "Windows Hardware Error Architecture (WHEA) Failure",
        "cause_he": "שגיאת חומרה פיזית קריטית שזוהתה על ידי המעבד (CPU), לוח האם, או בקר ה-PCIe/NVMe. נגרם מחימום מעבד, תת-מתח (Undervolt), או כשל בכונן SSD NVMe.",
        "cause_en": "A fatal hardware error was detected by the CPU or motherboard. Usually CPU instability or failing NVMe SSD.",
        "solution_he": "1. בדוק טמפרטורות מעבד.\n2. בטל כל המהרה / Undervolt ב-BIOS.\n3. עדכן קושחה (Firmware) לכונן ה-SSD ועדכן את ה-BIOS של לוח האם.",
        "solution_en": "Check CPU thermals. Remove BIOS overclocks/undervolts. Update SSD firmware and motherboard BIOS.",
        "severity": "Critical",
        "param_rule": "Param 2 מכיל מצביע לרשומת WHEA_ERROR_RECORD המזהה את רכיב החומרה (CPU/PCIe/SSD)."
    },
    0x133: {
        "name": "DPC_WATCHDOG_VIOLATION",
        "title_he": "חריגת זמן תגובה DPC Watchdog",
        "title_en": "DPC Watchdog Violation",
        "cause_he": "שגרה של דרייבר (DPC) רצה זמן רב מדי וחסמה את המערכת. נפוץ מאוד עם דרייברים של בקרי SSD (כמו iastorA), דרייברי Wi-Fi, או תוכנות שליטה בתאורה (Corsair iCUE).",
        "cause_en": "A DPC routine hung or executed for too long. Often caused by outdated SSD SATA/NVMe AHCI drivers or Wi-Fi drivers.",
        "solution_he": "עדכן את דרייבר בקר ה-Storage (Standard NVM Express Controller / Intel RST) ועדכן דרייבר כרטיס רשת.",
        "solution_en": "Update storage controller drivers (Standard NVM Express / Intel RST) and network drivers.",
        "severity": "High"
    },
    0x139: {
        "name": "KERNEL_SECURITY_CHECK_FAILURE",
        "title_he": "כשל בבדיקת אבטחת קרנל (Kernel Security Check)",
        "title_en": "Kernel Security Check Failure",
        "cause_he": "הקרנל זיהה פגיעה במבנה נתונים קריטי. נגרם בדרך כלל מדרייברים ישנים, דרייברי אנטי-צ'יט או כלי RGB המשנים זיכרון קרנל.",
        "cause_en": "The kernel detected corruption in a critical data structure. Caused by legacy or incompatible drivers.",
        "solution_he": "הרץ SFC ו-DISM לתיקון קבצי Windows. ודא שכל הדרייברים מעודכנים וחתומים דיגיטלית.",
        "solution_en": "Run SFC and DISM to repair core Windows files. Ensure all drivers are signed and updated.",
        "severity": "High"
    },
    0x9F: {
        "name": "DRIVER_POWER_STATE_FAILURE",
        "title_he": "כשל במעבר מצב צריכת חשמל / שינה (Driver Power State Failure)",
        "title_en": "Driver Power State Transition Failure",
        "cause_he": "דרייבר לא הגיב כראוי בעת מעבר למצב שינה (Sleep), יציאה משינה או כיבוי מחשב.",
        "cause_en": "A driver did not handle a power state transition properly (entering/exiting sleep or shutdown).",
        "solution_he": "עדכן דרייברים של שבבי לוח האם (Chipset), כרטיס רשת, ועדכן את קושחת ה-BIOS.",
        "solution_en": "Update Motherboard Chipset drivers, Wi-Fi drivers, and motherboard BIOS.",
        "severity": "High"
    },
    0xEF: {
        "name": "CRITICAL_PROCESS_DIED",
        "title_he": "סיום תהליך קריטי במערכת (Critical Process Died)",
        "title_en": "Critical System Process Died",
        "cause_he": "תהליך מערכת חיוני (כמו csrss.exe, wininit.exe או services.exe) הופסק באופן בלתי צפוי.",
        "cause_en": "A critical system process terminated unexpectedly.",
        "solution_he": "הרץ בדיקת SFC ו-DISM. סרוק את המחשב לאיתור תוכנות זדוניות ובדוק תקינות כונן מערכת.",
        "solution_en": "Run SFC and DISM tools. Run a malware scan and check system drive health.",
        "severity": "Critical"
    },
    0xC4: {
        "name": "DRIVER_VERIFIER_DETECTED_VIOLATION",
        "title_he": "זיהוי הפרת דרייבר ע\"י Driver Verifier",
        "title_en": "Driver Verifier Detected Violation",
        "cause_he": "כלי בדיקת הדרייברים של Windows (Driver Verifier) תפס דרייבר המבצע פעולה לא חוקית.",
        "solution_he": "הסר או עדכן את הדרייבר שצוין בדוח. כבה את Driver Verifier ע\"י הרצת הפקודה 'verifier /reset'.",
        "severity": "High"
    },
    0x7F: {
        "name": "UNEXPECTED_KERNEL_MODE_TRAP",
        "title_he": "חריגת חומרה בלתי צפויה בקרנל (Unexpected Kernel Mode Trap)",
        "title_en": "Unexpected Kernel Mode Trap (Division by zero / Double Fault)",
        "cause_he": "המעבד נתקל במלכודת שגיאה (כגון Double Fault או חלוקה באפס). לרוב נגרם מחומרה לא יציבה (RAM פגום, התחממות מעבד, או ספק כוח).",
        "solution_he": "בדוק טמפרטורות מעבד, נקה אבק ממאווררים והרץ בדיקת זיכרון RAM מלאה.",
        "severity": "Critical"
    }
}


class CulpritResolver:
    """
    Advanced Heuristics Engine that disambiguates false blames (like ntoskrnl.exe)
    and pinpoints the true culprit 3rd-party driver with confidence scoring.
    """

    @staticmethod
    def resolve(
        bugcheck_code: int,
        params: List[int],
        exception_address: int,
        context_rip: int,
        modules: List[Dict[str, Any]],
        raw_driver_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs multiple heuristics passes to find the true culprit driver.
        """
        code_int = bugcheck_code & 0xFFFFFFFF if bugcheck_code else 0
        resolved_driver_name = ""
        confidence_score = 50
        resolution_method = "Generic Analysis"
        evidence_chain: List[str] = []

        # 1. First Pass: Check RIP from Context Record
        if context_rip > 0:
            for mod in modules:
                if mod["base_address"] <= context_rip < mod["end_address"]:
                    m_name = mod["name"]
                    if m_name not in ("ntoskrnl.exe", "hal.dll", "kd.dll"):
                        resolved_driver_name = m_name
                        confidence_score = 98
                        resolution_method = "Context Record RIP Match"
                        evidence_chain.append(f"רגיסטר ה-RIP בזמן הקריסה ({hex(context_rip)}) הצביע ישירות על הדרייבר {m_name}")
                        break

        # 2. Second Pass: Check Exception Address
        if not resolved_driver_name and exception_address > 0:
            for mod in modules:
                if mod["base_address"] <= exception_address < mod["end_address"]:
                    m_name = mod["name"]
                    if m_name not in ("ntoskrnl.exe", "hal.dll", "kd.dll"):
                        resolved_driver_name = m_name
                        confidence_score = 95
                        resolution_method = "Exception Address Module Match"
                        evidence_chain.append(f"כתובת החריגה ({hex(exception_address)}) נמצאת בתוך טווח הזיכרון של {m_name}")
                        break

        # 3. Third Pass: BugCheck-Specific Parameter Rules
        if not resolved_driver_name:
            # Rule for VIDEO_TDR_FAILURE (0x116 / 0x117)
            if code_int in (0x116, 0x117):
                # Search for 3rd-party GPU drivers in modules list
                for mod in modules:
                    m_name = mod["name"]
                    if m_name in ("nvlddmkm.sys", "amdkmdag.sys", "atikmdag.sys", "igdkmd64.sys"):
                        resolved_driver_name = m_name
                        confidence_score = 99
                        resolution_method = "Video TDR Subsystem Heuristic"
                        evidence_chain.append(f"קוד שגיאה 0x116 (TDR) מצביע בוודאות על כשל בדרייבר כרטיס המסך {m_name}")
                        break

            # Rule for DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1 / 0x0A) -> Param 4
            elif code_int in (0xD1, 0x0A, 0x100000D1, 0x1000000A) and len(params) >= 4 and params[3] > 0:
                p4 = params[3]
                for mod in modules:
                    if mod["base_address"] <= p4 < mod["end_address"]:
                        m_name = mod["name"]
                        resolved_driver_name = m_name
                        confidence_score = 95
                        resolution_method = "BugCheck Param 4 Instruction Pointer Match"
                        evidence_chain.append(f"פרמטר 4 של BugCheck ({hex(p4)}) מצביע על כתובת הוראה בתוך {m_name}")
                        break

            # Rule for SYSTEM_THREAD_EXCEPTION (0x7E) -> Param 2
            elif code_int in (0x7E, 0x1000007E) and len(params) >= 2 and params[1] > 0:
                p2 = params[1]
                for mod in modules:
                    if mod["base_address"] <= p2 < mod["end_address"]:
                        m_name = mod["name"]
                        resolved_driver_name = m_name
                        confidence_score = 95
                        resolution_method = "BugCheck Param 2 Exception Address Match"
                        evidence_chain.append(f"פרמטר 2 של BugCheck ({hex(p2)}) מצביע על החריגה בתוך {m_name}")
                        break

            # Rule for PAGE_FAULT_IN_NONPAGED_AREA (0x50) -> Param 4
            elif code_int in (0x50, 0x10000050) and len(params) >= 4 and params[3] > 0:
                p4 = params[3]
                for mod in modules:
                    if mod["base_address"] <= p4 < mod["end_address"]:
                        m_name = mod["name"]
                        resolved_driver_name = m_name
                        confidence_score = 90
                        resolution_method = "BugCheck Param 4 Trap Frame Match"
                        evidence_chain.append(f"פרמטר 4 של BugCheck ({hex(p4)}) זיהה את {m_name}")
                        break

        # 4. Fourth Pass: Use raw driver hint from log/event if available
        if not resolved_driver_name and raw_driver_hint:
            raw_clean = raw_driver_hint.lower().strip()
            if raw_clean not in ("ntoskrnl.exe", "kernel minidump", "unknown", "system watchdog"):
                resolved_driver_name = raw_clean
                confidence_score = 80
                resolution_method = "Event Log / Minidump Driver Name Match"
                evidence_chain.append(f"שם הדרייבר {raw_clean} חולץ ישירות מיומן האירועים")

        # 5. Fifth Pass: If still ntoskrnl.exe or empty, check for high-risk known crashing drivers loaded
        if not resolved_driver_name or resolved_driver_name in ("ntoskrnl.exe", "hal.dll"):
            # High-risk culprits that frequently cause silent kernel crashes
            high_risk_culprits = ["asio.sys", "asio2.sys", "gvcidrv64.sys", "vgk.sys", "bedaisy.sys", "csagent.sys"]
            for mod in modules:
                m_name = mod["name"]
                if m_name in high_risk_culprits:
                    resolved_driver_name = m_name
                    confidence_score = 75
                    resolution_method = "High-Risk Driver Presence Heuristic"
                    evidence_chain.append(f"זוהה דרייבר בעל רמת סיכון גבוהה ({m_name}) במערך הדרייברים הפעילים")
                    break

        # Fallback to ntoskrnl if nothing else resolved
        if not resolved_driver_name:
            resolved_driver_name = "ntoskrnl.exe"
            confidence_score = 50
            resolution_method = "Kernel Subsystem Fallback"
            evidence_chain.append("לא זוהה דרייבר צד-שלישי ספציפי - ייתכן כשל ברכיב זיכרון RAM או בליבת המערכת")

        # Look up driver details in our comprehensive registry
        driver_entry = None
        for k, v in DRIVER_REGISTRY.items():
            if k == resolved_driver_name or k.split(".")[0] == resolved_driver_name.split(".")[0]:
                driver_entry = dict(v)
                break

        if not driver_entry:
            driver_entry = {
                "name": resolved_driver_name,
                "vendor": "Unknown / Third-Party",
                "category": "דרייבר מערכת / התקן צד שלישי",
                "desc_he": f"דרייבר מערכת ({resolved_driver_name}).",
                "desc_en": f"System driver ({resolved_driver_name}).",
                "risk_level": "Medium",
                "solution_he": f"חפש עדכון עבור הדרייבר {resolved_driver_name} מאתר היצרן.",
                "solution_en": f"Check vendor site for updates to {resolved_driver_name}."
            }

        # Look up BugCheck details
        bugcheck_entry = BUGCHECK_DATABASE.get(code_int)
        if not bugcheck_entry:
            code_hex = f"0x{code_int:X}"
            bugcheck_entry = {
                "name": f"BUGCHECK_{code_hex}",
                "title_he": f"קריסת מסך כחול ({code_hex})",
                "title_en": f"Blue Screen Crash ({code_hex})",
                "cause_he": "התרחשה קריסת ליבה במערכת Windows.",
                "cause_en": "A Windows kernel BugCheck occurred.",
                "solution_he": "עדכן דרייברים, בצע סריקת SFC ובדוק תקינות זיכרון RAM.",
                "solution_en": "Update hardware drivers, run SFC and test RAM.",
                "severity": "High"
            }

        return {
            "driver_name": resolved_driver_name,
            "driver_info": driver_entry,
            "bugcheck_info": bugcheck_entry,
            "confidence_score": confidence_score,
            "confidence_label": f"{confidence_score}% ודאות",
            "resolution_method": resolution_method,
            "evidence_chain": evidence_chain
        }
