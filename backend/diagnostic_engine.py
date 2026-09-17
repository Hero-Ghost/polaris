"""
Polaris - Diagnostic & Root Cause Intelligence Engine
Analyzes memory states, detects hidden memory hogs, driver leaks (Non-Paged Pool),
and produces clear, actionable natural language diagnoses in Hebrew and English.
"""

from backend.win_utils import format_bytes as _format_bytes


class DiagnosticEngine:
    def __init__(self):
        pass

    def diagnose(self, memory_stats, grouped_processes):
        """
        Runs comprehensive heuristic analysis on memory and processes.
        Returns health score, category breakdown, identified root causes,
        and human-readable explanations in Hebrew and English.
        """
        total_ram = memory_stats.get('total_bytes', 1)
        available_ram = memory_stats.get('available_bytes', 0)
        cached_ram = memory_stats.get('cached_bytes', 0)
        ram_percent = memory_stats.get('percent', 0.0)

        kernel_nonpaged = memory_stats.get('kernel_nonpaged_bytes', 0)

        # 1. Category aggregation
        cat_map = {
            "Browsers": 0,
            "Development": 0,
            "Communication": 0,
            "System": 0,
            "Background & Services": 0,
            "User Apps": 0
        }

        browser_count = 0
        browser_bytes = 0
        browser_processes = []

        dev_bytes = 0
        comm_bytes = 0
        system_bytes = 0
        background_bytes = 0

        for g in grouped_processes:
            cat = g.get('category', 'User Apps')
            rss = g.get('total_rss_bytes', 0)
            cat_map[cat] = cat_map.get(cat, 0) + rss

            if cat == "Browsers":
                browser_count += g.get('process_count', 1)
                browser_bytes += rss
                browser_processes.append(g)
            elif cat == "Development":
                dev_bytes += rss
            elif cat == "Communication":
                comm_bytes += rss
            elif cat == "System":
                system_bytes += rss
            elif cat == "Background & Services":
                background_bytes += rss

        # Top 5 groups
        top_groups = grouped_processes[:5]
        top_5_bytes = sum(g.get('total_rss_bytes', 0) for g in top_groups)
        top_5_percent = round((top_5_bytes / total_ram * 100.0), 1) if total_ram > 0 else 0

        # Health score calculation (0 to 100)
        score = 100
        if ram_percent > 70:
            score -= (ram_percent - 70) * 1.5
        if kernel_nonpaged > 1.2 * (1024**3): # Over 1.2 GB NPP
            score -= 20
        if ram_percent >= 90:
            score -= 15
        score = max(5, min(100, int(score)))

        # Findings & Root Cause Analysis
        findings = []
        recommendations = []

        # Check 1: Driver / Non-Paged Pool Leak
        if kernel_nonpaged > 1.2 * (1024**3) or (total_ram > 0 and (kernel_nonpaged / total_ram) > 0.15):
            findings.append({
                "type": "DRIVER_LEAK",
                "severity": "high",
                "icon": "alert-triangle",
                "title_he": "חשד לדליפת זיכרון בדרייבר / קרנל (Non-Paged Pool)",
                "title_en": "Suspicious Driver/Kernel Memory Leak (Non-Paged Pool)",
                "desc_he": f"הזיכרון הבלתי-מוחלף (Non-Paged Pool) עומד על {self.format_bytes(kernel_nonpaged)}, כשהנורמה התקינה היא לרוב מתחת ל-500MB. זיכרון זה מוקצה על ידי דרייברים וחומרה ואינו משתחרר. גורמים שכיחים בווינדוס: דרייבר כרטיס רשת ישן (כגון Killer Network או שירות 'ndu.sys') או תוכנות אנטי-וירוס.",
                "desc_en": f"Non-Paged Pool is consuming {self.format_bytes(kernel_nonpaged)} (normal is typically under 500 MB). This is allocated by hardware drivers and kernel modules. Common Windows culprits: outdated network card drivers (e.g. Killer Network or 'ndu.sys' service) or third-party antivirus filters.",
                "action_he": "מומלץ לעדכן דרייברים לכרטיס הרשת, או לבדוק ביטול שירות NDU ברג'יסטרי.",
                "action_en": "Update network adapter drivers or investigate the Windows NDU service."
            })
            recommendations.append({
                "he": "עדכן דרייברים של כרטיס הרשת (LAN / Wi-Fi)",
                "en": "Update network card drivers (LAN / Wi-Fi)"
            })

        # Check 2: Browser Multi-Process footprint
        if browser_bytes > 2.0 * (1024**3) or (total_ram > 0 and (browser_bytes / total_ram) > 0.25):
            top_browser_names = ", ".join([b['friendly_name'] for b in browser_processes[:3]])
            findings.append({
                "type": "BROWSER_FLOOD",
                "severity": "medium",
                "icon": "globe",
                "title_he": f"צריכת זיכרון משמעותית מדפדפנים ({self.format_bytes(browser_bytes)})",
                "title_en": f"High Browser Memory Footprint ({self.format_bytes(browser_bytes)})",
                "desc_he": f"נמצאו {browser_count} תהליכים נפרדים של דפדפנים ({top_browser_names}). דפדפנים מודרניים יוצרים תהליך רקע נפרד עבור כל טאב, תוסף (Extension) ורכיב גרפי, דבר שמצטבר במהירות לג'יגה-בייטים שלמים.",
                "desc_en": f"Found {browser_count} separate browser processes ({top_browser_names}). Modern browsers create isolated sub-processes for every tab, extension, and media stream, which rapidly accumulates RAM.",
                "action_he": "מומלץ לסגור טאבים לא פעילים, להשתמש במצב חיסכון בזיכרון של הדפדפן (Memory Saver), או לנקות תוספים כבדים.",
                "action_en": "Enable browser 'Memory Saver' mode, close idle tabs, or disable unused extensions."
            })
            recommendations.append({
                "he": "הפעל 'מצב חיסכון בזיכרון' בהגדרות הדפדפן או סגור טאבים מיותרים",
                "en": "Enable 'Memory Saver' in browser settings or discard inactive tabs"
            })

        # Check 3: Standby Cache vs Active Memory
        if cached_ram > 0 and total_ram > 0 and (cached_ram / total_ram) > 0.35 and ram_percent > 75:
            findings.append({
                "type": "STANDBY_CACHE",
                "severity": "info",
                "icon": "info",
                "title_he": f"זיכרון מטמון של מערכת ההפעלה ({self.format_bytes(cached_ram)})",
                "title_en": f"Windows Standby Cache Active ({self.format_bytes(cached_ram)})",
                "desc_he": f"חלק ניכר מהזיכרון ({self.format_bytes(cached_ram)}) מוחזק כזיכרון מטמון (Standby Cache) על ידי Windows. ווינדוס טוען לזיכרון קבצים ותוכנות שנפתחו לאחרונה כדי להאיץ את המחשב. זיכרון זה זמין וישוחרר אוטומטית ברגע שתוכנה כלשהי תדרוש זיכרון.",
                "desc_en": f"A significant portion ({self.format_bytes(cached_ram)}) is cached in Standby Memory by Windows to speed up file access and app launch. This memory is instantly reclaimed by the OS whenever any application requests it.",
                "action_he": "מצב תקין של מערכת ההפעלה - אין סיבה לדאגה.",
                "action_en": "Normal OS caching behavior - memory will be freed automatically."
            })

        # Check 4: Windows Background Maintenance / Defender / Search Indexer
        sec_proc = [g for g in grouped_processes if 'msmpeng' in g['name'].lower() or 'search' in g['name'].lower()]
        if sec_proc:
            sec_bytes = sum(p['total_rss_bytes'] for p in sec_proc)
            if sec_bytes > 800 * (1024**2):
                findings.append({
                    "type": "BACKGROUND_SERVICES",
                    "severity": "medium",
                    "icon": "shield",
                    "title_he": f"שירותי רקע ותחזוקה של Windows ({self.format_bytes(sec_bytes)})",
                    "title_en": f"Windows Background Maintenance & Defender ({self.format_bytes(sec_bytes)})",
                    "desc_he": f"שירותי אבטחה ואינדוקס של Windows (כגון Windows Defender ו-Search Indexer) צורכים זיכרון בעת סריקת קבצים לאחר הדלקת המחשב.",
                    "desc_en": f"Windows security and indexing background services (e.g. Defender and Search Indexer) are actively caching signatures and indexing files.",
                    "action_he": "הצריכה תרד מעצמה לאחר סיום סריקת האתחול.",
                    "action_en": "Usage will normalize once initial boot scanning completes."
                })

        # Check 5: Top 3 Process Hogs
        if len(top_groups) > 0 and top_5_percent > 45:
            top_names_str = ", ".join([f"{g['friendly_name']} ({g['total_rss_formatted']})" for g in top_groups[:3]])
            findings.append({
                "type": "TOP_HOGS",
                "severity": "medium",
                "icon": "pie-chart",
                "title_he": f"3 האפליקציות הכבדות ביותר צורכות נתח ניכר",
                "title_en": f"Top 3 Applications Consuming Major Share",
                "desc_he": f"האפליקציות המובילות: {top_names_str}. יחד הן מהוות {top_5_percent}% מכלל זיכרון המחשב.",
                "desc_en": f"Top consumers: {top_names_str}. Together they account for {top_5_percent}% of total system RAM.",
                "action_he": "ניתן ללחוץ על 'ניקוי זיכרון' (Trim Working Sets) כדי לשחרר זיכרון עודף שנשמר על ידן.",
                "action_en": "You can use 'Clean RAM' (Trim Working Sets) to purge their idle memory."
            })

        # General recommendations
        if ram_percent > 80:
            recommendations.append({
                "he": "השתמש בכפתור 'שחרור זיכרון' המובנה באפליקציה כדי לפנות דפים רדומים",
                "en": "Use the built-in 'Clean RAM' feature to flush inactive working sets"
            })
            recommendations.append({
                "he": "בדוק במנהל המשימות את לשונית 'הפעלה' (Startup) ובטל תוכנות שאינך צריך בהדלקה",
                "en": "Review Startup apps in Task Manager and disable unneeded background launch items"
            })

        if not findings:
            findings.append({
                "type": "NORMAL",
                "severity": "low",
                "icon": "check-circle",
                "title_he": "שימוש הזיכרון במצב תקין ומאוזן",
                "title_en": "Memory Usage is Healthy and Balanced",
                "desc_he": f"נפח הזיכרון הפנוי עומד על {self.format_bytes(available_ram)} מתוך {self.format_bytes(total_ram)}. לא זוהו דליפות זיכרון או עומסים חריגים.",
                "desc_en": f"Available memory is {self.format_bytes(available_ram)} out of {self.format_bytes(total_ram)}. No abnormal leaks or runaway processes detected.",
                "action_he": "המערכת פועלת כשורה.",
                "action_en": "System is operating smoothly."
            })

        # Status text in Hebrew and English
        if score >= 80:
            status_he = "מצב מצוין ותקין"
            status_en = "Optimal & Healthy"
            status_color = "emerald"
        elif score >= 60:
            status_he = "שימוש מתון וסביר"
            status_en = "Moderate Load"
            status_color = "yellow"
        elif score >= 40:
            status_he = "עומס זיכרון גבוה"
            status_en = "High Memory Pressure"
            status_color = "amber"
        else:
            status_he = "עומס כבד / דליפה חשודה"
            status_en = "Critical Pressure / Potential Leak"
            status_color = "rose"

        return {
            "health_score": score,
            "status_he": status_he,
            "status_en": status_en,
            "status_color": status_color,
            "ram_percent": ram_percent,
            "category_breakdown": [
                {"name": "Browsers", "label_he": "דפדפנים", "bytes": cat_map["Browsers"], "formatted": self.format_bytes(cat_map["Browsers"]), "percent": round(cat_map["Browsers"] / total_ram * 100.0, 1) if total_ram else 0, "color": "#38bdf8"},
                {"name": "Development", "label_he": "כלי פיתוח", "bytes": cat_map["Development"], "formatted": self.format_bytes(cat_map["Development"]), "percent": round(cat_map["Development"] / total_ram * 100.0, 1) if total_ram else 0, "color": "#a855f7"},
                {"name": "Communication", "label_he": "תקשורת והודעות", "bytes": cat_map["Communication"], "formatted": self.format_bytes(cat_map["Communication"]), "percent": round(cat_map["Communication"] / total_ram * 100.0, 1) if total_ram else 0, "color": "#ec4899"},
                {"name": "System", "label_he": "שירותי מערכת Windows", "bytes": cat_map["System"], "formatted": self.format_bytes(cat_map["System"]), "percent": round(cat_map["System"] / total_ram * 100.0, 1) if total_ram else 0, "color": "#64748b"},
                {"name": "Background & Services", "label_he": "תהליכי רקע ואבטחה", "bytes": cat_map["Background & Services"], "formatted": self.format_bytes(cat_map["Background & Services"]), "percent": round(cat_map["Background & Services"] / total_ram * 100.0, 1) if total_ram else 0, "color": "#f59e0b"},
                {"name": "User Apps", "label_he": "תוכנות משתמש", "bytes": cat_map["User Apps"], "formatted": self.format_bytes(cat_map["User Apps"]), "percent": round(cat_map["User Apps"] / total_ram * 100.0, 1) if total_ram else 0, "color": "#10b981"},
                {"name": "Kernel Non-Paged", "label_he": "קרנל ודרייברים (Non-Paged)", "bytes": kernel_nonpaged, "formatted": self.format_bytes(kernel_nonpaged), "percent": round(kernel_nonpaged / total_ram * 100.0, 1) if total_ram else 0, "color": "#ef4444"}
            ],
            "top_consumers": [
                {
                    "name": g['friendly_name'],
                    "raw_name": g['name'],
                    "category": g['category'],
                    "rss_formatted": g['total_rss_formatted'],
                    "rss_bytes": g['total_rss_bytes'],
                    "percent": g['total_memory_percent'],
                    "process_count": g['process_count']
                } for g in top_groups
            ],
            "findings": findings,
            "recommendations": recommendations
        }

    @staticmethod
    def format_bytes(b):
        return _format_bytes(b)
