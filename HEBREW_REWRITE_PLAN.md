# תוכנית שכתוב הטקסט העברי ב-Polaris

**מסמך הנחיה לביצוע ע"י Claude Sonnet.**
נכתב: 18.09.2026 · מאגר: `C:\Users\pc\Desktop\RAM`

---

## 1. מטרה

כל הטקסט העברי המוצג למשתמש ב-Polaris ייכתב מחדש בעברית מקצועית, עקבית ותמציתית.
**לא** מתרגמים מחדש מאנגלית — כותבים מחדש בעברית, ואז מיישרים את האנגלית לפי התוצאה.

**החלטות שנקבעו מראש (אין לסטות מהן):**

| נושא | ההחלטה |
|---|---|
| רישום לשוני | מקצועי-ענייני. משפטים קצרים. משפט = רעיון אחד. |
| פנייה למשתמש | ציווי זכר יחיד — "לחץ", "הפעל", "בחר". |
| מונחים טכניים | מונח לועזי בכתיב לטיני + הסבר עברי קצר בהופעה הראשונה במסך. |
| היקף | ממשק (`index.html`, טבלת `I18N`, `app.js`) **+** מחרוזות `_he` בשרת (`backend/*.py`). |
| מחוץ להיקף | `README.md`, `TERMS_OF_USE.md`, `CHANGELOG.md`, `IMPROVEMENT_PLAN.md`. |

---

## 2. אינוונטר מדויק

| מיקום | היקף | הערה |
|---|---|---|
| `frontend/app.js` שורות 115–655 | **487 מפתחות** בטבלת `I18N.he` | מקור האמת של רוב הממשק |
| `frontend/app.js` שורות 658–1199 | **490 מפתחות** בטבלת `I18N.en` | 3 מפתחות עודפים: `lblTotalApps`, `totalFreed`, `totalRam` |
| `frontend/app.js` מחוץ לטבלה | **222 שורות** עם עברית מקודדת קשיח | מתוכן **196 ללא חלופה אנגלית כלל** — באג תצוגה במצב English |
| `frontend/index.html` | 520 שורות עם עברית: **358** דרך `data-i18n`, **162 מקודדות קשיח** | ה-162 הן העבודה האמיתית |
| `backend/*.py` | **669 מופעים** של שדות `_he` | פירוט להלן |
| `frontend/styles.css` | 0 | אין טקסט |

**פירוט השרת (לפי נפח):**

```
knowledge_base.py      136    smart_engine.py      49
smart_database.py      118    uninstaller_engine   49
system_revitalizer.py   87    diagnostic_engine    30
crash_analyzer.py       72    server.py            25
event_log.py            63    battery/device/disk  ~31
                              storage/copilot       8
```

**סה״כ עבודה: כ-1,400 מחרוזות.**

---

## 3. אבחון — מה בדיוק לא בסדר

זה לא "עברית גרועה" באופן כללי. יש חמישה כשלים ספציפיים וחוזרים. כל אחד מהם דורש טיפול אחר.

### 3.1 תרגום מילולי של מונחים טכניים ("תרגומית")

הכשל החמור ביותר. מונח אנגלי תורגם מילה-במילה ויצא חסר משמעות בעברית.

| בקוד היום | הבעיה | תיקון |
|---|---|---|
| `"בריכות זיכרון קרנל"` <br>(`diagScanning`, `scrMemoryDesc`, `attentionFoot`) | "Kernel memory pools" → "בריכות". בעברית בריכה היא בריכת שחייה. | `"מאגרי הזיכרון של הקרנל"` |
| `"מפת כריות (Treemap)"` <br>(`storageTabTreemap` + 2 נוספים) | "Treemap" → "מפת כריות"?! אין לזה שום קשר. | `"מפת שטחים (Treemap)"` |
| `"כוונת ציד"` <br>(`btnHunterMode`, `hunterModalTitle`) | "Hunter Mode" תורגם לדימוי ציד. משתמש לא מבין מה הכפתור עושה. | `"איתור ידני"` או `"חיפוש שאריות לפי נתיב"` |
| `"סריקת שאריות היוריסטית"` <br>(3 מופעים) | "היוריסטית" היא מילה שלא אומרת למשתמש דבר. | `"סריקת שאריות מבוססת דפוסים"` |

**זה מה שגורם לטקסט להיקרא כתוצר AI** — המילים תקינות דקדוקית, אבל אף דובר עברית לא היה בוחר אותן.

### 3.2 מילוי תאגידי ריק

טקסט שנכתב כדי למלא מקום, ולא כדי למסור מידע.

```
היום:  "מרכז גישה מהירה לקטגוריות"
       "מעבר מהיר לכל אחד ממוקדי הניהול והאבחון של Polaris"

תיקון: "קיצורי דרך"
       "מעבר ישיר לכל מסך בתוכנה"
```

`"מוקדי הניהול והאבחון"` הוא צירוף שלא קיים בעברית.

### 3.3 דחיסת רשימת פיצ'רים למשפט אחד

```
היום:  "ניתוח תפוסת דיסק, תרשים Sunburst מעגלי אינטראקטיבי,
        סל איסוף למחיקה (Collector) ומפת כריות Treemap"
```

ארבעה פריטים, אפס פעלים, שני מונחים לועזיים לא מוסברים ותרגומית אחת. המשתמש לא יודע מה המסך עושה.

```
תיקון: "מראה מה תופס מקום בכונן. סמן קבצים מיותרים ומחק אותם בבת אחת."
```

**כלל:** תיאור מסך = מה הוא עושה עבורי, לא רשימת רכיביו.

### 3.4 חוסר עקביות במינוח

ספירה בפועל במאגר:

- `כונן` (24) מול `דיסק` (8) — שני שמות לאותו דבר
- `תוכנה/תוכנות` (83) מול `יישום` (2) מול `אפליקציה` (2)
- `מסך כחול` (7) מול `BSOD` (22)
- `דרייברים` (110) — תעתיק, בלי אף מופע של `מנהלי התקנים`
- `ווינדוס` (24) מול `Windows` — תעתיק ושם לועזי מעורבבים באותו קובץ
- `קרנל` מול `ליבה` — שניהם בשימוש
- `סה"כ` עם גרש ישר (6 מופעים) במקום גרשיים עבריים `סה״כ`. אותו כשל ב-`storageExportCsv: "ייצוא דו\"ח CSV"` — הגרש הישר אף מחייב escaping מיותר בקוד; `דו״ח` פותר את שניהם

### 3.5 כפילות מקורות אמת

**15 מחרוזות מופיעות פעמיים בתוך טבלת `I18N.he` עצמה** (`סקירה כללית`, `תהליכים ושירותים`, `אבחון זיכרון`, `תחזוקה ותיקון`, `קריסות ומסך כחול` ועוד) — פעם כתווית ניווט ופעם ככותרת מסך.

בנוסף, אותן מחרוזות מופיעות שוב מקודדות קשיח ב-`index.html`:

```html
<div class="topbar-title" id="screenTitle">סקירה כללית</div>
<span class="badge" id="healthStatusBadge">בודק...</span>
```

**משמעות:** תיקון ניסוח במקום אחד לא מתקן את השאר. **חייבים לאחד לפני שמשכתבים**, אחרת עושים את אותה עבודה שלוש פעמים ומקבלים שלוש גרסאות שונות.

---

## 4. מדריך הסגנון

### 4.1 כללי כתיבה

1. **משפט קצר.** תיאור מסך — עד 12 מילים. טולטיפ — עד 15. הסבר מורחב — עד 3 משפטים.
2. **פועל פעיל, לא שם פעולה.** `"התוכנה סורקת את הכונן"` ולא `"מתבצעת סריקה של הכונן"`.
3. **בלי מגבירים.** למחוק: "משמעותי", "מלא", "מתקדם", "חכם", "מיידי", "במהירות שיא", "לתמיד".
4. **בלי סימן קריאה** בטקסט ממשק. אזהרה מועברת בצבע ובניסוח, לא בפיסוק.
5. **מספרים בספרות.** `"4 עד 20 דקות"` ולא `"ארבע עד עשרים דקות"`.
6. **גרשיים עבריים** — `סה״כ`, `ס״מ`. לא `סה"כ`.
7. **קו מפריד `—`** — רק להפרדת פסוקית. במאגר 81 מופעים; רבים מהם היו צריכים להיות נקודה.

### 4.2 פנייה למשתמש

| הקשר | תבנית | דוגמה |
|---|---|---|
| כפתור פעולה | ציווי זכר יחיד | `סרוק`, `הסר`, `שחרר זיכרון` |
| הוראה למשתמש | ציווי זכר יחיד | `הפעל את Polaris כמנהל` |
| תיאור מה התוכנה עושה | הווה, גוף שלישי | `מוחק קבצים זמניים שלא נגעו בהם 24 שעות` |
| שאלת אישור | שאלה ישירה | `לסיים את התהליך chrome.exe?` |
| הודעת הצלחה | עבר, סביל או פעיל | `התהליך הסתיים`, `נוקו 2.3GB` |

**אין** לכתוב `אתה`, `שלך`, `אנא`, `בבקשה`. (במאגר: 8 מופעי `אתה`, 3 מופעי `אנא` — למחוק.)

### 4.3 מונחים לועזיים

**כלל ההופעה הראשונה:** בהופעה הראשונה של מונח לועזי **בכל מסך**, יש הסבר עברי בסוגריים או במשפט הסמוך. בהמשך אותו מסך — המונח לבדו.

```
✅  "TRIM — מודיע לכונן אילו תאים כבר לא בשימוש, כדי שכתיבות עתידיות יהיו מהירות."
❌  "מבצע TRIM לכונן."
```

**החזקת כתיב לטיני** — מונחים שאין להם מקבילה עברית מקובלת:
`RAM`, `Registry`, `TRIM`, `SFC`, `DISM`, `BugCheck`, `Minidump`, `WinSxS`, `SMART`, `Sunburst`, `Treemap`, `PID`, `UAC`, `Windows`

**החלפה לעברית** — מונחים שיש להם מקבילה רשמית ומוכרת:

| להחליף | במקום |
|---|---|
| `מנהל התקן` / `מנהלי התקנים` | `דרייבר` / `דרייברים` |
| `Windows` | `ווינדוס` |
| `תהליך` | `פרוסס` |
| `שירות` | `סרוויס` |

> ⚠️ **נקודת החלטה:** החלפת `דרייברים` ב-`מנהלי התקנים` נוגעת ב-110 מופעים. זהו המונח הרשמי בתרגום Windows לעברית, אבל `דרייבר` נפוץ יותר בדיבור. **אשר או בטל את השורה הזו לפני תחילת הביצוע.** אם מבטלים — `דרייבר` נכנס לרשימת המונחים המותרים ואין לגעת בו.

### 4.4 מילון מונחים מחייב

טבלה אחת. כל סטייה ממנה היא באג.

| מושג | המונח היחיד המותר | אסור |
|---|---|---|
| התקן אחסון פיזי | **כונן** | דיסק |
| תוכנה מותקנת | **תוכנה** | יישום, אפליקציה, אפליקציית |
| תהליך רץ | **תהליך** | פרוסס |
| שירות Windows | **שירות** | סרוויס |
| מסך כחול | **מסך כחול (BSOD)** בהופעה ראשונה, אח״כ **BSOD** | רק "מסך כחול", רק "BSOD" |
| ליבת מערכת ההפעלה | **הקרנל** | הליבה |
| קבצי מערכת מוגנים | **קובצי המערכת המוגנים** | קבצי הליבה |
| מאגר זיכרון של הקרנל | **מאגר זיכרון** | בריכה |
| שרידי התקנה | **שאריות** | שרידים, עודפים |
| מנהל התקן | **מנהל התקן** *(בכפוף ל-4.3)* | דרייבר |
| זיכרון פיזי | **RAM** | זיכרון פיזי, ראם |
| רישום המערכת | **Registry** | רג׳יסטרי, מרשם |
| הפעלה כמנהל | **הפעלה כמנהל** | הרצה כאדמין |
| נקודת שחזור | **נקודת שחזור** | — |

---

## 5. תוכנית הביצוע

שישה שלבים. **סדר כפוי** — שלב 1 מבטל כפילויות שאחרת ישוכתבו שלוש פעמים.

### שלב 0 — הכנה (ידני, לפני Sonnet)

```powershell
cd C:\Users\pc\Desktop\RAM
git status                    # ודא עץ עבודה נקי
git checkout -b hebrew-rewrite
```

צור את קובץ האימות `tools/verify_he.py` (הקוד בנספח א׳) והרץ אותו פעם אחת כדי לקבל **קו בסיס**.

### שלב 1 — איחוד מקורות אמת

**אין לשכתב טקסט בשלב הזה.** מבנה בלבד.

1. ב-`app.js` שורות 115–656: אתר את 15 זוגות המפתחות הכפולים. השאר מפתח אחד לכל מחרוזת; החלף את השני בהפניה.
2. ב-`index.html`: ל-162 השורות עם עברית מקודדת קשיח — הוסף `data-i18n` / `data-i18n-title` / `data-i18n-ph` והעבר את הטקסט לטבלת `I18N.he`. הוסף מפתח מקביל ל-`I18N.en`.
3. ב-`app.js`: ל-196 השורות עם עברית ללא חלופה אנגלית — העבר לטבלת `I18N` והחלף בקריאת `t('key')`.
4. מחק 3 מפתחות היתומים ב-`I18N.en`: `lblTotalApps`, `totalFreed`, `totalRam`.

**קריטריון סיום:** הרצת התוכנה במצב English לא מציגה אף תו עברי. זהו תיקון באג אמיתי, לא רק ניקיון.

**בדיקה:**
```powershell
python tools\verify_he.py --stage 1
```

---

### שלב 2 — שכתוב טבלת `I18N.he`

הליבה. 487 מפתחות (יגדלו לכ-800 אחרי שלב 1).

**עבודה בקבוצות של 40–60 מפתחות, לפי בלוקי ההערות הקיימים בקוד** (`/* Navigation */`, `/* Consolidated Categories */` וכו׳). אחרי כל קבוצה — commit.

**נוסח ההנחיה ל-Sonnet לכל קבוצה:**

> שכתב את ערכי העברית במפתחות X עד Y בטבלת `I18N.he` בקובץ `frontend/app.js` (הטבלה נמצאת בשורות 115–655).
> החל את מדריך הסגנון בסעיף 4 של `HEBREW_REWRITE_PLAN.md` ואת מילון המונחים בסעיף 4.4.
> **אל תשנה שמות מפתחות. אל תשנה מבנה. אל תיגע בטבלת `I18N.en`.**
> שמור בדיוק את כל ה-placeholders מסוג `${...}` — אותו מספר, אותם שמות.
> הצג לפני/אחרי עבור כל מחרוזת ששינית.

**סדר עדיפויות בתוך השלב:**

1. ניווט וכותרות מסכים — הכי נראה
2. כפתורים ותוויות פעולה
3. תיאורי מסכים ותת-כותרות — **כאן מרוכזים כשלי 3.2 ו-3.3**
4. הודעות מצב, טוסטים ושגיאות
5. טולטיפים

---

### שלב 3 — יישור `I18N.en`

אחרי ששלב 2 הסתיים: לכל מפתח שהעברית שלו השתנתה מהותית — יישר את האנגלית לאותו מסר ואותו אורך. האנגלית סובלת מאותם כשלים (`"Sunburst & Collector"` כתווית מסך).

---

### שלב 4 — טקסטים בשרת

14 קבצים, 669 שדות `_he`. **קובץ אחד לכל סשן.** סדר מומלץ — מהקטן לגדול, כדי לכייל את הסגנון:

```
1. storage_analyzer (6)     8.  event_log (63)
2. copilot_remapper (2)     9.  crash_analyzer (72)
3. device_manager (10)      10. system_revitalizer (87)
4. disk_health (10)         11. smart_database (118)
5. battery_analyzer (11)    12. knowledge_base (136)
6. server (25)
7. diagnostic_engine (30) / smart_engine (49) / uninstaller_engine (49)
```

**אזהרה קריטית:** הקבצים האלה משתמשים ב-f-strings של Python עם placeholders מסוג `{count}`, `{self._format_bytes(freed)}`, `{s['title_he']}`. **שינוי, מחיקה או הוספה של סוגריים מסולסלים ישבור את התוכנה בזמן ריצה.** קובץ האימות בנספח א׳ בודק זאת אוטומטית.

**שני קבצים דורשים תשומת לב מיוחדת:**

- **`knowledge_base.py` (136)** — הסברים על תהליכי Windows. הטקסט כאן איכותי יחסית ומדויק טכנית. **אל תשכתב אותו רק כדי לשכתב.** התיקון הנדרש: אחידות מונחים (`ווינדוס` → `Windows`), קיצור משפטים ארוכים, והסרת מגבירים (`"במהירות שיא"` מופיע פעמיים).
- **`smart_database.py` (118)** — הגדרות מוני SMART. טקסט טכני מדויק עם 3 סימני קריאה מיותרים. תיקון מינימלי בלבד. **דיוק טכני קודם לסגנון** — אם שכתוב מסכן את נכונות ההסבר, השאר כפי שהוא.

---

### שלב 5 — אימות

```powershell
python tools\verify_he.py --full
git diff --stat
python -m pytest tests\ -q
```

**רשימת בדיקה ידנית:**

- [ ] `python main.py` — התוכנה עולה ללא שגיאות
- [ ] מעבר על 11 המסכים בעברית — אין טקסט חתוך, אין גלישה מחוץ לכפתור
- [ ] החלפה ל-English ובחזרה — אין תו עברי במצב אנגלי
- [ ] הרצת פעולת תחזוקה אחת — הודעות ההתקדמות תקינות והמספרים מוצגים נכון
- [ ] פתיחת מודאל הסרת תוכנה — ה-placeholders מתמלאים בערכים אמיתיים ולא ב-`{count}`

---

## 6. גדרות ביטחון

**אסור לגעת בתיקיות האלה** — הן פלט בנייה ויידרסו בבנייה הבאה:

```
dist/          build/         __pycache__/
squirreldisk_src/             graphify-out/
Polaris.exe    CopilotToCtrl.exe
```

`dist/MemPulse/_internal/frontend/` מכילה עותק ישן של הממשק. **התעלם ממנה לחלוטין.**

**כללי עריכה:**

1. אין לשנות שמות מפתחות ב-`I18N` — הם מקושרים ל-`data-i18n` ב-HTML.
2. אין לשנות שמות שדות ב-Python (`title_he`, `desc_he`, `description_he`).
3. אין לשנות מספר או שמות placeholders — `${...}` ב-JS, `{...}` ב-Python.
4. אין לשנות ישויות HTML או מבנה תגיות.
5. כל הקבצים נשמרים ב-UTF-8 ללא BOM.
6. אין לשנות לוגיקה, שמות פונקציות או זרימת בקרה — **טקסט בלבד.**
7. commit אחרי כל קבוצה. הודעת commit באנגלית, בפורמט: `he: rewrite <scope>`.

---

## 7. נספח א׳ — סקריפט האימות

צור כ-`tools/verify_he.py`:

```python
"""Verification for the Hebrew rewrite. Run before and after each stage."""
import re, sys, json, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {'dist', 'build', '__pycache__', 'squirreldisk_src', 'graphify-out', '.git'}
HEB  = re.compile(r'[\u0590-\u05FF]')

# Terms that must not appear after the rewrite (see glossary 4.4)
BANNED = ['ווינדוס', 'בריכות', 'מפת כריות', 'היוריסטית', 'כוונת ציד',
          'אנא ', 'אתה ', 'רג\u05f3יסטרי', 'סה"כ']
# NOTE: add 'דרייבר' here only if the decision in 4.3 was confirmed.

def files():
    for p in ROOT.rglob('*'):
        if p.suffix not in {'.py', '.js', '.html'}: continue
        if SKIP & set(p.parts): continue
        if p.name == 'verify_he.py': continue
        yield p

def i18n_tables():
    src = (ROOT / 'frontend' / 'app.js').read_text(encoding='utf-8')
    he = src[src.index('  he: {'):src.index('  en: {')]
    en = src[src.index('  en: {'):]
    key = lambda s: set(re.findall(r'^\s{4}([A-Za-z0-9_]+):\s*"', s, re.M))
    return key(he), key(en)

def placeholders(path):
    """Map every Hebrew-bearing line to its placeholder multiset."""
    out = {}
    pat = r'\$\{[^}]*\}' if path.suffix in {'.js', '.html'} else r'\{[^}]*\}'
    for n, line in enumerate(path.read_text(encoding='utf-8').split('\n'), 1):
        if HEB.search(line):
            out[n] = sorted(re.findall(pat, line))
    return out

def main():
    full = '--full' in sys.argv
    errors, warnings = [], []

    # 1. encoding
    for p in files():
        raw = p.read_bytes()
        if raw.startswith(b'\xef\xbb\xbf'):
            errors.append(f'BOM found: {p.relative_to(ROOT)}')
        try: raw.decode('utf-8')
        except UnicodeDecodeError: errors.append(f'not UTF-8: {p.relative_to(ROOT)}')

    # 2. i18n key parity
    he, en = i18n_tables()
    for k in sorted(he - en): errors.append(f'key missing in I18N.en: {k}')
    for k in sorted(en - he): errors.append(f'key missing in I18N.he: {k}')

    # 3. Hebrew leaking into the English table
    src = (ROOT / 'frontend' / 'app.js').read_text(encoding='utf-8')
    en_block = src[src.index('  en: {'):]
    for k, v in re.findall(r'^\s{4}([A-Za-z0-9_]+):\s*"([^"]*)"', en_block, re.M):
        if HEB.search(v): errors.append(f'Hebrew inside I18N.en: {k} = {v[:40]}')

    # 4. banned terms
    for p in files():
        txt = p.read_text(encoding='utf-8')
        for term in BANNED:
            c = txt.count(term)
            if c: (errors if full else warnings).append(
                f'banned term {term!r} x{c}: {p.relative_to(ROOT)}')

    # 5. placeholder snapshot (compare against baseline.json)
    snap = {str(p.relative_to(ROOT)): placeholders(p) for p in files()}
    base = ROOT / 'tools' / 'baseline.json'
    if base.exists():
        old = json.loads(base.read_text(encoding='utf-8'))
        for f, lines in old.items():
            new = snap.get(f, {})
            old_all = sorted(x for v in lines.values() for x in v)
            new_all = sorted(x for v in new.values() for x in v)
            if old_all != new_all:
                missing = set(old_all) - set(new_all)
                added   = set(new_all) - set(old_all)
                errors.append(f'PLACEHOLDER MISMATCH in {f}: '
                              f'lost={sorted(missing)} gained={sorted(added)}')
    else:
        base.write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding='utf-8')
        print('baseline written ->', base)

    # 6. hardcoded Hebrew outside I18N
    appjs = (ROOT / 'frontend' / 'app.js').read_text(encoding='utf-8').split('\n')
    lo, hi = next(i for i, l in enumerate(appjs) if '  he: {' in l), \
             next(i for i, l in enumerate(appjs) if l.strip() == '};' and i > 1000)
    stray = [i + 1 for i, l in enumerate(appjs) if HEB.search(l) and not lo <= i <= hi]
    html_stray = [n for n, l in enumerate(
        (ROOT / 'frontend' / 'index.html').read_text(encoding='utf-8').split('\n'), 1)
        if HEB.search(l) and 'data-i18n' not in l]
    print(f'\nhardcoded Hebrew  app.js: {len(stray)}   index.html: {len(html_stray)}')
    print(f'i18n keys  he: {len(he)}  en: {len(en)}')

    for w in warnings: print('  WARN ', w)
    for e in errors:   print('  ERROR', e)
    print(f'\n{len(errors)} errors, {len(warnings)} warnings')
    return 1 if errors else 0

if __name__ == '__main__':
    sys.exit(main())
```

**אופן השימוש:**

```powershell
python tools\verify_he.py              # יוצר baseline.json בהרצה הראשונה
python tools\verify_he.py --stage 1    # אחרי כל שלב
python tools\verify_he.py --full       # בסיום: מונחים אסורים = שגיאה
```

`baseline.json` נוצר **לפני** תחילת העבודה. אם placeholder נעלם או נוסף — הסקריפט יתפוס זאת לפני שהתוכנה קורסת אצל משתמש.

---

## 8. אומדן ותוצרים

| שלב | היקף | מפגשי Sonnet |
|---|---|---|
| 0 — הכנה | סקריפט + baseline | 1 |
| 1 — איחוד מקורות | ~370 מחרוזות מועברות | 2–3 |
| 2 — שכתוב `I18N.he` | ~800 מפתחות | 6–8 |
| 3 — יישור `I18N.en` | ~800 מפתחות | 2 |
| 4 — שרת | 669 שדות, 14 קבצים | 8–10 |
| 5 — אימות | — | 1 |

**~20 מפגשים.** אפשר להריץ שלבים 2 ו-4 במקביל — הם אינם נוגעים באותם קבצים.

**קריטריון קבלה:** `verify_he.py --full` מסיים ב-0 שגיאות, הבדיקות עוברות, והתוכנה עולה ומתפקדת בשתי השפות.
