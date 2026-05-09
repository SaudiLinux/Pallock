# Pallock - Advanced Zero-Day Vulnerability Scanner

Pallock هو ماسح متقدم للثغرات الأمنية (Vulnerability Scanner) مبني بلغة Python، مصمم لاكتشاف ثغرات Zero-Day، الأخطاء في إعدادات الحماية، ونقاط الاستغلال المحتملة باستخدام تقنيات الذكاء الاصطناعي والتعلم الآلي.

## المميزات الرئيسية

- **اكتشاف ثغرات Zero-Day**: محرك تحليل يعتمد على الذكاء الاصطناعي لاكتشاف الأنماط غير المعروفة.
- **إطار عمل الاستغلال (Exploit Framework)**: توليد تلقائي لملفات إثبات الاختراق (PoC) بما في ذلك ثغرات Clickjacking، Template Injection، و Log4j.
- **دعم شامل للثغرات**: اكتشاف ثغرات XSS، SQLi، Command Injection، Path Traversal، وغيرها.
- **الاستخبارات الأمنية (Threat Intelligence)**: تكامل مع Shodan و VirusTotal و Censys و WHOIS.
- **زاحف ويب متطور (Advanced Crawler)**: تحليل ذكي للروابط، ملفات JavaScript، والنماذج (Forms).
- **محرك Fuzzing**: اختبار شامل للمدخلات للكشف عن الثغرات الخفية.
- **تقارير متعددة الصيغ**: استخراج النتائج بصيغ JSON، HTML، XML، و Text.

## التثبيت

```bash
# استنساخ المستودع
git clone https://github.com/SayerLinux/Pallock.git
cd Pallock

# تثبيت المكتبات المطلوبة
pip install -r requirements.txt
```

*ملاحظة: تم حل مشكلة تعارض مكتبة WHOIS في الإصدار الحالي.*

## الاستخدام

### فحص سريع لرابط واحد
```bash
python pallock.py -u (http://example.com) --output reports/scan_result.json --format json --quiet```

### فحص عميق مع تفعيل اكتشاف Zero-Day
```bash
python pallock.py -u http://example.com --deep-scan --zero-day-only
```

### فحص مجموعة روابط من ملف
```bash
python pallock.py -f urls.txt --output report.html
```

## إطار عمل الاستغلال (Exploit Framework)

يقوم Pallock تلقائياً بتوليد ملفات PoC للثغرات المكتشفة في مجلد `exploits/`. يدعم الإطار حالياً:
- **Clickjacking**: توليد ملفات HTML تحاكي الهجوم (PoC) عند اكتشاف غياب رأس الحماية `X-Frame-Options`.
- **Template Injection**: توليد سكريبتات Python لاستغلال ثغرات SSTI.
- **Log4j/JNDI**: قوالب جاهزة لاختبار ثغرات حقن JNDI.
- **Deserialization**: اختبار ثغرات تسلسل البيانات في Java و PHP و Python.

## خيارات السطر البرمجي (CLI Options)

- `-u, --url`: الرابط المستهدف للفحص.
- `-f, --file`: ملف يحتوي على قائمة روابط.
- `--deep-scan`: تفعيل وضع الفحص العميق (يشمل الزحف والـ Fuzzing).
- `--zero-day-only`: التركيز فقط على اكتشاف الثغرات غير المعروفة.
- `--threads`: عدد الخيوط المستخدمة (الافتراضي: 10).
- `--output`: مسار ملف التقرير.
- `--verbose, -v`: عرض تفاصيل العمليات (وضع التصحيح).
- `--quiet, -q`: وضع الهدوء (عرض التحذيرات والثغرات فقط).

## الأمان والخصوصية

- الأداة مخصصة للأغراض التعليمية واختبار الاختراق الأخلاقي فقط.
- يجب الحصول على إذن مسبق قبل فحص أي نظام.
- تم تحسين الأداة لتعطيل تحذيرات SSL غير الآمنة عند الحاجة بشكل صحيح.

## المساهمة

نرحب بالمساهمات! يمكنك تحسين القوالب في `exploits/templates/` أو إضافة أنماط جديدة لمحرك الـ Zero-Day.

## المؤلف

**SayerLinux**
- البريد الإلكتروني: SayerLinux1@gmail.com
- GitHub: [SayerLinux](https://github.com/SayerLinux)

## إخلاء المسؤولية

المؤلف غير مسؤول عن أي سوء استخدام لهذه الأداة. الاستخدام يقع تحت مسؤوليتك الكاملة.
