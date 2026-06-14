"""Rule-based narrative generator for ML attack classifications."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

INTERESTING_FEATURES: Sequence[str] = (
    "Total Fwd Packets",
    "Total Bwd Packets",
    "Flow Duration",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd IAT Std",
    "Bwd IAT Std",
    "Packet Length Variance",
)

RESPONSE_GUIDANCE: Dict[str, str] = {
    "DDOS": "اعزل المصدر أو فعّل rate limiting وراجع قواعد الجدار الناري وخدمات الحماية من الإغراق.",
    "DOS": "افحص الخدمة المستهدفة، طبّق rate limiting، وراقب استهلاك الموارد على الخادم.",
    "BRUTE_FORCE": "عطّل الحسابات المتأثرة مؤقتًا، فعّل MFA، وطبّق حظرًا تدريجيًا للمصدر.",
    "PORT_SCAN": "راقب المصدر، قلّل الخدمات المكشوفة، وأضف rule للحظر إذا تكرر المسح.",
    "BOT": "اعزل الجهاز المشتبه، افحصه بمانع برمجيات خبيثة، وراجع الاتصالات الخارجية.",
    "WEB_ATTACK": "راجع سجلات تطبيق الويب وWAF، وثبّت المدخلات وحدث التطبيق.",
    "SQL_INJECTION": "راجع endpoint المتأثر، استخدم prepared statements، وافحص أي تسريب بيانات محتمل.",
    "XSS": "طبّق output encoding وCSP، وراجع الحقول التي تقبل HTML أو JavaScript.",
    "COMMAND_INJECTION": "أوقف تنفيذ أوامر النظام من المدخلات، وراجع صلاحيات خدمة الويب فورًا.",
    "PATH_TRAVERSAL": "قيّد الوصول للملفات، طبّق allow-list للمسارات، وراجع أي ملفات تم تحميلها أو كشفها.",
    "DNS_TUNNELING": "راجع سجلات DNS، احظر النطاقات المشبوهة، وراقب طول وتكرار الاستعلامات.",
    "ARP_SPOOFING": "فعّل ARP inspection أو static ARP للأجهزة الحرجة، وافحص الجهاز المرسل.",
    "RANSOMWARE": "اعزل الجهاز فورًا، أوقف المشاركات الشبكية، وابدأ فحص النسخ الاحتياطية وسجلات الملفات.",
    "MALWARE": "اعزل الجهاز، افحص الملفات والعمليات النشطة، وراجع الاتصالات الخارجية المشبوهة.",
    "DATA_EXFILTRATION": "أوقف الاتصال الخارجي المشبوه، راجع حجم البيانات المنقولة، وفعّل DLP إن توفر.",
    "LATERAL_MOVEMENT": "راجع حسابات الدخول الداخلية، افحص SMB/RDP/SSH، وغيّر الاعتمادات المتأثرة.",
    "C2_BEACONING": "احظر الوجهة الخارجية، اعزل الجهاز، وابحث عن persistence أو agent خبيث.",
    "UNKNOWN": "اعتبره حدثًا يحتاج مراجعة محلل، واجمع PCAP وسجلات إضافية قبل اتخاذ قرار حظر دائم.",
}

RISK_MEANING: Dict[str, str] = {
    "Critical": "خطورة حرجة: السلوك قد يؤدي إلى اختراق مباشر، تعطيل خدمة، أو تسريب بيانات.",
    "High": "خطورة عالية: المؤشرات قوية وتحتاج استجابة سريعة لتقليل الأثر.",
    "Medium": "خطورة متوسطة: النشاط مشبوه ويحتاج مراقبة وربطًا بسجلات أخرى.",
    "Low": "خطورة منخفضة: الثقة أو الأدلة محدودة ويُفضّل التحقق اليدوي.",
    "Informational": "معلومة: لا توجد مؤشرات هجومية واضحة.",
}

def _cfg(summary: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"summary": summary, "rules": rules}


EXPLANATION_CONFIG: Dict[str, Dict[str, Any]] = {
    "DDOS": _cfg(
        "التصنيف: هجوم DDoS بثقة {confidence:.1f}%",
        [
            {"feature": "Total Fwd Packets", "operator": ">", "threshold": 5000,
             "template": "تم رصد {value:.0f} حزمة في تدفق واحد، وهو رقم ضخم يطابق نمط الإغراق."},
            {"feature": "Flow Duration", "operator": "<", "threshold": 2_000_000,
             "template": "المدة القصيرة للتدفق ({formatted}) تشير إلى دفعات آلية متكررة."},
            {"feature": "Fwd Packets/s", "operator": ">", "threshold": 2500,
             "template": "معدل الحزم المتدفقة للأمام {value:.0f} pkt/s أعلى بكثير من الحركة الشرعية."},
            {"feature": "SYN Flag Count", "operator": ">", "threshold": 200,
             "template": "عدد أعلام SYN الكبير ({value:.0f}) يدل على سيل محاولات فتح اتصال."},
        ],
    ),
    "DOS": _cfg(
        "التصنيف: هجوم DoS بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": "<", "threshold": 1_500_000,
             "template": "مدة التدفق {formatted} قصيرة جدًا مما يعكس محاولات متتابعة لحظر الخدمة."},
            {"feature": "Packet Length Variance", "operator": "<", "threshold": 50,
             "template": "تجانس أطوال الحزم ({value:.1f}) يدل على مولّد طلبات آلي ثابت."},
            {"feature": "Flow Bytes/s", "operator": ">", "threshold": 10_000,
             "template": "التدفق دفع {value:.0f} بايت في الثانية، وهو أعلى من حجم الطلبات البشرية."},
        ],
    ),
    "BRUTE_FORCE": _cfg(
        "التصنيف: هجوم Brute Force بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": "<", "threshold": 1_000_000,
             "template": "محاولات تسجيل الدخول تتم في دفعات زمنية قصيرة ({formatted})."},
            {"feature": "Packet Length Variance", "operator": "<", "threshold": 20,
             "template": "كل الطلبات بنفس الحجم تقريبًا، ما يشير إلى كلمات مرور مختلفة في نفس القالب."},
            {"feature": "Flow Packets/s", "operator": ">", "threshold": 800,
             "template": "عدد الطلبات في الثانية ({value:.0f}) يعبّر عن سكربت تجربة كلمات مرور."},
        ],
    ),
    "SQL_INJECTION": _cfg(
        "التصنيف: SQL Injection بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Bytes/s", "operator": ">", "threshold": 5_000,
             "template": "معدل البايتات العالي ({value:.0f} B/s) يطابق استعلامات حقن ضخمة."},
            {"feature": "Fwd Packet Length Mean", "operator": ">", "threshold": 600,
             "template": "متوسط حجم الطلب ({value:.0f} بايت) أكبر من طلب HTTP عادي، ما يشير إلى حمولة حقن."},
            {"feature": "Bwd Packet Length Mean", "operator": ">", "threshold": 700,
             "template": "الخادم أعاد ردودًا كبيرة ({value:.0f} بايت) تدل على أخطاء قاعدة البيانات."},
        ],
    ),
    "XSS": _cfg(
        "التصنيف: Cross-Site Scripting بثقة {confidence:.1f}%",
        [
            {"feature": "Fwd Packet Length Mean", "operator": ">", "threshold": 500,
             "template": "حجم الطلبات ({value:.0f} بايت) يدل على تضمين جافاسكربت داخل الحقل."},
            {"feature": "Fwd Packet Length Std", "operator": "<", "threshold": 40,
             "template": "ثبات حجم الطلبات يشير إلى نفس الحمولة النصية تُعاد تكرارها."},
        ],
    ),
    "PORT_SCAN": _cfg(
        "التصنيف: Port Scan بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": "<", "threshold": 500_000,
             "template": "تدفقات آنية ({formatted}) مع اختلاف المنافذ هي سلوك مسح للرصد."},
            {"feature": "Total Fwd Packets", "operator": "<=", "threshold": 5,
             "template": "عدد الحزم المحدود ({value:.0f}) لكل منفذ يطابق مسح تدريجي للأهداف."},
            {"feature": "Flow Packets/s", "operator": "<", "threshold": 400,
             "template": "النشاط منخفض الحجم لكنه واسع الانتشار عبر منافذ متعددة."},
        ],
    ),
    "BOT": _cfg(
        "التصنيف: نشاط Botnet بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Packets/s", "operator": ">", "threshold": 1500,
             "template": "سرعة تدفق الحزم {value:.0f} pkt/s تشير إلى قناة C2 آلية."},
            {"feature": "Flow Duration", "operator": ">", "threshold": 5_000_000,
             "template": "الاتصال الطويل ({formatted}) يوحي بقناة تحكم مستمرة."},
        ],
    ),
    "INFILTRATION": _cfg(
        "التصنيف: Infiltration بثقة {confidence:.1f}%",
        [
            {"feature": "Bwd Packet Length Mean", "operator": ">", "threshold": 800,
             "template": "استجابة الخادم بحزم كبيرة ({value:.0f} بايت) توضح نقل بيانات غير اعتيادي."},
            {"feature": "Flow Bytes/s", "operator": ">", "threshold": 8_000,
             "template": "سرعة السحب ({value:.0f} B/s) تشير إلى تسريب ملفات."},
        ],
    ),
    "WEB_ATTACK": _cfg(
        "التصنيف: Web Attack بثقة {confidence:.1f}%",
        [
            {"feature": "Fwd Packet Length Max", "operator": ">", "threshold": 700,
             "template": "أكبر طلب HTTP ({value:.0f} بايت) يتجاوز الحدود الطبيعية لطلب متصفح."},
            {"feature": "Flow Packets/s", "operator": ">", "threshold": 900,
             "template": "تكرار الطلبات السريع يوحي بأتمتة استغلال الثغرة."},
        ],
    ),
    "ICMP_FLOOD": _cfg(
        "التصنيف: ICMP Flood بثقة {confidence:.1f}%",
        [
            {"feature": "Total Fwd Packets", "operator": ">", "threshold": 100,
             "template": "عدد رسائل ICMP ({value:.0f}) يترجم إلى إغراق Ping."},
            {"feature": "Flow Duration", "operator": "<", "threshold": 1_000_000,
             "template": "زمن قصير بينما يتم قصف الوجهة بطلبات Ping متتالية."},
        ],
    ),
    "ICMP_SWEEP": _cfg(
        "التصنيف: ICMP Sweep بثقة {confidence:.1f}%",
        [
            {"feature": "Total Fwd Packets", "operator": ">", "threshold": 20,
             "template": "عدد الرسائل يكشف عن مسح Ping لعناوين متعددة."},
        ],
    ),
    "COMMAND_INJECTION": _cfg(
        "التصنيف: Command Injection بثقة {confidence:.1f}%",
        [
            {"feature": "Fwd Packet Length Mean", "operator": ">", "threshold": 500,
             "template": "حجم الطلبات الأمامية ({value:.0f} بايت) يتوافق مع حمولة أوامر طويلة."},
            {"feature": "Bwd Packet Length Mean", "operator": ">", "threshold": 700,
             "template": "ردود الخادم الكبيرة ({value:.0f} بايت) قد تعكس مخرجات أوامر نظام."},
            {"feature": "Flow Bytes/s", "operator": ">", "threshold": 6_000,
             "template": "معدل تبادل البيانات ({value:.0f} B/s) أعلى من طلب ويب بسيط."},
        ],
    ),
    "PATH_TRAVERSAL": _cfg(
        "التصنيف: Path Traversal بثقة {confidence:.1f}%",
        [
            {"feature": "Fwd Packet Length Mean", "operator": ">", "threshold": 350,
             "template": "متوسط حجم الطلب ({value:.0f} بايت) قد يحتوي مسارات ملفات أو معاملات طويلة."},
            {"feature": "Bwd Packet Length Mean", "operator": ">", "threshold": 600,
             "template": "رد الخادم الكبير ({value:.0f} بايت) قد يدل على تسريب محتوى ملف."},
        ],
    ),
    "DNS_TUNNELING": _cfg(
        "التصنيف: DNS Tunneling بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Packets/s", "operator": ">", "threshold": 300,
             "template": "معدل طلبات DNS ({value:.0f} pkt/s) مرتفع ويشبه قناة نفقية."},
            {"feature": "Fwd Packet Length Mean", "operator": ">", "threshold": 120,
             "template": "طول الاستعلامات ({value:.0f} بايت) أكبر من أسماء نطاقات عادية."},
            {"feature": "Packet Length Variance", "operator": ">", "threshold": 200,
             "template": "تباين أطوال الحزم ({value:.1f}) يتماشى مع بيانات مشفرة داخل DNS."},
        ],
    ),
    "ARP_SPOOFING": _cfg(
        "التصنيف: ARP Spoofing بثقة {confidence:.1f}%",
        [
            {"feature": "Total Fwd Packets", "operator": ">", "threshold": 30,
             "template": "عدد الإعلانات/الحزم الأمامية ({value:.0f}) يدل على محاولة تسميم متكررة."},
            {"feature": "Flow Duration", "operator": "<", "threshold": 800_000,
             "template": "التدفقات القصيرة ({formatted}) تتوافق مع رسائل ARP سريعة ومتكررة."},
        ],
    ),
    "RANSOMWARE": _cfg(
        "التصنيف: Ransomware بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Bytes/s", "operator": ">", "threshold": 12_000,
             "template": "معدل نقل البيانات ({value:.0f} B/s) يوحي بنشاط مكثف على الملفات."},
            {"feature": "Total Fwd Packets", "operator": ">", "threshold": 800,
             "template": "عدد الحزم الكبير ({value:.0f}) يشبه نشاط تشفير أو نشر عدوى."},
            {"feature": "Packet Length Variance", "operator": ">", "threshold": 500,
             "template": "تباين الأحجام ({value:.1f}) يدل على عمليات قراءة/كتابة متنوعة."},
        ],
    ),
    "MALWARE": _cfg(
        "التصنيف: Malware بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": ">", "threshold": 4_000_000,
             "template": "الاتصال الطويل ({formatted}) قد يكون جلسة تحميل أو قناة تحكم."},
            {"feature": "Bwd Packet Length Mean", "operator": ">", "threshold": 900,
             "template": "ردود كبيرة من الخادم ({value:.0f} بايت) قد تعكس تنزيل payload."},
            {"feature": "Flow Packets/s", "operator": ">", "threshold": 700,
             "template": "تواتر الحزم ({value:.0f} pkt/s) أعلى من نشاط مستخدم طبيعي."},
        ],
    ),
    "DATA_EXFILTRATION": _cfg(
        "التصنيف: Data Exfiltration بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Bytes/s", "operator": ">", "threshold": 15_000,
             "template": "معدل الخروج ({value:.0f} B/s) مرتفع وقد يشير إلى تسريب بيانات."},
            {"feature": "Fwd Packet Length Mean", "operator": ">", "threshold": 900,
             "template": "متوسط الحزم الخارجة ({value:.0f} بايت) كبير وغير معتاد."},
            {"feature": "Flow Duration", "operator": ">", "threshold": 5_000_000,
             "template": "طول الجلسة ({formatted}) يدعم فرضية نقل بيانات مستمر."},
        ],
    ),
    "LATERAL_MOVEMENT": _cfg(
        "التصنيف: Lateral Movement بثقة {confidence:.1f}%",
        [
            {"feature": "Total Fwd Packets", "operator": ">", "threshold": 50,
             "template": "عدد الاتصالات الأمامية ({value:.0f}) يشير إلى نشاط داخلي متكرر."},
            {"feature": "Flow Duration", "operator": "<", "threshold": 2_000_000,
             "template": "جلسات قصيرة ({formatted}) تتوافق مع محاولات انتقال بين أجهزة."},
        ],
    ),
    "C2_BEACONING": _cfg(
        "التصنيف: C2 Beaconing بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": ">", "threshold": 5_000_000,
             "template": "استمرار الاتصال ({formatted}) يشبه قناة تحكم خارجية."},
            {"feature": "Packet Length Variance", "operator": "<", "threshold": 80,
             "template": "ثبات حجم الحزم ({value:.1f}) يطابق رسائل beacon دورية."},
            {"feature": "Flow Packets/s", "operator": "<", "threshold": 300,
             "template": "معدل منخفض ومنتظم ({value:.0f} pkt/s) أقرب إلى beacon وليس تحميلًا عاديًا."},
        ],
    ),
    "BENIGN": _cfg(
        "التصنيف: Benign بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": ">", "threshold": 3_000_000,
             "template": "المدة الطويلة ({formatted}) مماثلة لتصفح أو جلسة شرعية."},
        ],
    ),
    "UNKNOWN": _cfg(
        "التصنيف: Unknown بثقة {confidence:.1f}%",
        [
            {"feature": "Flow Duration", "operator": ">", "threshold": 500_000,
             "template": "القيم خارج نطاق التدريب جعلت النموذج يصنّفه كمجهول."},
        ],
    ),
    "DEFAULT": {
        "summary": "تم تصنيف التدفق كـ {label} بثقة {confidence:.1f}%",
        "rules": [],
    },
}


def build_narrative(
    label: str,
    top_features: List[Dict[str, Any]] | None,
    feature_map: Dict[str, float] | None,
    *,
    confidence: float | None = None,
    anomaly: bool = False,
    mitre: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    key = label.upper().replace("-", "_").replace(" ", "_")
    config = EXPLANATION_CONFIG.get(key, EXPLANATION_CONFIG["DEFAULT"])
    summary = config.get("summary", "التصنيف: {label}").format(
        label=label,
        confidence=(confidence or 0.0) * 100,
    )

    details: List[str] = []
    feature_map = feature_map or {}
    for rule in config.get("rules", []):
        detail = _apply_rule(rule, feature_map)
        if detail:
            details.append(detail)

    if anomaly:
        details.append("طبقة كشف الشذوذ رأت أن نمط التدفق خارج السلوك الطبيعي الموجود في بيانات التدريب، وهذا يعزز الاشتباه.")

    if not details and top_features:
        for feat in top_features[:3]:
            name = feat.get("feature")
            impact = feat.get("impact")
            details.append(
                f"الميزة {name} ساهمت بقيمة {impact:+.3f} في القرار (اتجاه {feat.get('direction', 'increase')})."
            )

    if not details:
        details.append("لم تظهر خصائص كافية لتكوين تفسير تفصيلي، لذلك يحتاج الحدث إلى مراجعة مع السجلات المحيطة.")

    mitre = mitre or {}
    severity = mitre.get("severity", "Low")
    technique = mitre.get("technique", "Unknown")
    tactic = mitre.get("tactic", "Unknown")
    response = RESPONSE_GUIDANCE.get(key, RESPONSE_GUIDANCE["UNKNOWN"])
    return {
        "summary": summary,
        "verdict": _build_verdict(label, confidence or 0.0, severity),
        "details": details,
        "evidence": _build_evidence(top_features, feature_map),
        "risk": RISK_MEANING.get(severity, RISK_MEANING["Low"]),
        "mitre_context": f"يرتبط هذا السلوك بتقنية MITRE {technique} ضمن تكتيك {tactic}.",
        "recommended_action": response,
    }


def _build_verdict(label: str, confidence: float, severity: str) -> str:
    pct = confidence * 100
    if pct >= 90:
        level = "قوي جدًا"
    elif pct >= 75:
        level = "قوي"
    elif pct >= 60:
        level = "متوسط"
    else:
        level = "ضعيف ويحتاج تحقق"
    return f"النتيجة: {label}. مستوى الاقتناع {level} ({pct:.1f}%)، والخطورة المصنفة: {severity}."


def _build_evidence(
    top_features: List[Dict[str, Any]] | None, feature_map: Dict[str, float] | None
) -> List[str]:
    evidence: List[str] = []
    if top_features:
        for feat in top_features[:3]:
            name = str(feat.get("feature", "unknown"))
            value = feat.get("value")
            impact = feat.get("impact")
            if value is not None:
                evidence.append(f"{name}: القيمة {_format_value(name, float(value))} وساهمت بتأثير {float(impact or 0):+.3f}.")
    if not evidence and feature_map:
        for name in INTERESTING_FEATURES:
            if name in feature_map:
                evidence.append(f"{name}: {_format_value(name, float(feature_map[name]))}.")
            if len(evidence) >= 3:
                break
    return evidence


def _apply_rule(rule: Dict[str, Any], feature_map: Dict[str, float]) -> str | None:
    name = rule.get("feature")
    if not name:
        return None
    value = feature_map.get(name)
    if value is None:
        return None

    op = rule.get("operator", ">")
    threshold = rule.get("threshold")
    passed = True
    if op == ">" and threshold is not None:
        passed = value > threshold
    elif op == ">=" and threshold is not None:
        passed = value >= threshold
    elif op == "<" and threshold is not None:
        passed = value < threshold
    elif op == "<=" and threshold is not None:
        passed = value <= threshold
    elif op == "range":
        min_v = rule.get("min")
        max_v = rule.get("max")
        if min_v is not None and value < min_v:
            passed = False
        if max_v is not None and value > max_v:
            passed = False

    if not passed:
        return None

    template = rule.get("template")
    formatted = _format_value(name, value)
    if not template:
        return f"الميزة {name} بقيمة {formatted} حققت شرط {op} {threshold}."
    return template.format(value=value, threshold=threshold, formatted=formatted)


def _format_value(feature: str, value: float) -> str:
    if "Duration" in feature:
        ms = value / 1000.0
        if ms < 1000:
            return f"{ms:.1f} ms"
        return f"{ms / 1000:.1f} s"
    if "Packets/s" in feature or feature.endswith("/s"):
        return f"{value:.0f} pkt/s"
    if "Bytes" in feature:
        if value > 1024:
            return f"{value / 1024:.1f} KB"
        return f"{value:.0f} B"
    return f"{value:.2f}"
