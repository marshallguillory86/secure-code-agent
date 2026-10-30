<!-- machine translation of README.md; the English README is the complete copy -->
# secure-code-agent

[English](README.md) | [Español](README.es.md) | [Deutsch](README.de.md) | [Français](README.fr.md) | **हिन्दी** | [简体中文](README.zh-CN.md)

> मशीन अनुवाद। [अंग्रेज़ी README](README.md) ही पूर्ण और एकमात्र अद्यतन संस्करण है।

## यह क्या है

उन रिपॉज़िटरी के लिए एक नियतात्मक (deterministic) सुरक्षा गेट, जिनमें AI कोडिंग
एजेंट काम करते हैं। यह सुरक्षा स्कैनरों का एक तय सेट चलाता है, परिणाम को अंक देता
है, और हर निष्कर्ष को एक **सीमित कार्य-आदेश** में बदलता है: एक प्रॉम्प्ट जो कहता है
*ठीक यही सुधारो और कुछ और मत बदलो*। निष्कर्ष NIST SSDF, OWASP ASVS, OWASP Top 10
और MITRE CWE Top 25 से जोड़े जाते हैं, और GitHub कोड स्कैनिंग के लिए SARIF में
निकाले जाते हैं। यह किसी भाषा मॉडल का उपयोग नहीं करता और आपका कोड किसी सेवा को
नहीं भेजता।

## इंस्टॉलेशन

```bash
pip install secure-code-agent
```

## पहला उपयोग

```bash
secure-code-agent --fail-on-gate \
    --output secure-code-report.md \
    --prompt-output secure-code-remediation-prompt.md
```

कॉन्फ़िगरेशन, स्कैनर, बेसलाइन, CI एकीकरण और GitHub Action का विवरण
[अंग्रेज़ी README](README.md) में है।

## लाइसेंस

MIT.
