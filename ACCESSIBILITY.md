# Accessibility

secure-code-agent is a command-line tool and a GitHub Action. Everything it
produces is text: terminal output, a Markdown report, JSON, SARIF and a
Markdown work order. This page says what that means for people using assistive
technology, what is known not to work well, and how to report a barrier.

## Commitment

Every finding, gate result and work-order item is available as plain text. No
information exists only in a chart, a colour or an image: the Markdown report
and the JSON carry the same findings, so a reader who cannot use one
presentation can use the other.

## Supported environments

- **Terminal output** is plain text with no colour codes, so it reads the same
  in a screen reader, a braille display or a log file. Colour codes that a
  scanner prints are stripped before they reach the report.
- **The project site** (the landing page and the example report) declares its
  language (`lang="en"`) and loads no script or stylesheet from elsewhere; its
  data sits in HTML tables with header cells.
- **Language:** reports are in English. The README has short machine-translated
  summaries in Spanish, German, French, Hindi and Simplified Chinese.

## Known limitations

- **Reports are long.** A full report lists every finding, including the test
  tree's, which are reported but not scored.
- **Markdown tables are wide.** The scanner table and the findings tables have
  many columns, which read cell by cell in a screen reader.

## Reporting a barrier

Open an issue at
<https://github.com/marshallguillory86/secure-code-agent/issues> and say which
output you were using (terminal, Markdown, JSON, SARIF or the site), the
assistive technology involved if any, and what you could not do. Barriers are
treated as defects.
