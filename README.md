# Veritas Inspector

A polished, responsive AI security command center for deepfake, malicious-code, and phishing inspection workflows.

## Run locally

This is a dependency-free static application. Serve the repository root with any static web server, for example:

```bash
python3 -m http.server 4173 --bind 0.0.0.0
```

Then open `http://localhost:4173` in a browser.

## Included

- Futuristic dark-mode dashboard with responsive mobile navigation.
- Media forensics workspace with image/video drag-and-drop previews.
- DOM / code inspector with source and URL presets.
- Text shield for phishing and authorship signals.
- Animated deep-scan simulation with live verdict, score gauge, signal meters, and evidence log.
- Device Guardian perimeter widget, activity chart, adaptive protection toggle, toast feedback, and local report export.
- Tailwind CSS and Font Awesome loaded via CDN; app behavior is implemented in vanilla JavaScript.
