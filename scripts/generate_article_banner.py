#!/usr/bin/env python3
"""
Generate a sleek, compact horizontal banner for Aegis-2B.
Intended for embedding inside article markdown after introductory links.
Dimensions: 1200x200 (Clean, uncluttered, matching user spec: logo + text + what it is + tags).
"""

import subprocess
from pathlib import Path

BASE_DIR = Path("/mnt/data/Projects/aegis-2b")
IMG_DIR = BASE_DIR / "docs" / "images"
TMP_DIR = BASE_DIR / "media" / "preview_tmp"
IMG_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

BANNER_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@500;600;700&display=swap');

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  width: 1200px;
  height: 200px;
  background-color: #f8fafc;
  background-image: 
    linear-gradient(to right, rgba(226, 232, 240, 0.75) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(226, 232, 240, 0.75) 1px, transparent 1px);
  background-size: 28px 28px;
  color: #0f172a;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 54px;
  overflow: hidden;
  border: 1px solid #e2e8f0;
}

.brand-section {
  display: flex;
  align-items: center;
  gap: 28px;
}

.logo-box {
  width: 84px;
  height: 84px;
  background: #0f172a;
  border-radius: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 16px 28px -6px rgba(15, 23, 42, 0.28);
  border: 1.5px solid #1e293b;
  flex-shrink: 0;
}

.brand-text {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.title-row {
  display: flex;
  align-items: center;
  gap: 14px;
}

.title {
  font-size: 38px;
  font-weight: 900;
  letter-spacing: -0.04em;
  color: #0f172a;
  line-height: 1;
}

.version-pill {
  font-size: 13px;
  font-weight: 700;
  background: #eff6ff;
  color: #2563eb;
  padding: 3px 10px;
  border-radius: 6px;
  border: 1px solid #bfdbfe;
  font-family: 'JetBrains Mono', monospace;
}

.subtitle {
  font-size: 17px;
  font-weight: 500;
  color: #475569;
  letter-spacing: -0.01em;
}

.tags-section {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
}

.tags-row {
  display: flex;
  align-items: center;
  gap: 10px;
}

.tag {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 6px;
  white-space: nowrap;
}

.tag-blue { background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }
.tag-green { background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
.tag-slate { background: #ffffff; color: #334155; border: 1px solid #cbd5e1; box-shadow: 0 1px 2px rgba(0,0,0,0.03); }

.tag-airbag {
  background: #0f172a;
  color: #ffffff;
  border: 1px solid #0f172a;
}
</style>
</head>
<body>

  <!-- Left: Logo & Identification -->
  <div class="brand-section">
    <div class="logo-box">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="58" height="58" fill="none">
        <path d="M32 12L16 18.5V30.5C16 41.8 22.8 51.4 32 54.5C41.2 51.4 48 41.8 48 30.5V18.5L32 12Z" stroke="#ffffff" stroke-width="2.8" stroke-linejoin="round"/>
        <line x1="22" y1="32" x2="27" y2="32" stroke="#ffffff" stroke-width="2.8" stroke-linecap="round"/>
        <circle cx="27" cy="32" r="2.2" fill="#ffffff"/>
        <line x1="27" y1="32" x2="36" y2="25" stroke="#ffffff" stroke-width="2.8" stroke-linecap="round"/>
        <circle cx="37" cy="32" r="2.2" fill="#ffffff"/>
        <line x1="37" y1="32" x2="42" y2="32" stroke="#ffffff" stroke-width="2.8" stroke-linecap="round"/>
      </svg>
    </div>

    <div class="brand-text">
      <div class="title-row">
        <h1 class="title">Aegis-2B</h1>
        <span class="version-pill">v0.2.1</span>
      </div>
      <p class="subtitle">Autonomous Cloud Operations Safety Circuit Breaker</p>
    </div>
  </div>

  <!-- Right: Clean Tech Badges -->
  <div class="tags-section">
    <div class="tags-row">
      <span class="tag tag-blue">Amazon Bedrock</span>
      <span class="tag tag-green">#strands-decider-2b</span>
      <span class="tag tag-slate">#guardrails</span>
    </div>
    <div class="tags-row">
      <span class="tag tag-slate">Botocore Pre-HTTP Hook</span>
      <span class="tag tag-airbag">FAIL-CLOSED AIRBAG</span>
    </div>
  </div>

</body>
</html>
"""

def main():
    print("Generating Clean In-Article Banner (1200x200)...")
    html_file = TMP_DIR / "article_banner.html"
    png_file = IMG_DIR / "aegis-article-banner.png"
    
    html_file.write_text(BANNER_HTML, encoding="utf-8")
    
    cmd = [
        "firefox",
        "--headless",
        "--window-size=1200,200",
        f"--screenshot={png_file.resolve()}",
        f"file://{html_file.resolve()}",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Generated Article Banner: {png_file}")

if __name__ == "__main__":
    main()
