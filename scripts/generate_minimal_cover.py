#!/usr/bin/env python3
"""
Generate clean, minimalist brand cover banners for Aegis-2B.
Focused purely on the Logo, Product Name, Clear Purpose, and Key Tech Tags.
"""

import shutil
import subprocess
from pathlib import Path

BASE_DIR = Path("/mnt/data/Projects/aegis-2b")
IMG_DIR = BASE_DIR / "docs" / "images"
TMP_DIR = BASE_DIR / "media" / "preview_tmp"
IMG_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

MINIMAL_COVER_HTML = """<!DOCTYPE html>
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
  height: 675px;
  background-color: #f8fafc;
  background-image: 
    linear-gradient(to right, rgba(226, 232, 240, 0.75) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(226, 232, 240, 0.75) 1px, transparent 1px);
  background-size: 32px 32px;
  color: #0f172a;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
}

/* Corner badges */
.top-left-tag {
  position: absolute;
  top: 36px;
  left: 44px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  font-weight: 600;
  color: #475569;
  background: #ffffff;
  padding: 6px 14px;
  border-radius: 6px;
  border: 1px solid #e2e8f0;
}

.top-right-tag {
  position: absolute;
  top: 36px;
  right: 44px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12.5px;
  font-weight: 700;
  color: #047857;
  background: #ecfdf5;
  padding: 6px 14px;
  border-radius: 6px;
  border: 1px solid #a7f3d0;
}

/* Main Hero Content */
.hero-wrapper {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  max-width: 960px;
  padding: 0 40px;
}

.logo-box {
  width: 116px;
  height: 116px;
  background: #0f172a;
  border-radius: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 20px 35px -8px rgba(15, 23, 42, 0.28);
  border: 1.5px solid #1e293b;
  margin-bottom: 28px;
}

.title {
  font-size: 72px;
  font-weight: 900;
  letter-spacing: -0.04em;
  color: #0f172a;
  line-height: 1;
  display: flex;
  align-items: center;
  gap: 16px;
}

.title-pill {
  font-size: 16px;
  font-weight: 700;
  background: #eff6ff;
  color: #2563eb;
  padding: 4px 12px;
  border-radius: 8px;
  border: 1px solid #bfdbfe;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0;
  vertical-align: middle;
}

.subtitle {
  font-size: 24px;
  font-weight: 500;
  color: #475569;
  line-height: 1.4;
  margin-top: 18px;
  max-width: 820px;
}

.tags-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 36px;
}

.tag-pill {
  padding: 8px 18px;
  border-radius: 8px;
  font-size: 13.5px;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  background: #ffffff;
  border: 1px solid #cbd5e1;
  color: #334155;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04);
}

.tag-blue {
  background: #eff6ff;
  border-color: #bfdbfe;
  color: #1d4ed8;
}

.tag-green {
  background: #ecfdf5;
  border-color: #a7f3d0;
  color: #047857;
}

/* Footer Stamp */
.footer-stamp {
  position: absolute;
  bottom: 32px;
  display: flex;
  align-items: center;
  gap: 20px;
  font-size: 13px;
  color: #64748b;
  font-weight: 500;
}

.footer-stamp strong {
  color: #0f172a;
}
</style>
</head>
<body>

  <!-- Top Badges -->
  <div class="top-left-tag">
    <span>●</span> AWS Builder Center Challenge
  </div>
  <div class="top-right-tag">
    <span>●</span> FAIL-CLOSED AIRBAG
  </div>

  <!-- Center Hero -->
  <div class="hero-wrapper">
    
    <!-- Logo Badge -->
    <div class="logo-box">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="80" height="80" fill="none">
        <path d="M32 12L16 18.5V30.5C16 41.8 22.8 51.4 32 54.5C41.2 51.4 48 41.8 48 30.5V18.5L32 12Z" stroke="#ffffff" stroke-width="2.8" stroke-linejoin="round"/>
        <line x1="22" y1="32" x2="27" y2="32" stroke="#ffffff" stroke-width="2.8" stroke-linecap="round"/>
        <circle cx="27" cy="32" r="2.2" fill="#ffffff"/>
        <line x1="27" y1="32" x2="36" y2="25" stroke="#ffffff" stroke-width="2.8" stroke-linecap="round"/>
        <circle cx="37" cy="32" r="2.2" fill="#ffffff"/>
        <line x1="37" y1="32" x2="42" y2="32" stroke="#ffffff" stroke-width="2.8" stroke-linecap="round"/>
      </svg>
    </div>

    <!-- Title -->
    <h1 class="title">
      Aegis-2B <span class="title-pill">v0.2.1</span>
    </h1>

    <!-- Subtitle / What is it -->
    <p class="subtitle">
      Autonomous Cloud Operations Safety Circuit Breaker
    </p>

    <!-- Tech Tags -->
    <div class="tags-row">
      <span class="tag-pill tag-blue">Amazon Bedrock</span>
      <span class="tag-pill tag-green">#strands-decider-2b</span>
      <span class="tag-pill">#guardrails</span>
      <span class="tag-pill">Botocore Pre-HTTP Hook</span>
    </div>

  </div>

  <!-- Bottom Stamp -->
  <div class="footer-stamp">
    <div>Author: <strong>Mohamed Makhlouf (@mhdomer)</strong> · Riyadh, Saudi Arabia</div>
    <div>·</div>
    <div>Live Console: <strong>mhdomer.github.io/aegis-2b</strong></div>
    <div>·</div>
    <div>GitHub: <strong>github.com/Mhdomer/aegis-2b</strong></div>
  </div>

</body>
</html>
"""

def main():
    print("Generating Clean Minimalist Cover Banner (1200x675)...")
    html_file = TMP_DIR / "minimal_cover.html"
    png_file = IMG_DIR / "aegis-builder-cover-minimal.png"
    target_cover = IMG_DIR / "aegis-builder-cover.png"
    
    html_file.write_text(MINIMAL_COVER_HTML, encoding="utf-8")
    
    cmd = [
        "firefox",
        "--headless",
        "--window-size=1200,675",
        f"--screenshot={png_file.resolve()}",
        f"file://{html_file.resolve()}",
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Update default cover
    shutil.copy2(png_file, target_cover)
    print(f"Generated: {png_file}")
    print(f"Updated default cover: {target_cover}")

if __name__ == "__main__":
    main()
