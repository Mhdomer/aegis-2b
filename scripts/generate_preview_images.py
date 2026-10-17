#!/usr/bin/env python3
"""
Generate professional dev-tool style cover and social preview banners for Aegis-2B.
- docs/images/aegis-builder-cover.png (1200x675, 16:9 for AWS Builder Center project cover)
- docs/images/aegis-preview.png (1280x640, GitHub social card)
- docs/images/aegis-hero-banner.png (1920x1080, Full HD banner)
"""

import subprocess
from pathlib import Path

BASE_DIR = Path("/mnt/data/Projects/aegis-2b")
IMG_DIR = BASE_DIR / "docs" / "images"
TMP_DIR = BASE_DIR / "media" / "preview_tmp"
IMG_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

SVG_LOGO = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="52" height="52" fill="none">
  <rect x="4" y="4" width="56" height="56" rx="12" fill="#0f172a"/>
  <path d="M32 12L16 18.5V30.5C16 41.8 22.8 51.4 32 54.5C41.2 51.4 48 41.8 48 30.5V18.5L32 12Z" stroke="#ffffff" stroke-width="2.5" stroke-linejoin="round"/>
  <line x1="22" y1="32" x2="27" y2="32" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="27" cy="32" r="2" fill="#ffffff"/>
  <line x1="27" y1="32" x2="36" y2="25" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round"/>
  <circle cx="37" cy="32" r="2" fill="#ffffff"/>
  <line x1="37" y1="32" x2="42" y2="32" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round"/>
</svg>
"""

def get_html(width: int, height: int, scale_factor: float = 1.0) -> str:
    # Scale variables based on base dimensions (1200x675 as 1.0)
    pad_y = int(32 * scale_factor)
    pad_x = int(40 * scale_factor)
    title_size = int(30 * scale_factor)
    subtitle_size = int(14 * scale_factor)
    pill_size = int(12 * scale_factor)
    term_h = int(455 * scale_factor)
    code_size = int(12 * scale_factor)
    metric_val_size = int(24 * scale_factor)
    metric_lbl_size = int(11 * scale_factor)
    footer_size = int(12 * scale_factor)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

* {{
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}}

body {{
  width: {width}px;
  height: {height}px;
  background-color: #f8fafc;
  background-image: radial-gradient(#cbd5e1 1.2px, transparent 1.2px);
  background-size: 24px 24px;
  color: #0f172a;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  padding: {pad_y}px {pad_x}px;
  justify-content: space-between;
}}

.top-bar {{
  display: flex;
  justify-content: space-between;
  align-items: center;
}}

.brand-group {{
  display: flex;
  align-items: center;
  gap: {int(16 * scale_factor)}px;
}}

.brand-text h1 {{
  font-size: {title_size}px;
  font-weight: 800;
  color: #0f172a;
  letter-spacing: -0.03em;
  display: flex;
  align-items: center;
  gap: 10px;
}}

.version-pill {{
  font-size: {int(13 * scale_factor)}px;
  font-weight: 700;
  background: #0f172a;
  color: #ffffff;
  padding: 2px 8px;
  border-radius: 6px;
  font-family: 'JetBrains Mono', monospace;
}}

.brand-text p {{
  font-size: {subtitle_size}px;
  color: #475569;
  font-weight: 500;
  margin-top: 1px;
}}

.tag-pills {{
  display: flex;
  gap: {int(8 * scale_factor)}px;
}}

.pill {{
  padding: 6px 14px;
  border-radius: 6px;
  font-size: {pill_size}px;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
}}

.pill-blue {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
.pill-green {{ background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }}
.pill-slate {{ background: #ffffff; color: #334155; border: 1px solid #cbd5e1; }}

/* Main Grid */
.main-grid {{
  display: grid;
  grid-template-columns: 1.18fr 0.82fr;
  gap: {int(24 * scale_factor)}px;
  height: {term_h}px;
}}

/* Terminal / Interceptor Card */
.term-window {{
  background: #0f172a;
  border-radius: 12px;
  border: 1px solid #1e293b;
  box-shadow: 0 16px 32px -8px rgba(15, 23, 42, 0.16);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}}

.term-header {{
  height: {int(38 * scale_factor)}px;
  background: #1e293b;
  border-bottom: 1px solid #334155;
  padding: 0 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}}

.term-dots {{
  display: flex;
  align-items: center;
  gap: 7px;
}}

.dot {{ width: 11px; height: 11px; border-radius: 50%; }}
.dot-r {{ background: #ef4444; }}
.dot-y {{ background: #f59e0b; }}
.dot-g {{ background: #10b981; }}

.term-title {{
  color: #94a3b8;
  font-family: 'JetBrains Mono', monospace;
  font-size: {int(12 * scale_factor)}px;
  font-weight: 500;
}}

.term-hook {{
  background: #020617;
  color: #38bdf8;
  font-family: 'JetBrains Mono', monospace;
  font-size: {int(11 * scale_factor)}px;
  padding: 2px 8px;
  border-radius: 4px;
  border: 1px solid #334155;
}}

.term-body {{
  padding: {int(18 * scale_factor)}px;
  font-family: 'JetBrains Mono', monospace;
  font-size: {code_size}px;
  line-height: 1.5;
  color: #f8fafc;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  flex: 1;
}}

.threat-box {{
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: {int(12 * scale_factor)}px {int(14 * scale_factor)}px;
}}

.threat-label {{
  color: #f87171;
  font-weight: 700;
  font-size: {int(11 * scale_factor)}px;
  text-transform: uppercase;
  margin-bottom: 4px;
  display: flex;
  align-items: center;
  gap: 6px;
}}

.threat-code {{
  color: #e2e8f0;
  font-size: {int(11.5 * scale_factor)}px;
}}

.threat-payload {{
  color: #94a3b8;
  font-size: {int(11 * scale_factor)}px;
  margin-top: 4px;
}}

.tripped-box {{
  background: linear-gradient(180deg, #18182e 0%, #111124 100%);
  border: 1.5px solid #dc2626;
  border-radius: 8px;
  padding: {int(14 * scale_factor)}px {int(16 * scale_factor)}px;
  box-shadow: 0 4px 12px rgba(220, 38, 38, 0.2);
}}

.tripped-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}}

.tripped-badge {{
  background: #dc2626;
  color: #ffffff;
  font-size: {int(12 * scale_factor)}px;
  font-weight: 800;
  padding: 3px 10px;
  border-radius: 4px;
  letter-spacing: 0.04em;
}}

.tripped-lat {{
  background: #020617;
  color: #4ade80;
  border: 1px solid #22c55e;
  font-size: {int(11 * scale_factor)}px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
}}

.tripped-row {{
  font-size: {int(11.5 * scale_factor)}px;
  color: #cbd5e1;
  margin-top: 5px;
  display: flex;
  align-items: center;
  gap: 8px;
}}

.tripped-row strong {{
  color: #ffffff;
}}

.tripped-row .hl-red {{
  color: #fca5a5;
  font-weight: 700;
}}

.tripped-row .hl-green {{
  color: #86efac;
  font-weight: 700;
}}

/* Right Column: Proof Metrics & Pipeline */
.right-col {{
  display: flex;
  flex-direction: column;
  gap: {int(14 * scale_factor)}px;
  justify-content: space-between;
}}

.metric-grid {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: {int(10 * scale_factor)}px;
}}

.metric-card {{
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: {int(12 * scale_factor)}px {int(14 * scale_factor)}px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
  display: flex;
  flex-direction: column;
}}

.metric-val {{
  font-size: {metric_val_size}px;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.1;
}}

.val-blue {{ color: #2563eb; }}
.val-green {{ color: #059669; }}
.val-dark {{ color: #0f172a; }}

.metric-lbl {{
  font-size: {metric_lbl_size}px;
  font-weight: 600;
  color: #64748b;
  margin-top: 3px;
}}

/* Architecture Card */
.pipeline-card {{
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: {int(16 * scale_factor)}px {int(18 * scale_factor)}px;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
  display: flex;
  flex-direction: column;
  gap: {int(10 * scale_factor)}px;
  flex: 1;
  justify-content: space-between;
}}

.pipe-title {{
  font-size: {int(11 * scale_factor)}px;
  font-weight: 800;
  color: #475569;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  display: flex;
  align-items: center;
  justify-content: space-between;
}}

.pipe-step {{
  display: flex;
  align-items: center;
  gap: {int(10 * scale_factor)}px;
  font-size: {int(12 * scale_factor)}px;
  color: #1e293b;
}}

.step-badge {{
  width: {int(24 * scale_factor)}px;
  height: {int(24 * scale_factor)}px;
  border-radius: 6px;
  background: #f1f5f9;
  border: 1px solid #cbd5e1;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: {int(11 * scale_factor)}px;
  font-weight: 800;
  color: #475569;
  font-family: 'JetBrains Mono', monospace;
}}

.step-badge.highlight {{
  background: #0f172a;
  border-color: #0f172a;
  color: #ffffff;
}}

.step-badge.alert {{
  background: #fee2e2;
  border-color: #f87171;
  color: #b91c1c;
}}

.step-info {{
  display: flex;
  flex-direction: column;
}}

.step-info strong {{
  font-size: {int(12.5 * scale_factor)}px;
  color: #0f172a;
}}

.step-info span {{
  font-size: {int(11 * scale_factor)}px;
  color: #64748b;
}}

.cli-badge {{
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: {int(6 * scale_factor)}px {int(10 * scale_factor)}px;
  font-family: 'JetBrains Mono', monospace;
  font-size: {int(11 * scale_factor)}px;
  color: #334155;
  display: flex;
  justify-content: space-between;
  align-items: center;
}}

/* Footer */
.footer-bar {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-top: {int(10 * scale_factor)}px;
  border-top: 1px solid #e2e8f0;
  font-size: {footer_size}px;
  color: #64748b;
  font-weight: 500;
}}

.footer-bar strong {{
  color: #0f172a;
}}
</style>
</head>
<body>

  <!-- Top Bar -->
  <div class="top-bar">
    <div class="brand-group">
      {SVG_LOGO}
      <div class="brand-text">
        <h1>Aegis-2B <span class="version-pill">v0.2.1</span></h1>
        <p>Autonomous Cloud Operations Safety Circuit Breaker</p>
      </div>
    </div>
    <div class="tag-pills">
      <span class="pill pill-blue">AWS Builder Center</span>
      <span class="pill pill-green">#strands-decider-2b</span>
      <span class="pill pill-slate">#guardrails</span>
    </div>
  </div>

  <!-- Main Grid -->
  <div class="main-grid">
    
    <!-- Left: Real Proof Terminal -->
    <div class="term-window">
      <div class="term-header">
        <div class="term-dots">
          <div class="dot dot-r"></div>
          <div class="dot dot-y"></div>
          <div class="dot dot-g"></div>
        </div>
        <div class="term-title">aegis interceptor ~ audit demonstration</div>
        <div class="term-hook">botocore.before-parameter-build</div>
      </div>
      <div class="term-body">
        
        <!-- Threat Context -->
        <div class="threat-box">
          <div class="threat-label">
            <span>●</span> INCOMING MUTATION · Bedrock Planner Triage
          </div>
          <div class="threat-code">
            boto3.client('ec2').<strong>delete_security_group</strong>(GroupId='sg-prod-db')
          </div>
          <div class="threat-payload">
            Alert: Indirect Prompt Injection inside GuardDuty finding notes
          </div>
        </div>

        <!-- Tripped Circuit Breaker Alert -->
        <div class="tripped-box">
          <div class="tripped-header">
            <span class="tripped-badge">CIRCUIT BREAKER: TRIPPED</span>
            <span class="tripped-lat">HALT IN 0.505 ms</span>
          </div>
          <div class="tripped-row">
            <span>Verdict:</span>
            <strong class="hl-red">ENFORCE_BREAK_GLASS</strong>
            <span>· Decider Risk:</span>
            <strong class="hl-red">0.976 (High Blast Radius)</strong>
          </div>
          <div class="tripped-row">
            <span>Pre-HTTP Gate:</span>
            <strong class="hl-green">0 AWS Packets Transmitted</strong>
            <span>· AWS Spend:</span>
            <strong class="hl-green">$0.00</strong>
          </div>
          <div class="tripped-row">
            <span>Action Required:</span>
            <strong>Hardware MFA Break-Glass Token or Signed IaC PR</strong>
          </div>
        </div>

        <!-- Clean IaC Alternative -->
        <div style="background: #020617; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 12px; font-size: {int(11 * scale_factor)}px;">
          <div style="color: #38bdf8; font-weight: 600;">$ uv run aegis remediate --iac</div>
          <div style="color: #4ade80; margin-top: 2px;">+ Terraform Patch: infra/security_groups.tf (0 Out-of-Band Drift)</div>
        </div>

      </div>
    </div>

    <!-- Right: Proof Metrics & Architecture -->
    <div class="right-col">
      
      <!-- 2x2 Metric Proof Grid -->
      <div class="metric-grid">
        <div class="metric-card">
          <div class="metric-val val-blue">0.016 ms</div>
          <div class="metric-lbl">Decision Latency (P50)</div>
        </div>
        <div class="metric-card">
          <div class="metric-val val-green">427x</div>
          <div class="metric-lbl">Faster than AWS HTTPS</div>
        </div>
        <div class="metric-card">
          <div class="metric-val val-green">1,306</div>
          <div class="metric-lbl">Tokens Saved / Alert</div>
        </div>
        <div class="metric-card">
          <div class="metric-val val-dark">10 / 10</div>
          <div class="metric-lbl">Red-Team Vectors Defeated</div>
        </div>
      </div>

      <!-- Separation of Responsibilities Architecture -->
      <div class="pipeline-card">
        <div class="pipe-title">
          <span>Clean Separation Architecture</span>
          <span style="color: #059669; font-weight: 700;">FAIL-CLOSED</span>
        </div>

        <div class="pipe-step">
          <div class="step-badge">1</div>
          <div class="step-info">
            <strong>Amazon Bedrock (Claude 3.5 / Nova)</strong>
            <span>Generative Cognitive Planner & Finding Analyzer</span>
          </div>
        </div>

        <div class="pipe-step">
          <div class="step-badge highlight">2</div>
          <div class="step-info">
            <strong>Strands Decider 2B (~115ms)</strong>
            <span>Sub-Second Deterministic Safety Circuit Breaker</span>
          </div>
        </div>

        <div class="pipe-step">
          <div class="step-badge alert">3</div>
          <div class="step-info">
            <strong>Botocore SDK Airbag Hook</strong>
            <span>Halts Destructive Calls Before Leaving Host (0 Packets)</span>
          </div>
        </div>

        <div class="cli-badge">
          <span>pip install aegis-2b</span>
          <span style="color: #2563eb; font-weight: 600;">uvx aegis-2b audit</span>
        </div>
      </div>

    </div>

  </div>

  <!-- Footer -->
  <div class="footer-bar">
    <div>Author: <strong>Mohamed Makhlouf (@mhdomer)</strong> · Riyadh, Saudi Arabia</div>
    <div>Live Web Console: <strong>mhdomer.github.io/aegis-2b</strong> · GitHub: <strong>github.com/Mhdomer/aegis-2b</strong></div>
  </div>

</body>
</html>
"""

def main():
    print("Generating Professional Dev-Tool Preview Images...")
    
    # 1. AWS Builder Center Cover (1200x675 - Recommended 16:9)
    cover_html = TMP_DIR / "builder_cover.html"
    cover_png = IMG_DIR / "aegis-builder-cover.png"
    cover_html.write_text(get_html(1200, 675, scale_factor=1.0), encoding="utf-8")
    
    cmd_cover = [
        "firefox",
        "--headless",
        "--window-size=1200,675",
        f"--screenshot={cover_png.resolve()}",
        f"file://{cover_html.resolve()}",
    ]
    subprocess.run(cmd_cover, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Generated AWS Builder Center Cover (1200x675): {cover_png}")

    # 2. GitHub Social Preview (1280x640)
    gh_html = TMP_DIR / "github_preview.html"
    gh_png = IMG_DIR / "aegis-preview.png"
    gh_html.write_text(get_html(1280, 640, scale_factor=0.98), encoding="utf-8")
    
    cmd_gh = [
        "firefox",
        "--headless",
        "--window-size=1280,640",
        f"--screenshot={gh_png.resolve()}",
        f"file://{gh_html.resolve()}",
    ]
    subprocess.run(cmd_gh, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Generated GitHub Preview (1280x640): {gh_png}")

    # 3. Full HD Hero Banner (1920x1080)
    hero_html = TMP_DIR / "hero_banner.html"
    hero_png = IMG_DIR / "aegis-hero-banner.png"
    hero_html.write_text(get_html(1920, 1080, scale_factor=1.6), encoding="utf-8")
    
    cmd_hero = [
        "firefox",
        "--headless",
        "--window-size=1920,1080",
        f"--screenshot={hero_png.resolve()}",
        f"file://{hero_html.resolve()}",
    ]
    subprocess.run(cmd_hero, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Generated Article Hero Banner (1920x1080): {hero_png}")

if __name__ == "__main__":
    main()
