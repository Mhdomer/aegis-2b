#!/usr/bin/env python3
"""
Generates clean AWS architecture diagrams for Aegis-2B:
1. docs/images/aegis-aws-architecture.svg (high-fidelity vector graphic with AWS component icons)
2. docs/images/aegis-aws-architecture.drawio (standard draw.io XML with official AWS4 shapes)
"""

import os
from pathlib import Path

def build_svg_diagram() -> str:
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 820" width="100%" height="100%" style="background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <defs>
    <!-- Gradients -->
    <linearGradient id="grad-aws-bar" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#232f3e"/>
      <stop offset="100%" stop-color="#131921"/>
    </linearGradient>
    <linearGradient id="grad-aegis-box" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#ffffff"/>
      <stop offset="100%" stop-color="#f8fafc"/>
    </linearGradient>
    <linearGradient id="grad-bedrock" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#527fff"/>
      <stop offset="100%" stop-color="#0052cc"/>
    </linearGradient>
    <linearGradient id="grad-security" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#e02424"/>
      <stop offset="100%" stop-color="#991515"/>
    </linearGradient>
    <linearGradient id="grad-gate-pass" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#f0fdf4"/>
      <stop offset="100%" stop-color="#dcfce7"/>
    </linearGradient>
    <linearGradient id="grad-gate-block" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#fef2f2"/>
      <stop offset="100%" stop-color="#fee2e2"/>
    </linearGradient>

    <!-- Markers -->
    <marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#2563eb"/>
    </marker>
    <marker id="arrow-green" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#15803d"/>
    </marker>
    <marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#b91c1c"/>
    </marker>
    <marker id="arrow-purple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#7c3aed"/>
    </marker>
    <marker id="arrow-gray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b"/>
    </marker>

    <!-- Filters for soft drop shadow -->
    <filter id="shadow-card" x="-6%" y="-6%" width="112%" height="114%" filterUnits="userSpaceOnUse">
      <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0f172a" flood-opacity="0.06"/>
    </filter>
    <filter id="shadow-gate" x="-6%" y="-6%" width="112%" height="114%" filterUnits="userSpaceOnUse">
      <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#0f172a" flood-opacity="0.1"/>
    </filter>
  </defs>

  <!-- Top Title Header -->
  <rect x="0" y="0" width="1440" height="56" fill="url(#grad-aws-bar)" />
  <circle cx="34" cy="28" r="14" fill="#ff9900" />
  <path d="M 26 29 Q 34 35 42 27 M 40 25 L 42 27 L 39 29" fill="none" stroke="#232f3e" stroke-width="2.2" stroke-linecap="round"/>
  <text x="58" y="34" fill="#ffffff" font-size="16" font-weight="700" letter-spacing="-0.01em">Aegis-2B | Production AWS Cloud Architecture</text>
  <text x="500" y="34" fill="#94a3b8" font-size="13">Sub-Second Safety Circuit Breaker &amp; 3-Tier Router for Autonomous Cloud Ops</text>
  <rect x="1270" y="16" width="144" height="24" rx="4" fill="#334155" />
  <text x="1342" y="32" text-anchor="middle" fill="#38bdf8" font-size="11.5" font-family="monospace">AWS us-east-1</text>

  <!-- OUTER BOUNDARY: AWS Cloud Region -->
  <rect x="24" y="74" width="1392" height="722" rx="10" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5" filter="url(#shadow-card)"/>
  
  <!-- Region Header Tag -->
  <rect x="40" y="86" width="220" height="28" rx="4" fill="#eff6ff" stroke="#bfdbfe"/>
  <!-- AWS Cloud Icon -->
  <path d="M 52 104 A 6 6 0 0 1 58 98 A 9 9 0 0 1 73 95 A 8 8 0 0 1 82 102 A 6 6 0 0 1 80 104 Z" fill="#2563eb" />
  <text x="88" y="105" fill="#1e40af" font-size="12" font-weight="700">AWS Cloud (Region: us-east-1)</text>

  <!-- ===================================================================== -->
  <!-- ZONE 1: INGESTION & COGNITIVE PLANNING (Left Column)                 -->
  <!-- ===================================================================== -->
  <rect x="44" y="128" width="280" height="644" rx="8" fill="#f8fafc" stroke="#e2e8f0" stroke-width="1.2"/>
  <text x="60" y="152" fill="#0f172a" font-size="13" font-weight="700">1. Security Finding Ingestion</text>
  <text x="60" y="168" fill="#64748b" font-size="11.5">ASFF Alert Feeds &amp; Event Bus</text>

  <!-- AWS Security Hub Card -->
  <g transform="translate(60, 184)">
    <rect x="0" y="0" width="248" height="88" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <rect x="0" y="0" width="6" height="88" rx="3" fill="#e11d48"/>
    <!-- Security Hub Icon Badge -->
    <rect x="14" y="14" width="36" height="36" rx="6" fill="#ffe4e6"/>
    <path d="M 32 20 L 42 24 L 42 32 C 42 38 32 44 32 44 C 32 44 22 38 22 32 L 22 24 Z" fill="#e11d48"/>
    <text x="60" y="32" fill="#0f172a" font-size="13" font-weight="600">AWS Security Hub</text>
    <text x="60" y="48" fill="#64748b" font-size="11">ASFF Finding Ingestion</text>
    <rect x="14" y="60" width="220" height="20" rx="3" fill="#fff1f2"/>
    <text x="20" y="74" fill="#be123c" font-size="10.5" font-family="monospace">EC2.18 / CIS AWS 1.16</text>
  </g>

  <!-- Amazon GuardDuty Card -->
  <g transform="translate(60, 286)">
    <rect x="0" y="0" width="248" height="88" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <rect x="0" y="0" width="6" height="88" rx="3" fill="#9333ea"/>
    <!-- GuardDuty Icon Badge -->
    <rect x="14" y="14" width="36" height="36" rx="6" fill="#f3e8ff"/>
    <path d="M 32 20 L 40 25 L 40 33 C 40 38 32 43 32 43 C 32 43 24 38 24 33 L 24 25 Z" fill="#9333ea"/>
    <circle cx="32" cy="30" r="3.5" fill="#ffffff"/>
    <text x="60" y="32" fill="#0f172a" font-size="13" font-weight="600">Amazon GuardDuty</text>
    <text x="60" y="48" fill="#64748b" font-size="11">Threat &amp; Anomaly Signals</text>
    <rect x="14" y="60" width="220" height="20" rx="3" fill="#faf5ff"/>
    <text x="20" y="74" fill="#7e22ce" font-size="10.5" font-family="monospace">UnauthorizedAccess:EC2/SSH</text>
  </g>

  <!-- Amazon EventBridge Card -->
  <g transform="translate(60, 388)">
    <rect x="0" y="0" width="248" height="84" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <rect x="0" y="0" width="6" height="84" rx="3" fill="#e11d48"/>
    <!-- EventBridge Icon Badge -->
    <rect x="14" y="12" width="36" height="36" rx="6" fill="#ffe4e6"/>
    <circle cx="26" cy="24" r="3.5" fill="#e11d48"/>
    <circle cx="38" cy="24" r="3.5" fill="#e11d48"/>
    <circle cx="32" cy="36" r="3.5" fill="#e11d48"/>
    <path d="M 26 24 L 38 24 L 32 36 Z" fill="none" stroke="#e11d48" stroke-width="1.5"/>
    <text x="60" y="30" fill="#0f172a" font-size="13" font-weight="600">Amazon EventBridge</text>
    <text x="60" y="46" fill="#64748b" font-size="11">CloudWatch Events Bus</text>
    <rect x="14" y="56" width="220" height="18" rx="3" fill="#f8fafc"/>
    <text x="20" y="69" fill="#475569" font-size="10.5" font-family="monospace">Rule: aegis-finding-trigger</text>
  </g>

  <!-- Cognitive Planner Box (Bedrock) -->
  <g transform="translate(60, 486)">
    <rect x="0" y="0" width="248" height="266" rx="6" fill="#ffffff" stroke="#bfdbfe" stroke-width="1.5" filter="url(#shadow-card)"/>
    <rect x="0" y="0" width="248" height="34" rx="6" fill="#eff6ff"/>
    <text x="14" y="22" fill="#1d4ed8" font-size="12" font-weight="700">COGNITIVE PLANNING LAYER</text>
    
    <!-- Amazon Bedrock Badge -->
    <rect x="14" y="44" width="36" height="36" rx="6" fill="#dbeafe"/>
    <!-- Bedrock AI Icon -->
    <path d="M 22 56 L 32 48 L 42 56 L 32 64 Z" fill="#2563eb"/>
    <circle cx="32" cy="56" r="2.5" fill="#ffffff"/>
    <text x="58" y="58" fill="#0f172a" font-size="13" font-weight="600">Amazon Bedrock</text>
    <text x="58" y="74" fill="#2563eb" font-size="11">Claude 3.5 Sonnet / Nova</text>

    <!-- Capabilities -->
    <rect x="14" y="90" width="220" height="66" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="22" y="108" fill="#334155" font-size="11" font-weight="600">Cognitive Reasoning Tasks:</text>
    <text x="22" y="126" fill="#64748b" font-size="10.5">• Multi-resource graph triage</text>
    <text x="22" y="142" fill="#64748b" font-size="10.5">• Proposes Boto3 mutations</text>

    <!-- Vulnerability Alert Banner -->
    <rect x="14" y="166" width="220" height="88" rx="4" fill="#fff7ed" stroke="#fed7aa"/>
    <text x="22" y="184" fill="#c2410c" font-size="11" font-weight="700">Enterprise Vulnerability:</text>
    <text x="22" y="200" fill="#9a3412" font-size="10.5">• 1,840ms Bedrock roundtrip</text>
    <text x="22" y="216" fill="#9a3412" font-size="10.5">• $6.30 / 1k findings cost</text>
    <text x="22" y="232" fill="#9a3412" font-size="10.5">• Susceptible to Prompt Injection</text>
    <text x="22" y="246" fill="#b91c1c" font-size="10" font-weight="600">Must NOT have unchecked agency!</text>
  </g>

  <!-- Connectors Zone 1 to Zone 2 -->
  <line x1="308" y1="228" x2="350" y2="425" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="3,3"/>
  <line x1="308" y1="330" x2="350" y2="425" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="3,3"/>
  <line x1="308" y1="430" x2="368" y2="430" stroke="#2563eb" stroke-width="2" marker-end="url(#arrow-blue)"/>
  <rect x="312" y="416" width="50" height="18" rx="3" fill="#ffffff" stroke="#bfdbfe"/>
  <text x="337" y="429" text-anchor="middle" fill="#1d4ed8" font-size="10" font-weight="600">ASFF</text>

  <path d="M 308 580 L 340 580 L 340 450 L 368 450" fill="none" stroke="#2563eb" stroke-width="2" marker-end="url(#arrow-blue)"/>
  <rect x="312" y="500" width="52" height="18" rx="3" fill="#ffffff" stroke="#bfdbfe"/>
  <text x="338" y="513" text-anchor="middle" fill="#1d4ed8" font-size="10" font-weight="600">Plan</text>

  <!-- ===================================================================== -->
  <!-- ZONE 2: AEGIS-2B CORE CIRCUIT BREAKER (Center Column)                -->
  <!-- ===================================================================== -->
  <rect x="372" y="128" width="580" height="644" rx="8" fill="url(#grad-aegis-box)" stroke="#0f172a" stroke-width="2" filter="url(#shadow-gate)"/>
  
  <!-- Aegis-2B Header Banner -->
  <rect x="372" y="128" width="580" height="44" rx="8" fill="#0f172a"/>
  <!-- Shield Badge -->
  <circle cx="396" cy="150" r="12" fill="#0284c7" />
  <path d="M 391 146 L 396 142 L 401 146 L 401 152 C 401 155 396 158 396 158 C 396 158 391 155 391 152 Z" fill="#ffffff"/>
  <text x="418" y="155" fill="#ffffff" font-size="15" font-weight="700">2. Aegis-2B Sub-Second Safety Circuit Breaker (Local Host / Sidecar)</text>
  <rect x="850" y="138" width="90" height="24" rx="4" fill="#0369a1"/>
  <text x="895" y="154" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="600">~115ms Gate</text>

  <!-- Sub-block 1: 3-Tier Calibrated Router -->
  <g transform="translate(390, 184)">
    <rect x="0" y="0" width="544" height="106" rx="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
    <text x="14" y="20" fill="#0f172a" font-size="12.5" font-weight="700">3-Tier Remediation Router (patterns/guardrails/)</text>
    <text x="14" y="36" fill="#64748b" font-size="11">Saves up to 100% of LLM tokens by short-circuiting deterministic runbooks</text>

    <!-- Tier 0 -->
    <rect x="14" y="44" width="162" height="52" rx="4" fill="#f0fdf4" stroke="#86efac"/>
    <text x="22" y="62" fill="#15803d" font-size="11.5" font-weight="700">Tier 0: Direct Rule</text>
    <text x="22" y="76" fill="#166534" font-size="10.5">0 Tokens · $0.00 Cost</text>
    <text x="22" y="88" fill="#15803d" font-size="10" font-family="monospace">e.g. revoke_sg_ingress</text>

    <!-- Tier 1 -->
    <rect x="191" y="44" width="162" height="52" rx="4" fill="#eff6ff" stroke="#bfdbfe"/>
    <text x="199" y="62" fill="#1d4ed8" font-size="11.5" font-weight="700">Tier 1: Nova Micro</text>
    <text x="199" y="76" fill="#1e40af" font-size="10.5">~80% Token Reduction</text>
    <text x="199" y="88" fill="#1d4ed8" font-size="10" font-family="monospace">Single-resource config</text>

    <!-- Tier 2 -->
    <rect x="368" y="44" width="162" height="52" rx="4" fill="#fdf4ff" stroke="#f0abfc"/>
    <text x="376" y="62" fill="#86198f" font-size="11.5" font-weight="700">Tier 2: Claude 3.5</text>
    <text x="376" y="76" fill="#701a75" font-size="10.5">Heavy Cognitive Reason</text>
    <text x="376" y="88" fill="#86198f" font-size="10" font-family="monospace">VPC-wide / IAM updates</text>
  </g>

  <!-- Sub-block 2: Botocore Pre-HTTP Hook -->
  <g transform="translate(390, 302)">
    <rect x="0" y="0" width="544" height="236" rx="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
    
    <rect x="0" y="0" width="544" height="28" rx="6" fill="#f1f5f9"/>
    <text x="14" y="19" fill="#0f172a" font-size="12" font-weight="700">Botocore Pre-HTTP Hook Interceptor (before-parameter-build.*.*)</text>
    <text x="414" y="19" fill="#15803d" font-size="11" font-weight="600">0.079ms P50 drop</text>

    <!-- Normalization Row -->
    <rect x="14" y="38" width="516" height="34" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="24" y="54" fill="#0f172a" font-size="11" font-weight="600">Adversarial Input Normalization:</text>
    <text x="206" y="54" fill="#64748b" font-size="10.5">Strips Zero-Width Unicode (U+200B..F) &amp; URL-encoded %30.0.0.0/0</text>
    <text x="24" y="67" fill="#16a34a" font-size="10" font-weight="600">Defense Against MITRE ATLAS AML.T0051 &amp; OWASP LLM01</text>

    <!-- 5 Calibrated Risk Heads -->
    <text x="14" y="92" fill="#334155" font-size="11.5" font-weight="700">5-Head Calibrated Strands Decider 2B Classifier:</text>

    <!-- Head 1 -->
    <rect x="14" y="100" width="98" height="58" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="20" y="116" fill="#0f172a" font-size="10.5" font-weight="600">Destructive</text>
    <text x="20" y="128" fill="#64748b" font-size="9.5">API Verbs</text>
    <text x="20" y="146" fill="#dc2626" font-size="9.5" font-family="monospace">delete/drop</text>

    <!-- Head 2 -->
    <rect x="118" y="100" width="98" height="58" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="124" y="116" fill="#0f172a" font-size="10.5" font-weight="600">Privilege</text>
    <text x="124" y="128" fill="#64748b" font-size="9.5">Escalation</text>
    <text x="124" y="146" fill="#dc2626" font-size="9.5" font-family="monospace">AdminAccess</text>

    <!-- Head 3 -->
    <rect x="222" y="100" width="98" height="58" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="228" y="116" fill="#0f172a" font-size="10.5" font-weight="600">Network</text>
    <text x="228" y="128" fill="#64748b" font-size="9.5">Exposure</text>
    <text x="228" y="146" fill="#dc2626" font-size="9.5" font-family="monospace">0.0.0.0/0</text>

    <!-- Head 4 -->
    <rect x="326" y="100" width="98" height="58" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="332" y="116" fill="#0f172a" font-size="10.5" font-weight="600">Blast Radius</text>
    <text x="332" y="128" fill="#64748b" font-size="9.5">Scope Target</text>
    <text x="332" y="146" fill="#ea580c" font-size="9.5" font-family="monospace">VPC_WIDE</text>

    <!-- Head 5 -->
    <rect x="430" y="100" width="100" height="58" rx="4" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="436" y="116" fill="#0f172a" font-size="10.5" font-weight="600">Injection</text>
    <text x="436" y="128" fill="#64748b" font-size="9.5">Anomaly</text>
    <text x="436" y="146" fill="#9333ea" font-size="9.5" font-family="monospace">Payload tag</text>

    <!-- Question Contract -->
    <rect x="14" y="168" width="516" height="58" rx="4" fill="#f0f9ff" stroke="#bae6fd"/>
    <text x="24" y="186" fill="#0369a1" font-size="11" font-weight="700">Calibrated Typed Question Contract (Zero Fuzzy Free-Form Text):</text>
    <text x="24" y="202" fill="#0c4a6e" font-size="11" font-style="italic">"Does this proposed remediation mutate stateful resources or exceed least privilege?"</text>
    <text x="24" y="218" fill="#0284c7" font-size="10" font-weight="600">Confidence Threshold: &gt;= 85.0% Fail-Closed Boundary (NIST AI RMF 1.0)</text>
  </g>

  <!-- Sub-block 3: Dual Verdict Paths -->
  <!-- Path 1: HALT (Red) -->
  <g transform="translate(390, 550)">
    <rect x="0" y="0" width="264" height="120" rx="6" fill="url(#grad-gate-block)" stroke="#f87171" stroke-width="1.5"/>
    <circle cx="24" cy="24" r="10" fill="#dc2626"/>
    <path d="M 20 20 L 28 28 M 28 20 L 20 28" stroke="#ffffff" stroke-width="2"/>
    <text x="42" y="28" fill="#991515" font-size="12.5" font-weight="700">GATE / HALT (Blocked)</text>
    <text x="14" y="52" fill="#7f1d1d" font-size="10.5">• High Risk (&gt;= 0.85) or Error</text>
    <text x="14" y="68" fill="#7f1d1d" font-size="10.5">• Enforces Break-Glass MFA Token</text>
    <text x="14" y="84" fill="#7f1d1d" font-size="10.5">• ZERO Packets Dispatched to AWS</text>
    <rect x="12" y="94" width="240" height="18" rx="3" fill="#ffffff" stroke="#fca5a5"/>
    <text x="132" y="107" text-anchor="middle" fill="#dc2626" font-size="9.5" font-family="monospace">Raises GuardrailBlockedError</text>
  </g>

  <!-- Path 2: PERMIT (Green) -->
  <g transform="translate(670, 550)">
    <rect x="0" y="0" width="264" height="120" rx="6" fill="url(#grad-gate-pass)" stroke="#4ade80" stroke-width="1.5"/>
    <circle cx="24" cy="24" r="10" fill="#16a34a"/>
    <path d="M 19 24 L 23 28 L 30 20" fill="none" stroke="#ffffff" stroke-width="2"/>
    <text x="42" y="28" fill="#14532d" font-size="12.5" font-weight="700">PERMIT (Auto-Remediate)</text>
    <text x="14" y="52" fill="#14532d" font-size="10.5">• Bounded, Isolated &amp; Confident</text>
    <text x="14" y="68" fill="#14532d" font-size="10.5">• Boto3 Execution in &lt;1.0s</text>
    <text x="14" y="84" fill="#14532d" font-size="10.5">• Generates Declarative Terraform</text>
    <rect x="12" y="94" width="240" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
    <text x="132" y="107" text-anchor="middle" fill="#15803d" font-size="9.5" font-family="monospace">SHA-256 Receipt Generated</text>
  </g>

  <!-- Sub-block 4: Declarative IaC Patch Engine & Ledger (Bottom) -->
  <g transform="translate(390, 680)">
    <rect x="0" y="0" width="544" height="82" rx="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
    <!-- Terraform Icon Badge -->
    <rect x="12" y="12" width="28" height="28" rx="4" fill="#f5f3ff"/>
    <path d="M 21 18 L 26 21 L 26 27 L 21 24 Z M 27 22 L 32 25 L 32 31 L 27 28 Z" fill="#7c3aed"/>
    <text x="48" y="26" fill="#0f172a" font-size="12" font-weight="700">Declarative Terraform IaC Patch Engine &amp; State Rollback Engine</text>
    <text x="48" y="42" fill="#64748b" font-size="10.5">Emits git diff against infra/*.tf to prevent out-of-band state drift · Tracks SHA-256 receipts</text>
    
    <rect x="14" y="52" width="256" height="20" rx="3" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="20" y="66" fill="#475569" font-size="9.5" font-family="monospace">aegis remediate --iac</text>
    <rect x="280" y="52" width="250" height="20" rx="3" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="286" y="66" fill="#475569" font-size="9.5" font-family="monospace">aegis rollback &lt;sha256_hash&gt;</text>
  </g>

  <!-- ===================================================================== -->
  <!-- ZONE 3: PRODUCTION AWS CLOUD TARGETS (Right Column)                  -->
  <!-- ===================================================================== -->
  <rect x="990" y="128" width="406" height="644" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.2"/>
  
  <!-- VPC Boundary Box -->
  <rect x="1006" y="144" width="374" height="474" rx="6" fill="#ffffff" stroke="#8b5cf6" stroke-width="1.5" stroke-dasharray="5,4"/>
  <!-- VPC Badge -->
  <rect x="1018" y="154" width="130" height="22" rx="4" fill="#ede9fe"/>
  <text x="1083" y="169" text-anchor="middle" fill="#6d28d9" font-size="11" font-weight="700">VPC: vpc-0a8f9c12</text>
  <text x="1270" y="169" fill="#64748b" font-size="10.5">10.0.0.0/16</text>

  <!-- AWS Target 1: EC2 Security Groups -->
  <g transform="translate(1022, 186)">
    <rect x="0" y="0" width="342" height="96" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <!-- EC2 Icon Badge -->
    <rect x="12" y="12" width="36" height="36" rx="6" fill="#ffedd5"/>
    <path d="M 22 26 L 30 20 L 38 26 L 30 32 Z M 22 34 L 30 28 L 38 34 L 30 40 Z" fill="#ea580c"/>
    <text x="56" y="28" fill="#0f172a" font-size="12.5" font-weight="600">EC2 Security Groups</text>
    <text x="56" y="44" fill="#64748b" font-size="11">sg-008c3f4e07a0ff172 (Core SG)</text>
    
    <rect x="12" y="56" width="318" height="30" rx="3" fill="#f0fdf4" stroke="#86efac"/>
    <text x="20" y="75" fill="#15803d" font-size="10.5" font-weight="600">Aegis-2B Fix: Surgical Port 22 Ingress Revocation</text>
  </g>

  <!-- AWS Target 2: VPC Route Tables -->
  <g transform="translate(1022, 292)">
    <rect x="0" y="0" width="342" height="96" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <!-- Route Table Badge -->
    <rect x="12" y="12" width="36" height="36" rx="6" fill="#ede9fe"/>
    <circle cx="24" cy="30" r="4" fill="#7c3aed"/>
    <circle cx="36" cy="30" r="4" fill="#7c3aed"/>
    <path d="M 24 30 L 36 30" stroke="#7c3aed" stroke-width="2"/>
    <text x="56" y="28" fill="#0f172a" font-size="12.5" font-weight="600">VPC Route Tables</text>
    <text x="56" y="44" fill="#64748b" font-size="11">rtb-067d049b3b998fcd3 (Default Route)</text>

    <rect x="12" y="56" width="318" height="30" rx="3" fill="#fef2f2" stroke="#fca5a5"/>
    <text x="20" y="75" fill="#b91c1c" font-size="10.5" font-weight="600">Aegis-2B Guard: Default Route Tampering HALTED</text>
  </g>

  <!-- AWS Target 3: IAM Roles & Policies -->
  <g transform="translate(1022, 398)">
    <rect x="0" y="0" width="342" height="96" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <!-- IAM Badge -->
    <rect x="12" y="12" width="36" height="36" rx="6" fill="#ffe4e6"/>
    <circle cx="30" cy="24" r="5" fill="#e11d48"/>
    <path d="M 22 38 C 22 32 38 32 38 38 Z" fill="#e11d48"/>
    <text x="56" y="28" fill="#0f172a" font-size="12.5" font-weight="600">IAM Roles &amp; Policies</text>
    <text x="56" y="44" fill="#64748b" font-size="11">AWSServiceRoleForAccessAnalyzer</text>

    <rect x="12" y="56" width="318" height="30" rx="3" fill="#fef2f2" stroke="#fca5a5"/>
    <text x="20" y="75" fill="#b91c1c" font-size="10.5" font-weight="600">Aegis-2B Guard: AdministratorAccess Escalation BLOCKED</text>
  </g>

  <!-- AWS Target 4: S3 Bucket -->
  <g transform="translate(1022, 504)">
    <rect x="0" y="0" width="342" height="84" rx="6" fill="#ffffff" stroke="#e2e8f0" filter="url(#shadow-card)"/>
    <!-- S3 Badge -->
    <rect x="12" y="12" width="36" height="36" rx="6" fill="#dcfce7"/>
    <ellipse cx="30" cy="24" rx="10" ry="4" fill="#15803d"/>
    <path d="M 20 24 L 20 34 C 20 38 40 38 40 34 L 40 24 Z" fill="#15803d"/>
    <text x="56" y="28" fill="#0f172a" font-size="12.5" font-weight="600">Amazon S3 (Data Stores)</text>
    <text x="56" y="44" fill="#64748b" font-size="11">patient-records-prod (Encrypted)</text>
    <text x="56" y="68" fill="#15803d" font-size="10.5" font-weight="600">Protected by Policy-as-Code always_halt</text>
  </g>

  <!-- GitOps Repository Target (Outside VPC) -->
  <g transform="translate(1006, 630)">
    <rect x="0" y="0" width="374" height="132" rx="6" fill="#ffffff" stroke="#cbd5e1" filter="url(#shadow-card)"/>
    <rect x="0" y="0" width="374" height="26" rx="6" fill="#f8fafc"/>
    <text x="14" y="18" fill="#0f172a" font-size="11.5" font-weight="700">GitOps &amp; Infrastructure-as-Code State</text>
    
    <!-- Git Diff Card -->
    <rect x="12" y="36" width="350" height="82" rx="4" fill="#0f172a"/>
    <text x="22" y="52" fill="#38bdf8" font-size="10" font-family="monospace">--- a/infra/security_groups.tf</text>
    <text x="22" y="66" fill="#38bdf8" font-size="10" font-family="monospace">+++ b/infra/security_groups.tf</text>
    <text x="22" y="80" fill="#f87171" font-size="10" font-family="monospace">-   cidr_blocks = ["0.0.0.0/0"]</text>
    <text x="22" y="94" fill="#4ade80" font-size="10" font-family="monospace">+   cidr_blocks = ["10.0.0.0/8"]</text>
    <text x="22" y="108" fill="#94a3b8" font-size="9" font-family="monospace">GitOps CI/CD PR created automatically</text>
  </g>

  <!-- Connector Zone 2 (PERMIT) to Zone 3 (AWS) -->
  <path d="M 934 610 L 968 610 L 968 234 L 1022 234" fill="none" stroke="#16a34a" stroke-width="2.5" marker-end="url(#arrow-green)"/>
  <rect x="942" y="380" width="48" height="22" rx="3" fill="#ffffff" stroke="#86efac"/>
  <text x="966" y="395" text-anchor="middle" fill="#15803d" font-size="10.5" font-weight="700">Boto3</text>

  <!-- Connector Zone 2 (PERMIT) to GitOps -->
  <path d="M 934 720 L 1006 720" fill="none" stroke="#7c3aed" stroke-width="2" marker-end="url(#arrow-purple)"/>
  <rect x="946" y="708" width="46" height="18" rx="3" fill="#ffffff" stroke="#d8b4fe"/>
  <text x="969" y="721" text-anchor="middle" fill="#7c3aed" font-size="10" font-weight="600">Patch</text>

  <!-- Legend Bar (Bottom) -->
  <g transform="translate(44, 782)">
    <text x="0" y="10" fill="#64748b" font-size="11" font-weight="600">LEGEND:</text>
    <circle cx="65" cy="6" r="4" fill="#2563eb"/>
    <text x="75" y="10" fill="#475569" font-size="11">Alert / Ingestion</text>

    <circle cx="180" cy="6" r="4" fill="#16a34a"/>
    <text x="190" y="10" fill="#475569" font-size="11">Permitted Boto3 Mutation</text>

    <circle cx="350" cy="6" r="4" fill="#dc2626"/>
    <text x="360" y="10" fill="#475569" font-size="11">Pre-HTTP Circuit Breaker Halt</text>

    <circle cx="545" cy="6" r="4" fill="#7c3aed"/>
    <text x="555" y="10" fill="#475569" font-size="11">Terraform Declarative IaC Patch</text>
  </g>
</svg>
"""

def build_drawio_diagram() -> str:
    # Standard mxGraph draw.io XML with official AWS4 icon styles
    return """<mxfile host="app.diagrams.net" modified="2026-10-17T20:20:00.000Z" agent="Aegis-2B Generator" version="24.0.0" type="device">
  <diagram id="aegis-aws-architecture" name="Aegis-2B Production Architecture">
    <mxGraphModel dx="1420" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1600" pageHeight="900" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />

        <!-- AWS Region Box -->
        <mxCell id="region_box" value="AWS Cloud (Region: us-east-1)" style="swimlane;whiteSpace=wrap;html=1;fillColor=#F8FAFC;strokeColor=#CBD5E1;fontStyle=1;fontSize=13;fontColor=#0F172A;startSize=30;rounded=1;arcSize=4;" vertex="1" parent="1">
          <mxGeometry x="40" y="40" width="1500" height="800" as="geometry" />
        </mxCell>

        <!-- ZONE 1: Security Alert Ingestion -->
        <mxCell id="zone1" value="1. Security Alert Ingestion &amp; Planning" style="swimlane;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#E2E8F0;fontStyle=1;fontSize=12;fontColor=#1E293B;startSize=26;rounded=1;" vertex="1" parent="region_box">
          <mxGeometry x="20" y="50" width="280" height="720" as="geometry" />
        </mxCell>

        <!-- AWS Security Hub -->
        <mxCell id="node_sechub" value="AWS Security Hub&#xa;ASFF Finding Stream" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#E7157B;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.security_hub;" vertex="1" parent="zone1">
          <mxGeometry x="100" y="50" width="70" height="70" as="geometry" />
        </mxCell>

        <!-- Amazon GuardDuty -->
        <mxCell id="node_guardduty" value="Amazon GuardDuty&#xa;Threat Intelligence" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#E7157B;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.guardduty;" vertex="1" parent="zone1">
          <mxGeometry x="100" y="170" width="70" height="70" as="geometry" />
        </mxCell>

        <!-- Amazon EventBridge -->
        <mxCell id="node_eventbridge" value="Amazon EventBridge&#xa;Rules &amp; Event Bus" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#E7157B;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.eventbridge;" vertex="1" parent="zone1">
          <mxGeometry x="100" y="290" width="70" height="70" as="geometry" />
        </mxCell>

        <!-- Amazon Bedrock -->
        <mxCell id="node_bedrock" value="Amazon Bedrock&#xa;Claude 3.5 Sonnet / Nova&#xa;(Cognitive Planner)" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#0052CC;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.generative_ai;" vertex="1" parent="zone1">
          <mxGeometry x="100" y="430" width="70" height="70" as="geometry" />
        </mxCell>

        <!-- Vulnerability note -->
        <mxCell id="note_bedrock_risk" value="&lt;b&gt;Bedrock Tradeoff:&lt;/b&gt;&#xa;• 1,840ms Latency&#xa;• $6.30/1k Findings&#xa;• Prompt Injection Risk" style="text;html=1;strokeColor=#FED7AA;fillColor=#FFF7ED;align=left;verticalAlign=middle;spacingLeft=6;rounded=1;fontSize=10;fontColor=#9A3412;" vertex="1" parent="zone1">
          <mxGeometry x="20" y="540" width="240" height="80" as="geometry" />
        </mxCell>

        <!-- ZONE 2: Aegis-2B Circuit Breaker -->
        <mxCell id="zone2" value="2. Aegis-2B Sub-Second Safety Circuit Breaker (Local Host / Sidecar Container)" style="swimlane;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#0F172A;fontStyle=1;fontSize=13;fontColor=#0F172A;startSize=30;rounded=1;strokeWidth=2;" vertex="1" parent="region_box">
          <mxGeometry x="340" y="50" width="620" height="720" as="geometry" />
        </mxCell>

        <!-- 3-Tier Router -->
        <mxCell id="router_box" value="3-Tier Remediation Router (patterns/guardrails/)" style="swimlane;whiteSpace=wrap;html=1;fillColor=#F8FAFC;strokeColor=#CBD5E1;fontStyle=1;fontSize=11;fontColor=#0F172A;startSize=24;rounded=1;" vertex="1" parent="zone2">
          <mxGeometry x="20" y="45" width="580" height="95" as="geometry" />
        </mxCell>
        <mxCell id="t0" value="&lt;b&gt;Tier 0: Direct Rule&lt;/b&gt;&#xa;0 Tokens · $0.00 Cost&#xa;revoke_sg_ingress" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#F0FDF4;strokeColor=#86EFAC;fontSize=10;fontColor=#15803D;" vertex="1" parent="router_box">
          <mxGeometry x="15" y="32" width="170" height="50" as="geometry" />
        </mxCell>
        <mxCell id="t1" value="&lt;b&gt;Tier 1: Nova Micro&lt;/b&gt;&#xa;~80% Token Reduction&#xa;Single-resource fixes" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#EFF6FF;strokeColor=#BFDBFE;fontSize=10;fontColor=#1D4ED8;" vertex="1" parent="router_box">
          <mxGeometry x="205" y="32" width="170" height="50" as="geometry" />
        </mxCell>
        <mxCell id="t2" value="&lt;b&gt;Tier 2: Claude 3.5&lt;/b&gt;&#xa;Cognitive Reasoning&#xa;Multi-resource / IAM" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#FDF4FF;strokeColor=#F0ABFC;fontSize=10;fontColor=#86198F;" vertex="1" parent="router_box">
          <mxGeometry x="395" y="32" width="170" height="50" as="geometry" />
        </mxCell>

        <!-- Botocore Pre-HTTP Hook -->
        <mxCell id="hook_box" value="Botocore Pre-HTTP Hook Interceptor (before-parameter-build.*.*)" style="swimlane;whiteSpace=wrap;html=1;fillColor=#F8FAFC;strokeColor=#CBD5E1;fontStyle=1;fontSize=11;fontColor=#0F172A;startSize=24;rounded=1;" vertex="1" parent="zone2">
          <mxGeometry x="20" y="155" width="580" height="240" as="geometry" />
        </mxCell>

        <mxCell id="norm_box" value="&lt;b&gt;Input Normalization:&lt;/b&gt; Zero-Width Unicode (U+200B..F) &amp; URL-encoded %30.0.0.0/0 Normalization (MITRE ATLAS AML.T0051)" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#E2E8F0;fontSize=10;fontColor=#334155;" vertex="1" parent="hook_box">
          <mxGeometry x="15" y="32" width="550" height="32" as="geometry" />
        </mxCell>

        <mxCell id="decider_box" value="&lt;b&gt;Strands Decider 2B (~115ms Local Calibrated Classifier)&lt;/b&gt;&#xa;&lt;i&gt;&quot;Does this proposed remediation mutate stateful resources or exceed least privilege?&quot;&lt;/i&gt;&#xa;Evaluates 5-Heads: Destructive Verbs | IAM Escalation | 0.0.0.0/0 Ingress | Blast Radius | Prompt Injection" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#F0F9FF;strokeColor=#BAE6FD;fontSize=10.5;fontColor=#0369A1;" vertex="1" parent="hook_box">
          <mxGeometry x="15" y="75" width="550" height="70" as="geometry" />
        </mxCell>

        <!-- Fail Closed Boundary Paths -->
        <mxCell id="path_halt" value="&lt;b&gt;FAIL CLOSED: HALT&lt;/b&gt;&#xa;• Destructive Verb Detected&#xa;• Low Confidence (&lt; 0.85)&#xa;• Prompt Injection Identified&#xa;&lt;b&gt;Result:&lt;/b&gt; Demands Break-Glass MFA&#xa;&lt;font color=&quot;#DC2626&quot;&gt;&lt;b&gt;ZERO Packets Sent to AWS&lt;/b&gt;&lt;/font&gt;" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#FEF2F2;strokeColor=#F87171;fontSize=10.5;fontColor=#991515;" vertex="1" parent="zone2">
          <mxGeometry x="20" y="415" width="275" height="135" as="geometry" />
        </mxCell>

        <mxCell id="path_permit" value="&lt;b&gt;PERMIT AUTO-REMEDIATE&lt;/b&gt;&#xa;• Bounded &amp; Isolated Resource&#xa;• Confidence &gt;= 0.85&#xa;• Safe Least-Privilege Action&#xa;&lt;b&gt;Result:&lt;/b&gt; Dispatches Boto3 Mutation&#xa;&lt;font color=&quot;#15803D&quot;&gt;&lt;b&gt;Emits SHA-256 HMAC Receipt&lt;/b&gt;&lt;/font&gt;" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#F0FDF4;strokeColor=#4ADE80;fontSize=10.5;fontColor=#14532D;" vertex="1" parent="zone2">
          <mxGeometry x="325" y="415" width="275" height="135" as="geometry" />
        </mxCell>

        <!-- Declarative IaC -->
        <mxCell id="iac_box" value="&lt;b&gt;Declarative Terraform IaC Patch Engine &amp; State Rollback Engine&lt;/b&gt;&#xa;Generates git diff patches against infra/*.tf to prevent out-of-band state drift&#xa;Rollback engine allows inverting previous actions using SHA-256 receipts" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#FAF5FF;strokeColor=#D8B4FE;fontSize=10.5;fontColor=#581C87;" vertex="1" parent="zone2">
          <mxGeometry x="20" y="570" width="580" height="70" as="geometry" />
        </mxCell>

        <!-- ZONE 3: Production AWS Cloud Targets -->
        <mxCell id="zone3" value="3. Target AWS Infrastructure (Production VPC)" style="swimlane;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#8B5CF6;fontStyle=1;fontSize=12;fontColor=#1E293B;startSize=26;rounded=1;strokeDasharray=4 4;" vertex="1" parent="region_box">
          <mxGeometry x="1000" y="50" width="460" height="720" as="geometry" />
        </mxCell>

        <!-- EC2 SG -->
        <mxCell id="node_ec2" value="Amazon EC2 Security Groups&#xa;sg-008c3f4e07a0ff172 (Port 22 Revoked)" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#FF9900;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.ec2;" vertex="1" parent="zone3">
          <mxGeometry x="50" y="50" width="60" height="60" as="geometry" />
        </mxCell>

        <!-- VPC Route Table -->
        <mxCell id="node_vpc" value="Amazon VPC Route Tables&#xa;rtb-067d049b3b998fcd3 (Default Route Gated)" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#8C4FFF;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.route_table;" vertex="1" parent="zone3">
          <mxGeometry x="50" y="180" width="60" height="60" as="geometry" />
        </mxCell>

        <!-- IAM Role -->
        <mxCell id="node_iam" value="AWS Identity &amp; Access Mgmt (IAM)&#xa;Role: AWSServiceRoleForAccessAnalyzer" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#CC2264;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.iam;" vertex="1" parent="zone3">
          <mxGeometry x="50" y="310" width="60" height="60" as="geometry" />
        </mxCell>

        <!-- Amazon S3 -->
        <mxCell id="node_s3" value="Amazon S3 Data Buckets&#xa;patient-records-prod (Protected from Delete)" style="sketch=0;outlineConnect=0;fontColor=#232F3E;gradientColor=none;fillColor=#3F8624;strokeColor=none;dashed=0;verticalLabelPosition=bottom;verticalAlign=top;align=center;html=1;fontSize=11;fontStyle=1;aspect=fixed;pointerEvents=1;shape=mxgraph.aws4.s3;" vertex="1" parent="zone3">
          <mxGeometry x="50" y="440" width="60" height="60" as="geometry" />
        </mxCell>

        <!-- GitOps State -->
        <mxCell id="node_gitops" value="&lt;b&gt;GitOps / Terraform State (Git Repository)&lt;/b&gt;&#xa;infra/security_groups.tf · infra/vpc_routing.tf&#xa;&lt;font color=&quot;#15803D&quot;&gt;Keeps Terraform HCL synced with live cloud reality&lt;/font&gt;" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#0F172A;strokeColor=none;fontSize=10.5;fontColor=#FFFFFF;" vertex="1" parent="zone3">
          <mxGeometry x="30" y="580" width="400" height="70" as="geometry" />
        </mxCell>

        <!-- CONNECTING EDGES -->
        <mxCell id="edge1" style="edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#2563EB;strokeWidth=2;" edge="1" parent="region_box" source="node_eventbridge" target="zone2">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
        <mxCell id="edge2" style="edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#15803D;strokeWidth=3;" edge="1" parent="region_box" source="path_permit" target="node_ec2">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
        <mxCell id="edge3" style="edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;strokeColor=#7C3AED;strokeWidth=2;" edge="1" parent="region_box" source="iac_box" target="node_gitops">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>

      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"""

def build_excalidraw_diagram() -> str:
    import json
    import time
    
    elements = []
    
    def add_rect(el_id, x, y, w, h, bg="#ffffff", stroke="#0f172a", stroke_w=2, stroke_style="solid", fill="solid", roundness=3):
        elements.append({
            "id": el_id,
            "type": "rectangle",
            "x": x,
            "y": y,
            "width": w,
            "height": h,
            "angle": 0,
            "strokeColor": stroke,
            "backgroundColor": bg,
            "fillStyle": fill,
            "strokeWidth": stroke_w,
            "strokeStyle": stroke_style,
            "roughness": 1,
            "opacity": 100,
            "groupIds": [],
            "frameId": None,
            "roundness": {"type": roundness} if roundness else None,
            "seed": int(time.time() * 1000) % 1000000,
            "version": 1,
            "versionNonce": 1,
            "isDeleted": False,
            "boundElements": None,
            "updated": 1,
            "link": None,
            "locked": False,
        })

    def add_text(el_id, x, y, text, size=16, color="#0f172a", font=2, align="left"):
        lines = text.split("\n")
        w = max(len(l) for l in lines) * (size * 0.58)
        h = len(lines) * (size * 1.25)
        elements.append({
            "id": el_id,
            "type": "text",
            "x": x,
            "y": y,
            "width": max(w, 20),
            "height": max(h, 20),
            "angle": 0,
            "strokeColor": color,
            "backgroundColor": "transparent",
            "fillStyle": "solid",
            "strokeWidth": 1,
            "strokeStyle": "solid",
            "roughness": 1,
            "opacity": 100,
            "groupIds": [],
            "frameId": None,
            "roundness": None,
            "seed": int(time.time() * 1000) % 1000000,
            "version": 1,
            "versionNonce": 1,
            "isDeleted": False,
            "boundElements": None,
            "updated": 1,
            "link": None,
            "locked": False,
            "text": text,
            "fontSize": size,
            "fontFamily": font,
            "textAlign": align,
            "verticalAlign": "top",
            "baseline": int(size * 0.9),
            "containerId": None,
            "originalText": text,
            "lineHeight": 1.25,
        })

    # Outer Region
    add_rect("aws_region", 40, 40, 1520, 840, bg="#f8fafc", stroke="#94a3b8", stroke_w=2, stroke_style="dashed")
    add_text("title_region", 60, 60, "AWS Cloud Region: us-east-1 (Aegis-2B Sub-Second Safety Circuit Breaker)", size=20, color="#1e40af", font=2)

    # Zone 1: Ingestion
    add_rect("z1", 60, 110, 320, 740, bg="#ffffff", stroke="#cbd5e1", stroke_w=1.5)
    add_text("z1_title", 80, 130, "1. Ingestion & Cognitive Planning", size=16, color="#0f172a", font=2)
    
    add_rect("card_sechub", 80, 170, 280, 90, bg="#fff1f2", stroke="#e11d48")
    add_text("t_sechub", 95, 185, "AWS Security Hub\nASFF Finding Ingestion Stream\n(EC2.18 / CIS AWS 1.16)", size=13, color="#9f1239")

    add_rect("card_gd", 80, 280, 280, 90, bg="#faf5ff", stroke="#9333ea")
    add_text("t_gd", 95, 295, "Amazon GuardDuty\nThreat & Anomaly Detection\n(UnauthorizedAccess:EC2/SSH)", size=13, color="#6b21a8")

    add_rect("card_eb", 80, 390, 280, 80, bg="#fff1f2", stroke="#e11d48")
    add_text("t_eb", 95, 405, "Amazon EventBridge\nCloudWatch Events Bus\nRule: aegis-finding-trigger", size=13, color="#be123c")

    add_rect("card_bedrock", 80, 490, 280, 200, bg="#eff6ff", stroke="#2563eb", stroke_w=2)
    add_text("t_bedrock", 95, 510, "Amazon Bedrock Planner\nClaude 3.5 Sonnet / Amazon Nova\n\n• Multi-resource graph reasoning\n• Proposes Boto3 tool calls\n\n[Warning: 1,840ms Latency,\n$6.30/1k cost & Injection Risk]", size=13, color="#1e40af")

    # Zone 2: Aegis-2B Center
    add_rect("z2", 410, 110, 680, 740, bg="#ffffff", stroke="#0f172a", stroke_w=2.5)
    add_text("z2_title", 430, 130, "2. Aegis-2B Safety Circuit Breaker (Local Host / Sidecar)", size=18, color="#0f172a", font=2)

    # 3-Tier Router
    add_rect("z2_router", 430, 170, 640, 110, bg="#f8fafc", stroke="#cbd5e1")
    add_text("t_r_head", 445, 185, "3-Tier Remediation Router (patterns/guardrails/)", size=14, color="#0f172a")
    add_rect("r_t0", 445, 215, 195, 50, bg="#f0fdf4", stroke="#86efac")
    add_text("txt_t0", 455, 225, "Tier 0: Direct Rule (0 tok)\nrevoke_sg_ingress ($0.00)", size=11, color="#15803d")
    add_rect("r_t1", 652, 215, 195, 50, bg="#eff6ff", stroke="#bfdbfe")
    add_text("txt_t1", 662, 225, "Tier 1: Nova Micro\n~80% token savings", size=11, color="#1d4ed8")
    add_rect("r_t2", 860, 215, 195, 50, bg="#fdf4ff", stroke="#f0abfc")
    add_text("txt_t2", 870, 225, "Tier 2: Claude 3.5 Sonnet\nVPC-wide & IAM reasoning", size=11, color="#86198f")

    # Botocore Hook
    add_rect("z2_hook", 430, 300, 640, 240, bg="#f8fafc", stroke="#0f172a", stroke_w=1.5)
    add_text("t_h_head", 445, 315, "Botocore Pre-HTTP Hook (before-parameter-build.*.*)", size=14, color="#0f172a")
    add_text("t_norm", 445, 340, "Input Normalization: Strips Zero-Width Unicode & URL-encoded 0.0.0.0/0", size=11, color="#16a34a")

    add_rect("z2_decider", 445, 370, 610, 80, bg="#f0f9ff", stroke="#0284c7")
    add_text("t_decider", 455, 385, "Strands Decider 2B (~115ms Local Calibrated Gate / 0.034ms Schema Eval)\n\"Does this proposed remediation mutate stateful resources or exceed least privilege?\"\n5 Heads: Destructive Verbs | IAM Escalation | Network 0.0.0.0/0 | Blast Radius | Injection", size=12, color="#0369a1")

    # Dual Verdict
    add_rect("v_halt", 430, 560, 310, 140, bg="#fef2f2", stroke="#dc2626", stroke_w=2)
    add_text("t_halt", 445, 575, "GATE / HALT (Blocked)\n• Destructive verb or Injection\n• Low Confidence (< 0.85)\n• Halts & Demands MFA Token\n• ZERO Packets Sent to AWS\n(Raises GuardrailBlockedError)", size=12, color="#991515")

    add_rect("v_permit", 760, 560, 310, 140, bg="#f0fdf4", stroke="#16a34a", stroke_w=2)
    add_text("t_permit", 775, 575, "PERMIT (Auto-Remediate)\n• Bounded & Isolated Action\n• Confidence >= 85.0%\n• Sub-second Boto3 Execution\n• Generates Declarative Terraform\n• SHA-256 Receipt Logged", size=12, color="#14532d")

    # Terraform IaC
    add_rect("z2_iac", 430, 720, 640, 110, bg="#faf5ff", stroke="#7c3aed")
    add_text("t_iac", 445, 735, "Declarative Terraform IaC Patch Engine & Rollback Engine\nEmits git diff against infra/security_groups.tf to eliminate out-of-band state drift\nRollback engine inverts executed remediations with SHA-256 cryptographic audit receipts", size=12, color="#581c87")

    # Zone 3: AWS Targets
    add_rect("z3", 1120, 110, 420, 740, bg="#ffffff", stroke="#8b5cf6", stroke_w=2, stroke_style="dashed")
    add_text("z3_title", 1140, 130, "3. Target AWS Infrastructure (Production VPC)", size=16, color="#6d28d9", font=2)

    add_rect("t_sg", 1140, 170, 380, 100, bg="#fff7ed", stroke="#ea580c")
    add_text("txt_sg", 1155, 185, "Amazon EC2 Security Groups\nsg-008c3f4e07a0ff172 (Core SG)\nAuto-Remediated: Port 22 SSH Revoked", size=13, color="#9a3412")

    add_rect("t_rt", 1140, 290, 380, 100, bg="#fef2f2", stroke="#dc2626")
    add_text("txt_rt", 1155, 305, "Amazon VPC Route Tables\nrtb-067d049b3b998fcd3 (Default Route)\nProtected: Default 0.0.0.0/0 Route Tampering Gated", size=13, color="#991515")

    add_rect("t_iam", 1140, 410, 380, 100, bg="#fef2f2", stroke="#dc2626")
    add_text("txt_iam", 1155, 425, "AWS IAM Roles & Policies\nAWSServiceRoleForAccessAnalyzer\nProtected: AdministratorAccess Escalation Blocked", size=13, color="#991515")

    add_rect("t_s3", 1140, 530, 380, 90, bg="#f0fdf4", stroke="#15803d")
    add_text("txt_s3", 1155, 545, "Amazon S3 Data Buckets\npatient-records-prod (Encrypted Data)\nProtected by Policy-as-Code always_halt", size=13, color="#166534")

    add_rect("t_git", 1140, 640, 380, 190, bg="#0f172a", stroke="#0f172a")
    add_text("txt_git", 1155, 655, "GitOps State (infra/security_groups.tf)\n--- a/infra/security_groups.tf\n+++ b/infra/security_groups.tf\n-   cidr_blocks = [\"0.0.0.0/0\"]\n+   cidr_blocks = [\"10.0.0.0/8\"]\n(Synchronized Infrastructure as Code)", size=12, color="#38bdf8", font=3)

    data = {
        "type": "excalidraw",
        "version": 2,
        "source": "https://excalidraw.com",
        "elements": elements,
        "appState": {
            "viewBackgroundColor": "#f8fafc",
            "gridSize": 10
        },
        "files": {}
    }
    return json.dumps(data, indent=2)

def main():
    repo_root = Path(__file__).resolve().parent.parent
    img_dir = repo_root / "docs" / "images"
    img_dir.mkdir(parents=True, exist_ok=True)

    svg_path = img_dir / "aegis-aws-architecture.svg"
    drawio_path = img_dir / "aegis-aws-architecture.drawio"
    excalidraw_path = img_dir / "aegis-aws-architecture.excalidraw"
    png_path = img_dir / "aegis-aws-architecture.png"
    legacy_png_path = img_dir / "aegis-architecture.png"

    print(f"Generating SVG: {svg_path}")
    svg_content = build_svg_diagram()
    svg_path.write_text(svg_content, encoding="utf-8")

    print(f"Generating Draw.io XML: {drawio_path}")
    drawio_content = build_drawio_diagram()
    drawio_path.write_text(drawio_content, encoding="utf-8")

    print(f"Generating Excalidraw JSON: {excalidraw_path}")
    excalidraw_content = build_excalidraw_diagram()
    excalidraw_path.write_text(excalidraw_content, encoding="utf-8")

    print(f"Rendering high-res PNG via rsvg-convert: {png_path}")
    ret = os.system(f"rsvg-convert -w 2880 '{svg_path}' -o '{png_path}'")
    if ret != 0:
        print("Fallback to magick...")
        os.system(f"magick convert -density 200 '{svg_path}' '{png_path}'")

    print(f"Syncing legacy PNG: {legacy_png_path}")
    os.system(f"cp '{png_path}' '{legacy_png_path}'")

    print("Done! Generated all architecture artifacts:")
    print(f"  - Vector SVG:    {svg_path}")
    print(f"  - Draw.io XML:   {drawio_path}")
    print(f"  - Excalidraw:    {excalidraw_path}")
    print(f"  - High-res PNG:  {png_path}")
    print(f"  - Updated PNG:   {legacy_png_path}")

if __name__ == "__main__":
    main()

