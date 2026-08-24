# HIPAA Security Rule × Agentic AI: Control Gap Mapping

> **A practitioner reference for health tech security leaders deploying agentic AI systems in PHI environments**

**Maintainer:** Mike Felker ([@mikhaelf](https://linkedin.com/in/mikhaelf))  
**Status:** v1.0  
**License:** CC BY 4.0 (documentation/content) — see [LICENSE](LICENSE). Any code, scripts, or schemas added later will be licensed separately (Apache 2.0).

> **Regulatory currency note (August 2026):** This mapping covers both the **current, in-effect** HIPAA Security Rule (last revised 2013) **and** the **2024 NPRM** ("HIPAA Security Rule to Strengthen the Cybersecurity of Electronic Protected Health Information," 90 FR 898, published Jan. 6, 2025; govinfo.gov FR-2025-01-06, document 2024-30983). As of August 2026 the NPRM's final rule has been **delayed to July 2027**, pushed back from OCR's original spring-2026 target and moved to HHS's Long-Term Actions regulatory agenda (RIN 0945-AA22). The comment period closed March 7, 2025 with ~4,745 comments; more than 100 hospital systems and provider associations have since petitioned OCR to withdraw the proposal outright, and OCR leadership has signaled the administration may revisit the rule's burdens and benefits. No final rule has been issued and the current rule remains in effect. Where the NPRM would change the applicable analysis, it is flagged inline as **[NPRM]**. The agentic gaps this document identifies persist under both the current rule and the proposed rule — the NPRM modernizes the baseline but does not address agentic AI. Separately, OCR began civil enforcement of 42 CFR Part 2 (substance-use-disorder record confidentiality) on February 16, 2026 — its first civil-penalty regime for Part 2 violations — which raises the stakes of the over-disclosure scenario below where an agent surfaces SUD-adjacent data without authorization.

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Scope and Definitions](#scope-and-definitions)
- [What the 2024 NPRM Changes](#what-the-2024-nprm-changes--and-why-the-agentic-gap-survives-it)
- [The Mapping](#the-mapping)
  - [Administrative Safeguards §164.308](#administrative-safeguards-45-cfr-164308)
  - [Physical Safeguards §164.310](#physical-safeguards-45-cfr-164310)
  - [Technical Safeguards §164.312](#technical-safeguards-45-cfr-164312)
- [Cross-Cutting Gap Summary](#cross-cutting-gap-summary)
- [Recommended Control Additions](#recommended-control-additions-for-agentic-ai-in-phi-environments)
- [Relationship to Other Frameworks](#relationship-to-other-frameworks)
- [Related Work / Prior Art](#related-work--prior-art)
- [Contributing](#contributing)
- [References](#references)
- [Legal & Regulatory Disclaimers](#legal--regulatory-disclaimers)

---

## Why This Exists

### A scenario to start with

In Season 2 of HBO's *The Pitt*, a new attending introduces an AI scribe to the emergency department, pitched to cut charting time by roughly 80%. In one episode, second-year resident Dr. Trinity Santos tries it on a patient — and the tool fabricates a clinical history (a phantom case of appendicitis) and confuses one specialty for another. The show stages this as an *accuracy* problem: the AI is right most of the time, but the times it is wrong, in emergency medicine, can kill someone. That is a real and important failure — under HIPAA it is a §164.312(c) **integrity** problem, agent-generated false ePHI written into and persisting in the record.

Now consider the failure the show *didn't* dramatize — the one a security officer should worry about more.

Imagine the same tool, the same busy shift, the same resident's credentials. To be "helpful," the scribe doesn't just transcribe the encounter; it *reaches*. Running under Dr. Santos's resident login — which legitimately carries broad read access across the EHR — the agent decides that family history would enrich the note, and pulls a parent's cardiac and genetic-panel results, a sibling's record, and a predisposition flag for a hereditary condition. None of that was part of this encounter. None of it was authorized for this use. Nothing was hacked. The agent simply exercised a human's broad standing authority more expansively than the encounter justified, and wrote conclusions ("family history suggests elevated hereditary risk") into a chart that now propagates downstream to billing, referrals, and payers.

This is no longer an accuracy problem. It is, simultaneously:

- a **minimum-necessary** violation (45 CFR §164.502(b)) — far more ePHI accessed than the encounter required;
- an **identity & privilege abuse** problem (OWASP **ASI03**) — an agent inheriting and over-exercising a clinician's standing authority;
- an **intent-drift** problem (OWASP **ASI10**) — the agent's behavior expanding beyond its assigned task;
- and, if the surfaced data touches substance-use, psychiatric, HIV, or genetic information, a problem reaching **beyond HIPAA** into 42 CFR Part 2 and state genetic-privacy law.

The unsettling part is that every individual step looks like normal, authorized clinician activity. There is no malicious actor, no breached credential, no exfiltration alert. The harm emerges from an autonomous system using legitimate access in a way no one explicitly approved — and, critically, in a way no audit log was designed to flag.

> *The integrity failure above is drawn from what actually aired; the over-broad-access scenario is a hypothetical extension and was not depicted in the show. Both are used here to illustrate, not to attribute any real-world conduct to the series or its characters.*

### The regulatory frame

The HIPAA Security Rule (45 CFR Part 164, Subparts A and C) was finalized in 2003 and last substantively amended in 2013; the 2024 NPRM proposes the first major overhaul in over a decade. The Rule is, by OCR's longstanding design, **technology-neutral and risk-based** — so it already *applies* to agentic AI: prompt injection, intent drift, and unauthorized autonomous access are "reasonably anticipated threats" to ePHI that §164.308(a)(1)(ii)(A) (Risk Analysis) obligates a covered entity to identify and mitigate today.

The gap this document addresses is therefore **methodological, not jurisdictional.** Technology-neutral language tells a covered entity *that* it must assess agentic risk; it provides no structured method for *how*. The Rule — designed around EHRs, network perimeters, and human-operated systems — offers no taxonomy for the ways autonomous, tool-using agents change the threat model:

- **Agents act autonomously** — they initiate access, execute tools, and make decisions without per-action human authorization
- **Agents chain together** — multi-agent pipelines create transitive trust relationships across systems that hold PHI
- **Agents are prompt-injectable** — natural language is now an attack surface against systems with privileged data access
- **Agents are software assets, not workforce** — an LLM calling a FHIR API is, legally, an Electronic Information System governed by Technical Safeguards, but existing guidance gives no method for scoping, identifying, or auditing it as one

This repository maps the HIPAA Security Rule standards and their implementation specifications to these agentic attack surfaces — operationalizing the risk-analysis obligation that already exists, identifying where existing controls apply directly, where they need reinterpretation, and where execution methodology is missing.

### The missing implementation guide

There is a deeper, structural reason this matters. In the established health-IT world, covered entities do not satisfy the Security Rule from first principles — they lean on **vendor implementation guidance** that translates regulatory objectives into concrete technical controls. Major EHR vendors publish security implementation guides, hardening baselines, and configuration playbooks (audit-log configuration, role-based access, break-the-glass, encryption settings); major cloud service providers publish HIPAA-eligible-services lists, shared-responsibility matrices, reference architectures, and HITRUST/SOC 2 mappings. A security officer can point to these artifacts as the recognized path from "the Rule requires X" to "here is how X is achieved on this platform."

**For agentic AI, that layer does not yet exist.** There is no equivalent implementation guide from the major agent platforms, foundation-model providers, or orchestration frameworks that tells a covered entity how to achieve §164.312 access control, audit controls, and integrity for an autonomous, tool-using agent touching ePHI. The behavior of the agent — what it accessed, why, under whose authority, and whether it stayed in scope — is effectively a **black box**: not because the controls are impossible, but because no vendor has yet published the recognized configuration baseline and shared-responsibility model that the EHR and CSP ecosystems take for granted.

That absence is a core impetus for this document. It is intended as a **thought-starter for the industry** — a structured articulation of the controls an eventual agentic implementation guide will need to cover, so that platform vendors, CSPs, and standards bodies have a HIPAA-anchored starting point rather than a blank page.

**This is not legal advice, and it does not claim the Security Rule is legally silent on agents. It is a practitioner framework for operationalizing agentic risk analysis under the Rule as it stands.**

---

## Scope and Definitions

### What is "agentic AI" for HIPAA purposes?

For this mapping, an **agentic AI system** is one that:

1. Uses an LLM or similar model to reason over inputs and select actions
2. Has access to tools, APIs, or data stores — including those containing ePHI
3. Executes multi-step tasks with limited or no per-step human approval
4. May spawn or coordinate with other agents (multi-agent architectures)

Examples in health tech: clinical documentation and ambient scribing pipelines; prior authorization and revenue cycle automation; care gap outreach and population health triage; clinical trial data extraction and cohort matching; pharmacy use cases (medication reconciliation, drug-interaction and dosing checks, refill and prior-auth workflows, pharmacy benefit adjudication); emergency department use cases (triage and acuity scoring, ED throughput and bed-management agents, sepsis and deterioration early-warning, discharge-summary generation); diagnostic and image analysis (radiology, pathology, and dermatology image triage and pre-read, ECG and waveform interpretation); patient-facing agents (symptom checkers, scheduling and intake bots, post-discharge follow-up); coding and CDI (autonomous medical coding, clinical documentation integrity); and claims, eligibility, and provider-network agents on the payer side.

### Threat taxonomy: OWASP Top 10 for Agentic Applications (ASI)

This mapping uses the **OWASP Top 10 for Agentic Applications 2026** (the "ASI" list, released December 2025 by the OWASP GenAI Security Project) as its threat taxonomy, rather than an ad hoc one. Anchoring to OWASP keeps the mapping aligned with a peer-reviewed, industry-recognized framework that healthcare security teams already encounter.

| ID | OWASP ASI Risk | Relevance to ePHI / Agentic Healthcare |
|:--:|-----------------|------------------------------------------|
| `ASI01` | Agent Goal Hijack | Prompt injection redirects an agent's objective — e.g., hidden instructions in a clinical document cause the agent to exfiltrate or over-disclose PHI. |
| `ASI02` | Tool Misuse & Exploitation | Agent invokes tools/APIs unsafely despite valid permissions — e.g., recursive or out-of-scope calls against an EHR or claims system. |
| `ASI03` | Agent Identity & Privilege Abuse | Delegated authority, ambiguous identity, or cross-agent trust leads to unauthorized PHI access; the "agent as workforce member" problem. |
| `ASI04` | Agentic Supply Chain Compromise | Compromised external agents, tools, MCP servers, schemas, or foundation models the agent dynamically trusts — incl. BAA-relevant third-party model risk. |
| `ASI05` | Unexpected Code Execution | Agent-generated or agent-triggered code executes without validation/isolation against ePHI-bearing systems. |
| `ASI06` | Memory & Context Poisoning | Injection/leakage of agent memory or context — PHI persistence in context windows and corruption of persistent memory stores. |
| `ASI07` | Insecure Inter-Agent Communication | Manipulation, spoofing, or interception of messages between agents in multi-agent ePHI workflows. |
| `ASI08` | Cascading Agent Failures | A single agent failure propagates through connected tools, memory, and agents — relevant to contingency and integrity. |
| `ASI09` | Human-Agent Trust Exploitation | Misleading explanations or authority framing cause clinicians/staff to over-rely on agent output touching PHI or care decisions. |
| `ASI10` | Rogue Agents | Goal drift, collusion, or emergent behavior causes an agent to act beyond intended objectives against ePHI. |

> **Source:** OWASP GenAI Security Project, *OWASP Top 10 for Agentic Applications 2026*. The ASI prefix = "Agentic Security Issue." This document maps HIPAA Security Rule provisions to these recognized risk categories; it does not redefine them.

**Cross-cutting note — the audit gap:** One important HIPAA-specific concern does not have a one-to-one ASI entry: the inability to *attribute, log, and review autonomous agent actions at the action level*. This is treated throughout as a cross-cutting concern (it intersects ASI03, ASI07, and ASI10 and maps directly to §164.312(b) Audit Controls) and is flagged as **`[AUDIT]`** where it applies.

---

## What the 2024 NPRM Changes — and Why the Agentic Gap Survives It

The NPRM is the most important development for this analysis, because it closes several "the rule is silent" gaps I would otherwise have to flag. Understanding what it *does* fix sharpens what it *doesn't*.

**Removes the "Required" vs. "Addressable" distinction — nearly all specs become mandatory.**
Controls previously flagged as merely "addressable" (MFA, encryption, automatic logoff) would become **mandatory** for agent-accessed ePHI. The flexibility argument disappears.

**Mandatory technology asset inventory + network map** of all ePHI-handling systems, updated ≥ every 12 months.
Agentic systems, model artifacts, vector DBs, and MCP/tool endpoints would have to appear in the asset inventory — but the NPRM gives no guidance on *how* to inventory an autonomous agent or what attributes to capture.

**Mandatory MFA** for all technology assets (limited legacy/medical-device exceptions).
Forces the agent-identity question: an autonomous agent cannot "MFA" in the human sense. How a service-account agent satisfies a mandatory MFA control is undefined.

**Mandatory encryption** of ePHI at rest and in transit.
Extends to agent context windows, memory stores, and inter-agent messages — but the NPRM does not contemplate these as ePHI-bearing media.

**Network segmentation** required to limit lateral movement.
Multi-agent pipelines and MCP tool meshes create new lateral-movement paths that conventional network segmentation doesn't capture.

**Biannual vulnerability scanning + annual penetration testing.**
No standard scanner or pentest methodology exists for prompt injection, tool-call abuse, or intent drift. The mandate exists; the method to satisfy it for agents doesn't.

**72-hour restoration** of critical systems and data.
Agent dependency chains and model/vendor availability create restoration failure modes outside traditional DR scope.

**Business Associate annual verification** — evidence, not attestation; 24-hour contingency notification.
Sharpens the foundation-model-provider BAA problem: covered entities would have to *verify* an LLM provider's technical controls annually, with evidence. Most providers neither offer a BAA nor expose verifiable controls.

**Written documentation of all policies/procedures/analyses.**
Agentic risk analysis, intent guardrails, and agent inventories would all require formal written documentation that almost no covered entity currently produces.

**Bottom line:** The NPRM raises the floor but does not change the ceiling. It is the first HIPAA rulemaking to address AI at all — but it addresses **AI as data and model** (ePHI in training data, algorithms, and prediction models; AI tools in the asset inventory and risk analysis), **not AI as autonomous actor**. Every agentic threat category (the full OWASP ASI Top 10) remains unaddressed by name. The NPRM makes the *generic* controls mandatory and pulls AI tools into inventory and risk analysis; it provides no methodology for applying any of it to autonomous, tool-using, promptable systems. That methodological gap is what this mapping fills.

---

## The Mapping

Each entry below follows the same structure: the implementation spec, whether it's Required or Addressable under the current rule, how it applies to agentic systems, the OWASP ASI threat categories it maps to, and the specific control gap.

### ADMINISTRATIVE SAFEGUARDS (45 CFR §164.308)

#### §164.308(a)(1) — Security Management Process

**Risk Analysis** — `Required`
- **Agentic AI applicability:** Must explicitly scope agentic systems; existing risk analyses rarely model prompt injection, intent drift, or multi-agent trust. **[NPRM]** would mandate a written risk analysis tied to the technology asset inventory and network map — agentic systems would have to be inventoried and assessed, but with no methodology provided for agentic threats.
- **Threat categories:** ASI01, ASI10, ASI07
- **Control gap:** Most existing HIPAA risk analyses have no methodology for LLM-based threat modeling. The NPRM's more prescriptive risk-analysis process still does not define how to assess prompt injection, intent drift, or multi-agent trust.

**Risk Management** — `Required`
- **Agentic AI applicability:** Risk mitigation plans must address novel agentic controls (intent guardrails, tool call authorization, output filtering).
- **Threat categories:** ASI02, ASI10
- **Control gap:** No HIPAA guidance on acceptable risk thresholds for autonomous PHI access.

**Sanction Policy** — `Required`
- **Agentic AI applicability:** Sanctions apply to workforce members. Agents are not workforce members; accountability is diffuse.
- **Threat categories:** ASI03
- **Control gap:** No framework for sanctioning the deploying team when an agent causes a breach vs. the model provider vs. the integration developer.

**Information System Activity Review** — `Required`
- **Agentic AI applicability:** Agent audit logs must be structured to support activity review; most LLM platforms do not produce HIPAA-grade audit trails by default.
- **Threat categories:** `[AUDIT]`
- **Control gap:** Standard audit log tooling does not capture tool call sequences, prompt content, or agent reasoning steps.

#### §164.308(a)(2) — Assigned Security Responsibility

**(None — standard only)** — `Required`
- **Agentic AI applicability:** A security official must be designated. For agentic systems, accountability for agent behavior is often split across ML engineering, platform, and security teams with no clear owner.
- **Threat categories:** ASI03
- **Control gap:** Organizational accountability structures for agentic AI are undefined in most covered entities.

#### §164.308(a)(3) — Workforce Security

> **Legal classification note:** An AI agent is **not** a "workforce member" under HIPAA (which is limited to employees, volunteers, trainees, and others under a covered entity's direct control). An agent is legally an **Electronic Information System / software asset**, and the cleaner analysis governs it under Technical Safeguards (§164.312 Access Control and Audit Controls). The entries below are included because the risk-modeling questions workforce security raises (who authorized this actor, what is it cleared to touch, how is access revoked) map usefully onto agents — but they are an analogy for risk analysis, not a claim that agents are workforce. Where the analogy and the legal classification diverge, defer to the Technical Safeguards framing.

**Authorization and/or Supervision** — `Addressable`
- **Agentic AI applicability:** Who authorizes an agent's access to ePHI? Treated as an asset-authorization question (analogous to, not identical to, workforce authorization).
- **Threat categories:** ASI02, ASI03
- **Control gap:** No HIPAA guidance on whether agents require documented access authorization before accessing ePHI; best handled under §164.312(a) Access Control.

**Workforce Clearance Procedure** — `Addressable`
- **Agentic AI applicability:** No analog for agentic systems; model provenance and training data provenance are not part of clearance processes.
- **Threat categories:** ASI06, ASI04
- **Control gap:** Agent "clearance" — evaluating model provenance, training data, and tool access scope — has no established standard.

**Termination Procedures** — `Addressable`
- **Agentic AI applicability:** Revoking agent access on model deprecation, vendor change, or project termination is not standardized.
- **Threat categories:** ASI06, ASI04
- **Control gap:** Agent credentials, API keys, and memory stores are often not deprovisioned with the rigor applied to workforce termination.

#### §164.308(a)(4) — Information Access Management

**Isolating Healthcare Clearinghouse Functions** — `Required (if applicable)`
- **Agentic AI applicability:** Agent pipelines that span clearinghouse and non-clearinghouse functions create commingling risk.
- **Threat categories:** ASI07
- **Control gap:** Multi-agent architectures can inadvertently bridge isolated functions.

**Access Authorization** — `Addressable`
- **Agentic AI applicability:** Agents must have documented access authorization; currently ad hoc in most deployments.
- **Threat categories:** ASI02, ASI03
- **Control gap:** No standard for scoping and documenting LLM agent access to ePHI resources.

**Access Establishment and Modification** — `Addressable`
- **Agentic AI applicability:** Agent access scope often expands as capabilities are added; no formal change control.
- **Threat categories:** ASI02, ASI10
- **Control gap:** Tool additions, memory expansions, and API integrations change agent access scope without triggering formal review.

#### §164.308(a)(5) — Security Awareness and Training

**Security Reminders** — `Addressable`
- **Agentic AI applicability:** Workforce must understand that prompt injection is a real threat; social engineering now targets agent inputs, not just humans.
- **Threat categories:** ASI01
- **Control gap:** No HIPAA training guidance addresses prompt injection or adversarial AI inputs as a threat vector.

**Protection from Malicious Software** — `Addressable`
- **Agentic AI applicability:** Malicious content embedded in documents or data that agents process can function as malware via prompt injection.
- **Threat categories:** ASI01
- **Control gap:** Traditional malware definitions don't cover adversarial prompt content. Agents processing untrusted documents need the equivalent of AV scanning.

**Log-in Monitoring** — `Addressable`
- **Agentic AI applicability:** Agent authentication events must be monitored; agents often use shared service accounts without per-session attribution.
- **Threat categories:** `[AUDIT]`
- **Control gap:** Shared credentials and service accounts used by agents obscure individual action attribution.

**Password Management** — `Addressable`
- **Agentic AI applicability:** Agents require credential management (API keys, OAuth tokens); these are often stored in plaintext in configs or context.
- **Threat categories:** ASI06, ASI04
- **Control gap:** Agent credential hygiene is routinely poor; keys appear in logs, prompts, and environment variables.

#### §164.308(a)(6) — Security Incident Procedures

**Response and Reporting** — `Required`
- **Agentic AI applicability:** Incident response playbooks must address agentic scenarios: prompt injection breach, unintended PHI disclosure via agent output, agent-initiated unauthorized access.
- **Threat categories:** ASI01, ASI02, ASI10
- **Control gap:** IR playbooks rarely include LLM-specific detection signatures, containment steps (e.g., disabling tool access vs. shutting down agent), or forensic procedures for context window reconstruction.

#### §164.308(a)(7) — Contingency Plan

**Data Backup Plan** — `Required`
- **Agentic AI applicability:** Agent memory stores, fine-tuned model weights, and RAG indexes containing ePHI must be backed up with the same rigor as traditional ePHI stores.
- **Threat categories:** ASI06
- **Control gap:** Memory stores and vector databases are often excluded from formal backup and recovery planning.

**Disaster Recovery Plan** — `Required`
- **Agentic AI applicability:** Fallback procedures when an agentic system is unavailable must not result in uncontrolled data exposure or clinical workflow failures.
- **Threat categories:** ASI10
- **Control gap:** Agent dependency chains create failure modes that traditional DR plans don't model.

**Emergency Mode Operation** — `Required`
- **Agentic AI applicability:** Clinical agents must have defined emergency mode behavior; autonomous agents may continue operating during incidents when they should be suspended.
- **Threat categories:** ASI02
- **Control gap:** No guidance on emergency suspension of agentic systems handling ePHI.

**Testing and Revision** — `Addressable`
- **Agentic AI applicability:** Contingency tests should include agentic failure scenarios.
- **Threat categories:** ASI10, ASI07
- **Control gap:** Agentic failure modes (cascading agent failures, context corruption) are not in standard tabletop exercises.

**Applications and Data Criticality Analysis** — `Addressable`
- **Agentic AI applicability:** Agentic AI systems processing ePHI must be classified in the criticality analysis.
- **Threat categories:** ASI06
- **Control gap:** Agentic systems are frequently omitted from formal criticality analysis because they are perceived as "tools" rather than systems.

#### §164.308(a)(8) — Evaluation

**(None — standard only)** — `Required`
- **Agentic AI applicability:** Periodic technical and nontechnical evaluations must include agentic AI systems; model updates and tool integrations constitute environmental changes triggering re-evaluation.
- **Threat categories:** ASI10, ASI04
- **Control gap:** Model version updates (e.g., foundation model upgrades) are not typically treated as environmental changes requiring HIPAA re-evaluation.

#### §164.308(b) — Business Associate Contracts

**Written Contract or Other Arrangement** — `Required`
- **Agentic AI applicability:** Foundation model providers, MCP server vendors, and agentic platform providers that access ePHI are Business Associates requiring BAAs. **[NPRM]** would require covered entities to *verify* business associate technical controls annually with evidence (not attestation) and require 24-hour contingency-activation notification.
- **Threat categories:** ASI04
- **Control gap:** BAA coverage for LLM providers is frequently absent, ambiguous, or untested. Providers often claim inputs are not "maintained" and thus PHI rules don't apply — a contested position. The NPRM's annual evidence-based verification requirement collides directly with foundation-model providers who neither offer BAAs nor expose verifiable controls.

---

### PHYSICAL SAFEGUARDS (45 CFR §164.310)

#### §164.310(a) — Facility Access Controls

**Contingency Operations** — `Addressable`
- **Agentic AI applicability:** Physical access procedures during agent system outages.
- **Threat categories:** ASI10
- **Control gap:** Minimal gap; standard controls apply.

**Facility Security Plan** — `Addressable`
- **Agentic AI applicability:** Cloud-hosted agentic infrastructure shifts physical security to the provider; BAA must cover physical safeguards.
- **Threat categories:** ASI04
- **Control gap:** Cloud provider physical safeguards are inherited but must be verified; agent-specific infrastructure (GPU clusters, inference endpoints) may not be explicitly covered.

#### §164.310(d) — Device and Media Controls

**Disposal** — `Required`
- **Agentic AI applicability:** Model weights, fine-tuned adapters, RAG indexes, and vector databases containing ePHI must be included in media disposal procedures.
- **Threat categories:** ASI06
- **Control gap:** These artifact types are not in standard device/media disposal inventories. Model weight files containing embedded PHI from fine-tuning are a novel disposal challenge.

**Media Re-use** — `Required`
- **Agentic AI applicability:** GPU memory and inference infrastructure reuse creates risk of residual PHI in model state.
- **Threat categories:** ASI06
- **Control gap:** No established standard for verifying PHI is not retained in GPU memory or model KV caches between inference sessions.

**Accountability** — `Addressable`
- **Agentic AI applicability:** Inventory of ePHI-bearing model artifacts.
- **Threat categories:** ASI06
- **Control gap:** Model artifact inventory is not standard practice.

**Data Backup and Storage** — `Addressable`
- **Agentic AI applicability:** Same as §164.308(a)(7) — memory stores and model artifacts must be in scope.
- **Threat categories:** ASI06
- **Control gap:** See above.

---

### TECHNICAL SAFEGUARDS (45 CFR §164.312)

#### §164.312(a) — Access Control

**Unique User Identification** — `Required`
- **Agentic AI applicability:** Agents must have unique, attributable identities — not shared service accounts. Each agent instance should be individually identifiable in audit logs. **[NPRM]** mandatory MFA for all technology assets makes this acute: an autonomous agent cannot satisfy human-style MFA, and no guidance exists on how an agent identity meets the control.
- **Threat categories:** `[AUDIT]`, ASI03
- **Control gap:** Most agent deployments use shared service accounts or API keys with no per-agent identity. This violates the spirit of unique user identification, and the NPRM's mandatory MFA expansion has no defined satisfaction path for non-human agent identities.

**Emergency Access Procedure** — `Required`
- **Agentic AI applicability:** Defined procedure for emergency human override of agent PHI access.
- **Threat categories:** ASI02
- **Control gap:** No guidance exists on emergency access procedures for agentic systems.

**Automatic Logoff** — `Addressable (→ mandatory under [NPRM])`
- **Agentic AI applicability:** Agent sessions with access to ePHI must have defined session boundaries and automatic termination on inactivity or task completion.
- **Threat categories:** ASI06
- **Control gap:** Agent sessions are often persistent or indefinite; context windows may retain PHI indefinitely. This is a direct analog to the session persistence CWE-613 class of vulnerabilities. **[NPRM]** removal of the addressable category would make session-termination controls mandatory, but agent context/memory persistence is not contemplated as a "session."

**Encryption and Decryption** — `Addressable`
- **Agentic AI applicability:** ePHI in agent context windows, memory stores, and inter-agent communications must be encrypted in transit and at rest.
- **Threat categories:** ASI06, ASI07
- **Control gap:** Inter-agent communication (e.g., via MCP, API calls, or shared memory) is rarely encrypted with the same rigor as traditional ePHI transport.

#### §164.312(b) — Audit Controls

**(None — standard only)** — `Required`
- **Agentic AI applicability:** Audit controls must capture agent actions at sufficient granularity to reconstruct what ePHI was accessed, by which agent, using which tool, in response to which input. Standard request logging does not capture this action-level semantic detail by default.
- **Threat categories:** `[AUDIT]`
- **Control gap:** **This is the gap most often unaddressed by default — though it is solvable, not impossible.** Compliant agentic audit is achievable at the application/orchestration layer (e.g., enterprise cloud logging in Azure OpenAI or AWS Bedrock, or custom middleware wrapping orchestrators like LangChain/Semantic Kernel). The gap is that it must be *deliberately engineered*: raw foundation-model APIs do not provide it, and capturing which tool touched which ePHI resource under which reasoning step exceeds standard request logs. Detection and attribution at the autonomous-action level remain the most commonly missed control.

#### §164.312(c) — Integrity

**Authentication of ePHI** — `Addressable`
- **Agentic AI applicability:** Agents that modify ePHI (e.g., documentation agents writing to EHR) must maintain integrity controls; LLM hallucination is a novel integrity threat.
- **Threat categories:** ASI10
- **Control gap:** LLM hallucination introduces a new class of ePHI integrity risk — incorrect clinical data written by an agent to a medical record. No HIPAA guidance addresses AI-generated ePHI integrity.

#### §164.312(d) — Person or Entity Authentication

**(None — standard only)** — `Required`
- **Agentic AI applicability:** The authenticating entity for an agentic system is ambiguous — is it the model, the orchestrator, the deploying organization, or the end user? This chain of authentication is undefined.
- **Threat categories:** ASI07, ASI03
- **Control gap:** Multi-agent architectures where Agent A authenticates on behalf of Agent B to access ePHI have no HIPAA-compliant authentication model. Delegation and impersonation in agentic pipelines are unaddressed.

#### §164.312(e) — Transmission Security

**Encryption** — `Addressable`
- **Agentic AI applicability:** ePHI transmitted to/from LLM inference endpoints, between agents, and to external tools must be encrypted.
- **Threat categories:** ASI07, ASI04
- **Control gap:** MCP server connections, tool API calls, and agent-to-agent message passing are frequently not evaluated under the same transmission security standards as traditional ePHI.

**Integrity Controls** — `Addressable`
- **Agentic AI applicability:** Transmission integrity controls must detect prompt injection or manipulation of agent inputs in transit.
- **Threat categories:** ASI01
- **Control gap:** No existing transmission integrity control is designed to detect adversarial prompt manipulation. This is a genuinely novel requirement.

---

## Cross-Cutting Gap Summary

### Critical

**No HIPAA guidance on agentic system risk analysis methodology** — §164.308(a)(1)
NPRM impact: Worsens — mandates more prescriptive risk analysis but still provides no agentic methodology. *OCR enforcement posture unknown; NPRM not yet final.*

**Audit trail requirements cannot be met by current LLM platforms** — §164.312(b)
NPRM impact: Unchanged — does not modify audit controls in an agent-aware way. *Biggest structural gap; requires purpose-built observability.*

**BAA ambiguity for foundation model providers** — §164.308(b)
NPRM impact: Sharpens — would require annual evidence-based BA verification, which most LLM providers cannot satisfy. *Actively debated; covered entities bear risk.*

### High

**Agent identity and unique identification** — §164.312(a)(1)
NPRM impact: Sharpens — mandatory MFA has no defined satisfaction path for agents. *Addressable with current technology if guidance existed.*

**PHI in model artifacts (weights, RAG indexes, vector DBs)** — §164.310(d), §164.308(a)(7)
NPRM impact: Sharpens — asset inventory would require these be inventoried, but offers no method. *Novel artifact class not in standard HIPAA asset inventories.*

**LLM hallucination as ePHI integrity threat** — §164.312(c)
NPRM impact: Unchanged — does not address AI-generated ePHI integrity. *Clinical documentation agents are highest-risk.*

**Session/context window persistence** — §164.312(a)(2)(iii)
NPRM impact: Sharpens — would make session termination mandatory. *Direct analog to CWE-613; addressable with session boundary controls.*

### Medium

**Multi-agent authentication delegation** — §164.312(d)
NPRM impact: Unchanged — does not contemplate agent-to-agent delegation. *Architectural problem; no current standard.*

**Workforce definition gap** — §164.308(a)(3)
NPRM impact: Unchanged — retains workforce-centric framing. *Requires HHS rulemaking to fully resolve.*

**Prompt injection as transmission/integrity threat** — §164.312(e)(2)
NPRM impact: Unchanged — transmission controls do not address adversarial prompts. *Novel framing; no existing control maps to this.*

**Network segmentation for multi-agent/MCP meshes** — §164.312 *(new [NPRM] spec)*
NPRM impact: New — would mandate network segmentation, but agent/tool meshes create paths it doesn't model. *Net-new gap introduced by the NPRM itself.*

---

## Recommended Control Additions for Agentic AI in PHI Environments

These are controls not required by existing HIPAA text but recommended as reasonable and appropriate safeguards given the agentic threat model. Several map to **[NPRM]** mandates and would help satisfy them in an agentic context:

1. **Agent Identity Registry** — Maintain a formal inventory of all agentic systems with access to ePHI, including model version, tool access scope, and data access authorization *(directly supports the [NPRM] technology asset inventory mandate)*
2. **Action Authorization Guardrails** — Implement output filtering and pre-execution checks that verify agent actions remain within authorized scope before any tool call touches ePHI
3. **Agentic Audit Logging Standard** — Capture: agent ID, session ID, input summary (not full prompt if PHI-bearing), tool invocations, ePHI resources accessed, output classification, timestamp, human-in-loop decision points
4. **Session Boundary Enforcement** — Define and enforce context window clearance at task completion; prohibit ePHI persistence in memory stores beyond defined retention periods *(supports [NPRM] mandatory session-termination controls)*
5. **Prompt Injection Testing** — Include adversarial prompt testing in security assessments for any agent with PHI access *(a method for satisfying [NPRM] biannual vulnerability scanning / annual pentest mandates against agentic surfaces)*
6. **BAA Coverage Audit** — Explicitly evaluate all foundation model providers, inference platforms, and tool/MCP vendors for BAA requirement; document coverage determination rationale *(supports [NPRM] annual evidence-based BA verification)*
7. **Agent Change Control** — Treat model version upgrades, tool additions, and memory expansion as environmental changes requiring security re-evaluation under §164.308(a)(8)
8. **Agentic IR Playbook** — Develop incident response procedures specific to: prompt injection breach, unintended PHI disclosure via agent output, agent-initiated unauthorized data access, and multi-agent compromise propagation
9. **Agent/Tool Mesh Segmentation** — Extend network segmentation to inter-agent and MCP/tool-call paths so a compromised agent cannot reach ePHI systems outside its authorized scope *(supports [NPRM] network segmentation mandate for an architecture it doesn't model)*

---

## Relationship to Other Frameworks

**HIPAA Security Rule NPRM** (90 FR 898, Jan. 6, 2025)
Proposed overhaul; removes addressable/required distinction, mandates asset inventory, MFA, encryption, segmentation, vuln scanning, pentesting, 72-hr restoration, annual BA verification. **Does not address agentic AI by name.** Final rule delayed to July 2027 as of August 2026; moved to HHS's Long-Term Actions agenda amid industry opposition.

**OWASP Top 10 for Agentic Applications 2026 (ASI)**
**The threat taxonomy this document uses.** Peer-reviewed, industry-recognized agentic risk list (ASI01–ASI10). No HIPAA mapping of its own — this document supplies that HIPAA lens.

**ISO/IEC 42001 (AI Management System, 2023)**
International standard for AI governance; its AI system impact assessments and lifecycle-management requirements map closely to HIPAA Administrative Safeguards. Not healthcare-specific, but a strong governance backbone a covered entity can adopt alongside this mapping.

**NIST AI RMF (2023)**
Addresses AI risk generally; no HIPAA-specific mapping; no agentic-specific threat taxonomy.

**HHS HPH Cybersecurity Performance Goals (2024)**
Focuses on ransomware and phishing; does not address agentic AI.

**MITRE ATLAS**
Adversarial ML threat taxonomy; complements ASI01, ASI06, ASI10; no HIPAA mapping.

**OWASP LLM Top 10**
Application-level LLM risks; complements this mapping; no HIPAA context.

**NIST SP 800-66r2** (HIPAA Security Rule guidance, 2024)
HHS-endorsed implementation guidance; does not address agentic AI.

**QFIRE study** (medRxiv, June 2026)
Empirical healthcare-security research showing generic prompt-injection scanners fail in clinical settings — health-specific threats (out-of-scope clinical advice, stealth bulk PHI export) carry no standard "jailbreak" tokens, demonstrating the need for application-layer *semantic* boundaries. Direct evidence for the ASI01/ASI02 control recommendations here.

**42 CFR Part 2 Civil Enforcement Program** (OCR, effective Feb. 16, 2026)
OCR's first civil-penalty enforcement regime for substance-use-disorder record confidentiality. Not an agentic-AI action, but it sharpens the stakes of the over-disclosure scenario above where an agent surfaces SUD-adjacent data without authorization.

**HL7 FHIR Security**
Data exchange security; relevant to ASI04 for FHIR-connected agents.

---

## Related Work / Prior Art

This document is not the first to connect agentic AI to HIPAA, but no existing artifact does what this one does: a comprehensive, provision-by-provision, NPRM-aware, vendor-neutral mapping with a reusable threat taxonomy, maintained as an open resource. The closest prior work:

**Maiti, "Caging the Agents: A Zero Trust Security Architecture for Autonomous AI in Healthcare"** (arXiv 2603.17419, Mar 2026) — *Academic paper*
Six-domain agentic threat model (credential exposure, execution abuse, network egress, prompt integrity, database access, fleet drift) mapped to specific Security Rule provisions, tied to a deployed 9-agent architecture (gVisor, K8s NetworkPolicy, credential sidecars). The closest prior art. *How this differs:* threat-model-first and tied to one company's stack; maps a *subset* of provisions. This document walks the *full* rule, is NPRM-aware, vendor-neutral, and maintained. Cite as foundational.

**agenticcontrolplane.com, "SOC 2 and HIPAA for AI agents compliance playbook"** — *Vendor blog*
Control-by-control mapping from SOC 2 TSC and HIPAA Security Rule to AI-agent governance controls, with evidence-collection guidance and audit-failure modes. *How this differs:* product-tied and SOC-2-led; framed around evidence collection for audit. This document is neutral, regulation-first, and threat-taxonomy-driven.

**Vendor capability pages** (Protecto, Synthflow, Databricks AI Governance, etc.) — *Marketing/product*
Claim coverage of "the HIPAA Security Rule surface for AI" via PHI detection, minimum-necessary enforcement, tamper-proof audit logs. *How this differs:* these are implementations/claims, not analysis. This document is the neutral yardstick a buyer could measure them against.

**OSS tooling** (`aigis`, `ai-compliance` privacy-skills, `trevorbryant/awesome-controls` HIPAA↔NIST CSF crosswalk) — *Code / rule sets*
Implement controls or crosswalk HIPAA to other frameworks; some include HIPAA among many compliance templates. *How this differs:* tooling and crosswalks, not a Security-Rule-to-agentic-threat analysis. Complementary, not overlapping.

**Academic governance frameworks** ("AI Trust OS"; "Agentic AI Governance and Lifecycle Management in Healthcare") — *Academic*
Argue that agent-specific audit-ready artifacts (registry fields, provenance, policy decision records, deprovisioning evidence) are *not standardized*, leaving compliance risk unquantified. *How this differs:* these confirm the gap rather than fill it. This document is a concrete, structured response to the standardization gap they identify.

If you are aware of prior work that should be listed here, please open an issue or PR.

---

## Contributing

This is an early-stage community resource. Contributions welcome via pull request or issue.

Priority areas for expansion:
- Real-world control implementation examples
- Mapping to specific agentic architectures (single-agent, multi-agent, RAG-augmented)
- State-specific additions beyond federal HIPAA floor (CMIA, NY SHIELD, etc.)
- Worked examples of BAA language for LLM providers
- OCR enforcement precedent analysis as it develops

---

## References

- [45 CFR Part 164 — HIPAA Security Rule (current, in effect)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164)
- [HIPAA Security Rule NPRM — 90 FR 898, published Jan. 6, 2025](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information) ([govinfo primary source](https://www.govinfo.gov/app/details/FR-2025-01-06/2024-30983))
- [ISO/IEC 42001:2023 — Artificial Intelligence Management System](https://www.iso.org/standard/81230.html)
- QFIRE: "A Positive-Security Prompt Firewall that Closes the Scope and PHI Gap" (medRxiv, June 2026)
- [HHS OCR — HIPAA Security Rule NPRM fact sheet](https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/factsheet/index.html)
- [HHS — Request for Information: Harnessing AI in Health Care (Dec. 2025)](https://www.hhs.gov/press-room/hhs-ai-rfi.html)
- [NIST SP 800-66r2 — Implementing the HIPAA Security Rule (2024)](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final)
- [HHS HPH Cybersecurity Performance Goals (2024)](https://www.hhs.gov/sites/default/files/hhs-cybersecurity-performance-goals.pdf)
- [NIST AI Risk Management Framework (2023)](https://airc.nist.gov/RMF)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org/)
- [OWASP Top 10 for Agentic Applications 2026 (ASI)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [HHS Office for Civil Rights — HIPAA Enforcement](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/index.html)
- [HIPAA Journal — HIPAA Security Rule Update Postponed (final rule delayed to July 2027, RIN 0945-AA22)](https://www.hipaajournal.com/hipaa-security-rule-update-postponed/)
- [Ropes & Gray — HHS OCR Announces Civil Enforcement Program for Confidentiality of Substance Use Disorder Patient Records (42 CFR Part 2, effective Feb. 16, 2026)](https://www.ropesgray.com/en/insights/alerts/2026/02/hhs-ocr-announces-civil-enforcement-program-for-confidentiality-of-substance-use)

---

## Legal & Regulatory Disclaimers

### Regulatory & Legal Disclaimer

This project is provided for educational, analytical, and technical practitioner reference only. It does not constitute legal advice, regulatory compliance counsel, or an official determination of HIPAA/HITECH compliance.

Reading, implementing, or aligning with the controls outlined in this repository does not guarantee compliance with 45 CFR Part 160 or Part 164 (HIPAA Security & Privacy Rules), 42 CFR Part 2, or any federal, state, or international laws. Covered entities, business associates, and healthcare technology developers must consult their own legal counsel, compliance officers, and qualified auditors to evaluate their specific risk profiles and legal obligations.

### No Reliance & No Safe Harbor

The control mappings, threat taxonomies, and recommendations contained herein represent theoretical and practitioner-based risk analyses. They have not been formally endorsed, reviewed, or approved by the U.S. Department of Health and Human Services (HHS), the Office for Civil Rights (OCR), NIST, or any regulatory authority.

Adoption of these recommendations does not create a regulatory safe harbor, nor does it shield any organization from civil monetary penalties, administrative enforcement, or private litigation resulting from security incidents, ePHI breaches, or unauthorized disclosures.

### Personal Capacity & Non-Endorsement

This repository is strictly the personal, independent research and intellectual work of the maintainer, created solely on personal time and resources.

The opinions, interpretations, and framework designs expressed here do not represent, reflect, or engage the official positions, policies, strategies, or endorsements of any current or former employer, consulting client, academic institution, or professional organization (including, but not limited to, Verily Life Sciences, UCLA Health, Farmers Insurance, ArmorIQ, USC, ISSA, or OWASP).

This document is independently authored and is not an official OWASP project, publication, or deliverable. The maintainer's role as an OWASP chapter leader does not extend to speaking on behalf of the OWASP Foundation, and this mapping's use of the OWASP Top 10 for Agentic Applications (ASI) taxonomy does not imply OWASP's review, endorsement, or sponsorship of this repository.

### Trademarks & Attribution

All product names, logos, brands, trademarks, and registered trademarks referenced in this repository (e.g., HBO, OWASP, NIST, ISO, AWS, Azure) are the property of their respective owners. Their inclusion in this repository is strictly for descriptive, educational, and analytical identification purposes and does not imply endorsement, affiliation, or sponsorship.
