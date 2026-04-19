---
title: AI Shield Intelligence
subtitle: How I keep myself up to date on the latest threats and attack techniques
date: April 14, 2026
aspectratio: 169
---

# AI Shield Intelligence In One Sentence

- A local-first AI threat intelligence platform for collecting, classifying, enriching, and serving AI/ML security threats.
- It turns raw external signals into structured records that engineers and downstream systems can query.
- In this repo, the production-ready profile is the minimal local deployment in src/minimal-local.

# What The System Actually Does

- Pulls from research, advisories, GitHub, CVE feeds, and community channels.
- Normalizes and deduplicates incoming documents into threat records.
- Classifies threat type and extracts entities, MITRE mappings, and severity.
- Stores raw artifacts plus structured metadata for search and analytics.
- Serves the output through FastAPI, React, scheduled jobs, and alert hooks.

![](images/minimal-local-dashboard.png){width=68%}

# Why This Matters To A Technical Team

- AI attack techniques change faster than most hand-written security test suites.
- Raw papers and repos are hard to operationalize under normal engineering time pressure.
- This system compresses the path from "new attack published" to "searchable, scored, testable threat."
- Structured metadata makes the output automatable by other tools instead of analyst-only.

# Architecture: Data Flow

- Sources: arXiv, security blogs, NVD/CVEs, GitHub, Reddit, Hacker News, other feeds.
- Ingestion: scheduled RSS/API/scraping collectors plus manual or event-driven inputs.
- Processing: normalization, deduplication, classification, entity extraction, MITRE ATLAS mapping.
- Analysis: optional Ollama-based LLM summaries, attack vectors, and mitigations.
- Delivery: search APIs, threat detail APIs, analytics UI, and alert notifications.

# Runtime Architecture: Data And Infrastructure

- PostgreSQL is the system of record for threats, entities, MITRE mappings, and LLM output.
- Redis is the queue broker and cache for asynchronous processing.
- MinIO stores raw threat payloads and collected artifacts.
- Ollama provides local model inference in the minimal deployment profile.
- Docker Compose ties the services together for a single-node pilot environment.

# Runtime Architecture: Application Services

- FastAPI exposes auth, search, threat retrieval, analytics, and system status endpoints.
- Celery Worker runs collection, enrichment, and LLM analysis tasks.
- Celery Beat triggers recurring collection on a schedule.
- React provides dashboard, search, threat detail, and settings views.
- Net effect: a complete analyst-facing platform, not just a background crawler.

# Why The Data Model Matters

- Threats carry structured classification metadata rather than only free text.
- Important fields include attack surface, testability, and target systems.
- Those fields let clients filter for runtime-testable threats and relevant system classes.
- This is the key design choice that makes the intelligence feed usable by automation.

![](images/threat-details.png){width=52%}

# How Eval Kit Uses The Feed

- Upstream interface: POST /api/v1/auth/login plus GET /api/v1/search, /api/v1/threats/recent, and /api/v1/threats/high-severity.
- Selects threats from AI Shield Intelligence using search, recent, and severity-based pulls.
- Deduplicates already-processed threats before spending enrichment or LLM time.
- Enriches source content to extract payloads, trigger phrases, and attack details.
- Filters for runtime-testable cases such as prompt injection, jailbreak, extraction, and adversarial flows.
- Generates validated YAML seeds for GenAI and agentic system evaluation.
- Simplified flow: fetch threats -> filter and enrich -> generate seeds -> write catalog.

# Why The Two Repos Belong Together

- AI Shield Intelligence answers: what new attack patterns exist right now?
- AI Shield Eval Kit answers: can our model or agent handle those attacks today?
- Combined, they form a pipeline from external threat discovery to repeatable validation.
- That pipeline keeps the test catalog current as the threat landscape changes.

# Technical Takeaway

- This repo is the intelligence backbone.
- The eval kit is the execution layer that converts intelligence into tests.
- The value is the handoff: structured threat records become living security evaluations.
