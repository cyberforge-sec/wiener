"""LLM provider layer.

Failover ladder:
  NORMAL  → configured provider (OpenCode or Local)
  CLOUD FAILURE → fallback to Local
  LOCAL FAILURE  → fallback to Replay
"""
