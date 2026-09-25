"""LLM provider layer.

Failover ladder:
  NORMAL  → configured cloud (any OpenAI-compatible endpoint) or local Ollama
  CLOUD FAILURE → fallback to local Ollama
  LOCAL FAILURE  → fallback to Replay
"""
