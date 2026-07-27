"""AI model registry — up-to-date model catalog for all supported providers.

Each model is described with an ID, display name, description, and provider so
the interactive chat UI can offer informed choices.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Model info dataclass
# ---------------------------------------------------------------------------


@dataclass
class ModelInfo:
    """Describes a single LLM model available for chat."""

    id: str          # API model identifier, e.g. "claude-sonnet-5"
    name: str        # Human-readable label, e.g. "Claude Sonnet 5"
    description: str  # One-line summary shown in selection menus
    provider: str     # "openai" | "anthropic" | "deepseek" | "ollama"
    tags: list[str] | None = None  # e.g. ["reasoning", "fast", "multimodal"]


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


PROVIDER_META: dict[str, dict] = {
    "anthropic": {
        "name": "Anthropic",
        "description": "Claude modelleri — Opus 4.8, Sonnet 5, Fable 5, Haiku 4.5",
    },
    "openai": {
        "name": "OpenAI",
        "description": "GPT-4o, GPT-4.1, o4-mini, o3 — geniş model yelpazesi",
    },
    "deepseek": {
        "name": "DeepSeek",
        "description": "DeepSeek-V4 Pro, V4 Flash, ve R1 (reasoner) — uygun maliyetli",
    },
    "kimi": {
        "name": "Kimi (Moonshot AI)",
        "description": "Kimi K2.5, K2 Instruct, K2 Thinking — 128K context, OpenAI uyumlu API",
    },
    "cursor": {
        "name": "Cursor",
        "description": "Cursor IDE modelleri — OpenAI uyumlu API, hızlı kod tamamlama ve analiz",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "description": "Yerel makinede çalışan açık kaynak modeller — internet gerektirmez",
    },
}


# ---------------------------------------------------------------------------
# Model catalog (current as of July 2026)
# ---------------------------------------------------------------------------


OPENAI_MODELS: list[ModelInfo] = [
    ModelInfo(
        id="gpt-4o",
        name="GPT-4o",
        description="Çok modlu amiral gemisi — 128K context, görüntü/ses desteği",
        provider="openai",
        tags=["multimodal", "flagship"],
    ),
    ModelInfo(
        id="gpt-4o-mini",
        name="GPT-4o Mini",
        description="Hızlı ve uygun maliyetli — günlük kullanım için ideal",
        provider="openai",
        tags=["fast", "cost-effective"],
    ),
    ModelInfo(
        id="gpt-4.1",
        name="GPT-4.1",
        description="En yeni sürüm — 1M token context penceresi",
        provider="openai",
        tags=["flagship", "long-context"],
    ),
    ModelInfo(
        id="gpt-4.1-mini",
        name="GPT-4.1 Mini",
        description="GPT-4.1'in dengeli versiyonu — performans/maliyet odaklı",
        provider="openai",
        tags=["balanced", "cost-effective"],
    ),
    ModelInfo(
        id="gpt-4.1-nano",
        name="GPT-4.1 Nano",
        description="En ucuz ve en hızlı GPT-4.1 varyantı",
        provider="openai",
        tags=["fast", "cheapest"],
    ),
    ModelInfo(
        id="o4-mini",
        name="o4-mini",
        description="Gelişmiş akıl yürütme (reasoning) — hızlı ve güçlü",
        provider="openai",
        tags=["reasoning", "fast"],
    ),
    ModelInfo(
        id="o3",
        name="o3",
        description="En gelişmiş akıl yürütme — karmaşık analizler için",
        provider="openai",
        tags=["reasoning", "flagship"],
    ),
    ModelInfo(
        id="o3-mini",
        name="o3-mini",
        description="Akıl yürütme — uygun maliyetli, hızlı",
        provider="openai",
        tags=["reasoning", "cost-effective"],
    ),
]

ANTHROPIC_MODELS: list[ModelInfo] = [
    ModelInfo(
        id="claude-opus-4-8",
        name="Claude Opus 4.8",
        description="En güçlü Claude — en karmaşık görevler, extended thinking",
        provider="anthropic",
        tags=["flagship", "reasoning", "extended-thinking"],
    ),
    ModelInfo(
        id="claude-sonnet-5",
        name="Claude Sonnet 5",
        description="Dengeli performans — hızlı ama güçlü, günlük kullanım",
        provider="anthropic",
        tags=["balanced", "fast"],
    ),
    ModelInfo(
        id="claude-fable-5",
        name="Claude Fable 5",
        description="Yaratıcı ve esnek — uzun metin üretimi için optimize",
        provider="anthropic",
        tags=["creative", "long-form"],
    ),
    ModelInfo(
        id="claude-haiku-4-5",
        name="Claude Haiku 4.5",
        description="En hızlı Claude — basit görevler, düşük gecikme",
        provider="anthropic",
        tags=["fast", "cost-effective"],
    ),
]

DEEPSEEK_MODELS: list[ModelInfo] = [
    ModelInfo(
        id="deepseek-v4-pro",
        name="DeepSeek-V4 Pro",
        description="En güçlü DeepSeek — 1.6T param, 1M context, karmaşık görevler",
        provider="deepseek",
        tags=["flagship", "reasoning", "long-context"],
    ),
    ModelInfo(
        id="deepseek-v4-flash",
        name="DeepSeek-V4 Flash",
        description="Hızlı ve ekonomik — 284B param, günlük kullanım için ideal",
        provider="deepseek",
        tags=["fast", "cost-effective", "balanced"],
    ),
]

KIMI_MODELS: list[ModelInfo] = [
    ModelInfo(
        id="kimi-k3",
        name="Kimi K3",
        description="En yeni Kimi K3 — 256K context, Moonshot amiral gemisi, en gelişmiş akıl yürütme",
        provider="kimi",
        tags=["flagship", "reasoning", "long-context", "latest"],
    ),
    ModelInfo(
        id="kimi-k2.5",
        name="Kimi K2.5",
        description="Güçlü Kimi — 128K context, gelişmiş akıl yürütme, karmaşık analiz",
        provider="kimi",
        tags=["reasoning", "long-context"],
    ),
    ModelInfo(
        id="kimi-k2-instruct",
        name="Kimi K2 Instruct",
        description="Dengeli Kimi — hızlı, komut takibi güçlü, günlük kullanım için ideal",
        provider="kimi",
        tags=["balanced", "fast", "instruction-following"],
    ),
    ModelInfo(
        id="kimi-k2-thinking",
        name="Kimi K2 Thinking",
        description="Derin düşünme odaklı — zincirleme akıl yürütme, karmaşık problem çözme",
        provider="kimi",
        tags=["reasoning", "thinking", "deep-analysis"],
    ),
]

CURSOR_MODELS: list[ModelInfo] = [
    ModelInfo(
        id="cursor-small",
        name="Cursor Small",
        description="Hızlı ve hafif — kod tamamlama, basit analizler, düşük gecikme",
        provider="cursor",
        tags=["fast", "cost-effective", "code"],
    ),
    ModelInfo(
        id="cursor-medium",
        name="Cursor Medium",
        description="Dengeli — kod inceleme, refactoring, orta karmaşıklıkta görevler",
        provider="cursor",
        tags=["balanced", "code", "analysis"],
    ),
    ModelInfo(
        id="cursor-large",
        name="Cursor Large",
        description="En güçlü Cursor — derin kod analizi, mimari kararlar, karmaşık görevler",
        provider="cursor",
        tags=["flagship", "code", "deep-analysis"],
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_models(provider: str) -> list[ModelInfo]:
    """Return all known models for a provider.

    For Ollama, models are detected dynamically from the local installation.
    """
    if provider == "openai":
        return list(OPENAI_MODELS)
    if provider == "anthropic":
        return list(ANTHROPIC_MODELS)
    if provider == "deepseek":
        return list(DEEPSEEK_MODELS)
    if provider == "kimi":
        return list(KIMI_MODELS)
    if provider == "cursor":
        return list(CURSOR_MODELS)
    if provider == "ollama":
        return _detect_ollama_models()
    return []


def list_providers() -> list[dict]:
    """Return provider metadata for display in selection menus."""
    result: list[dict] = []
    for key, meta in PROVIDER_META.items():
        entry = dict(meta)
        entry["id"] = key
        # Show model count for static providers
        if key != "ollama":
            entry["model_count"] = len(get_models(key))
        else:
            entry["model_count"] = None  # dynamic
        result.append(entry)
    return result


def get_default_model(provider: str) -> Optional[str]:
    """Return the recommended default model ID for a provider."""
    defaults = {
        "openai": "gpt-4o-mini",
        "anthropic": "claude-sonnet-5",
        "deepseek": "deepseek-v4-flash",
        "kimi": "kimi-k3",
        "cursor": "cursor-medium",
    }
    if provider in defaults:
        return defaults[provider]
    if provider == "ollama":
        models = _detect_ollama_models()
        return models[0].id if models else None
    return None


def get_provider_name(provider: str) -> str:
    """Return the human-readable provider name."""
    meta = PROVIDER_META.get(provider, {})
    return meta.get("name", provider.title())


# ---------------------------------------------------------------------------
# Ollama dynamic detection
# ---------------------------------------------------------------------------


def _detect_ollama_models() -> list[ModelInfo]:
    """Detect available Ollama models from the local installation."""
    try:
        from ai_core.llm_engine import LLMClient

        client = LLMClient(provider="ollama")
        names = client._list_ollama_models()
        if not names:
            return [
                ModelInfo(
                    id="llama3.1:8b",
                    name="Llama 3.1 8B",
                    description="Varsayılan — Ollama'da model bulunamadı, manuel kurun",
                    provider="ollama",
                    tags=["fallback"],
                )
            ]
        result: list[ModelInfo] = []
        for name in names:
            # Build a reasonable display name and description
            display = name.replace(":latest", "").replace(":"," ")
            desc = f"Yerel model: {name}"
            # Tag popular models
            tags: list[str] = []
            if "llama" in name.lower():
                tags.append("meta")
            elif "mistral" in name.lower():
                tags.append("european")
            elif "qwen" in name.lower():
                tags.append("alibaba")
            elif "gemma" in name.lower():
                tags.append("google")
            elif "phi" in name.lower():
                tags.append("microsoft")
            elif "deepseek" in name.lower():
                tags.append("reasoning")

            result.append(
                ModelInfo(
                    id=name,
                    name=display,
                    description=desc,
                    provider="ollama",
                    tags=tags if tags else None,
                )
            )
        return result
    except Exception:
        return [
            ModelInfo(
                id="llama3.1:8b",
                name="Llama 3.1 8B (varsayılan)",
                description="Ollama'ya erişilemedi — manuel kurulum gerekebilir",
                provider="ollama",
                tags=["fallback"],
            )
        ]
