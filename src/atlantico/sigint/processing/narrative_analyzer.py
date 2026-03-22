"""
NarrativeAnalyzer — NLP para detecção de desinformação e análise de narrativas.

Implementado com sklearn (TF-IDF, NMF, cosine similarity) + regex NER.
Sem dependências pesadas (sem spacy, sem transformers).

Capacidades:
  - Extração de entidades nomeadas por regex (CVEs, IPs, domínios, orgs)
  - Análise de sentimento por léxico (PT-BR e EN)
  - Clustering de documentos similares (cosine similarity em TF-IDF)
  - Modelagem de tópicos (NMF sobre TF-IDF)
  - Detecção de amplificação coordenada (mesma narrativa, múltiplas fontes)
  - Score de desinformação composto
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np

logger = logging.getLogger(__name__)

# ─── Regex NER ─────────────────────────────────────────────────────────────────

_CVE_RE      = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IP_RE       = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE   = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_HASH_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# ─── Léxico de sentimento / ameaça ─────────────────────────────────────────────

_THREAT_LEXICON = {
    "en": {
        "critical": -0.9, "attack": -0.7, "breach": -0.8, "exploit": -0.75,
        "ransomware": -0.9, "malware": -0.8, "vulnerability": -0.6,
        "warning": -0.5, "risk": -0.4, "threat": -0.6, "hack": -0.7,
        "compromised": -0.8, "infected": -0.75, "zero-day": -0.85,
        "patch": 0.3, "fixed": 0.4, "mitigated": 0.5, "resolved": 0.4,
        "secure": 0.5, "protected": 0.4, "updated": 0.3,
    },
    "pt": {
        "crítico": -0.9, "ataque": -0.7, "vazamento": -0.8, "invasão": -0.8,
        "ransomware": -0.9, "vírus": -0.75, "vulnerabilidade": -0.6,
        "alerta": -0.5, "risco": -0.4, "ameaça": -0.6, "hacker": -0.65,
        "comprometido": -0.8, "infectado": -0.75, "zero-day": -0.85,
        "patch": 0.3, "corrigido": 0.4, "mitigado": 0.5, "resolvido": 0.4,
        "seguro": 0.5, "protegido": 0.4, "atualizado": 0.3,
        # Desinformação PT-BR
        "fake": -0.6, "mentira": -0.7, "falso": -0.65, "boato": -0.6,
        "desinformação": -0.8, "manipulação": -0.7,
    },
}

# ─── Keywords de desinformação ─────────────────────────────────────────────────

_DISINFO_SIGNALS = {
    "en": [
        "unverified", "rumor", "conspiracy", "fake", "false claim",
        "disinformation", "propaganda", "manipulated", "deepfake",
        "bot network", "coordinated", "astroturfing", "troll",
        "influence operation", "state-sponsored", "fabricated",
    ],
    "pt": [
        "não verificado", "boato", "conspiração", "fake", "mentira",
        "desinformação", "propaganda", "manipulado", "deepfake",
        "rede de bots", "coordenado", "troll", "robôs",
        "operação de influência", "patrocinado pelo estado", "fabricado",
        "fake news", "notícia falsa",
    ],
}

# Organizações conhecidas de segurança/governo (heurística)
_KNOWN_ORGS = [
    "cert.br", "anatel", "serpro", "cisa", "nsa", "cni", "abin",
    "microsoft", "google", "apple", "cisco", "fortinet", "palo alto",
    "mandiant", "crowdstrike", "kaspersky", "symantec",
    "polícia federal", "mpf", "tcu", "agu",
]


@dataclass
class NlpResult:
    """Resultado NLP de um NewsItem."""
    item_id:         str
    sentiment_score: float          # [-1.0, 1.0]
    sentiment_label: str            # "threat" | "negative" | "neutral" | "positive"
    topics:          list[str]
    keywords:        list[str]
    entities: dict = field(default_factory=lambda: {
        "cves": [], "ips": [], "domains": [], "hashes": [], "orgs": []
    })
    disinfo_score:   float = 0.0    # [0.0, 1.0]
    cluster_id:      str | None = None


@dataclass
class ClusterResult:
    """Resultado de clustering de artigos por similaridade."""
    cluster_id:   str
    item_ids:     list[str]
    central_text: str
    key_topics:   list[str]
    source_count: int
    is_amplification: bool          # mesma história em múltiplas fontes
    disinfo_score:    float


class NarrativeAnalyzer:
    """
    Analisa corpus de notícias/posts para detectar desinformação e padrões narrativos.

    Uso:
        analyzer = NarrativeAnalyzer()
        nlp_results = analyzer.analyze_batch(items)
        clusters = analyzer.cluster_items(items)
        disinfo_campaigns = analyzer.detect_disinfo_campaigns(clusters, items)
    """

    def __init__(
        self,
        similarity_threshold: float = 0.35,
        disinfo_threshold:    float = 0.4,
        min_cluster_size:     int   = 2,
        n_topics:             int   = 8,
    ) -> None:
        self._sim_threshold    = similarity_threshold
        self._disinfo_threshold = disinfo_threshold
        self._min_cluster_size = min_cluster_size
        self._n_topics         = n_topics

    def analyze_item(
        self,
        item_id: str,
        title: str,
        content: str,
        language: str = "en",
    ) -> NlpResult:
        """Análise NLP de um único item."""
        full_text = f"{title} {content}"

        entities      = self._extract_entities(full_text)
        sentiment     = self._compute_sentiment(full_text, language)
        sent_label    = self._sentiment_label(sentiment)
        keywords      = self._extract_keywords(full_text, language)
        disinfo_score = self._compute_disinfo_score(full_text, language)

        return NlpResult(
            item_id=item_id,
            sentiment_score=round(sentiment, 4),
            sentiment_label=sent_label,
            topics=[],        # preenchido em analyze_batch (corpus necessário)
            keywords=keywords,
            entities=entities,
            disinfo_score=round(disinfo_score, 4),
        )

    def analyze_batch(
        self,
        items: list[dict],
        language: str = "en",
    ) -> list[NlpResult]:
        """
        Analisa um lote de items e adiciona tópicos (NMF sobre corpus completo).

        Args:
            items: list de dicts com keys "id", "title", "content", "language"
        """
        results: list[NlpResult] = []

        # Análise individual
        for item in items:
            result = self.analyze_item(
                item_id=item.get("id", ""),
                title=item.get("title", ""),
                content=item.get("content", ""),
                language=item.get("language", language),
            )
            results.append(result)

        # Topic modeling em batch
        if len(items) >= 3:
            try:
                topics_per_item = self._extract_topics_batch(
                    [f"{i.get('title','')} {i.get('content','')}" for i in items]
                )
                for i, result in enumerate(results):
                    result.topics = topics_per_item[i] if i < len(topics_per_item) else []
            except Exception as exc:
                logger.warning("Topic modeling falhou: %s", exc)

        return results

    def cluster_items(
        self,
        items: list[dict],
    ) -> list[ClusterResult]:
        """
        Agrupa artigos similares por TF-IDF cosine similarity.

        Detecta amplificação: mesma história publicada em múltiplas fontes.
        """
        if len(items) < 2:
            return []

        texts = [f"{i.get('title','')} {i.get('content','')}" for i in items]

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity

            tfidf = TfidfVectorizer(
                max_features=500, stop_words="english",
                ngram_range=(1, 2), min_df=1,
            )
            matrix = tfidf.fit_transform(texts)
            sim_matrix = cosine_similarity(matrix)
        except Exception as exc:
            logger.warning("TF-IDF clustering falhou: %s", exc)
            return []

        # Greedy clustering
        n = len(items)
        assigned = [-1] * n
        cluster_id = 0
        clusters: dict[int, list[int]] = {}

        for i in range(n):
            if assigned[i] != -1:
                continue
            assigned[i] = cluster_id
            clusters[cluster_id] = [i]
            for j in range(i + 1, n):
                if assigned[j] == -1 and sim_matrix[i, j] >= self._sim_threshold:
                    assigned[j] = cluster_id
                    clusters[cluster_id].append(j)
            if len(clusters[cluster_id]) < self._min_cluster_size:
                del clusters[cluster_id]
            else:
                cluster_id += 1

        results: list[ClusterResult] = []
        for cid, indices in clusters.items():
            cluster_items = [items[i] for i in indices]
            sources = {i.get("feed_name") or i.get("source_id", "?") for i in cluster_items}
            central_text = cluster_items[0].get("title", "")
            cluster_texts = " ".join(
                f"{i.get('title','')} {i.get('content','')}"[:500] for i in cluster_items
            )
            keywords = self._extract_keywords(cluster_texts, "en")
            disinfo  = self._compute_disinfo_score(cluster_texts, "en")
            is_amp   = len(sources) >= 2

            results.append(ClusterResult(
                cluster_id=f"cluster-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{cid:03d}",
                item_ids=[i.get("id", "") for i in cluster_items],
                central_text=central_text,
                key_topics=keywords[:5],
                source_count=len(sources),
                is_amplification=is_amp,
                disinfo_score=round(disinfo, 4),
            ))

        return results

    def detect_disinfo_campaigns(
        self,
        clusters: list[ClusterResult],
        all_items: list[dict],
    ) -> list[dict]:
        """
        Identifica campanhas de desinformação a partir de clusters.

        Retorna lista de dicts prontos para NarrativeCampaignRepository.create_or_update().
        """
        campaigns: list[dict] = []
        now = datetime.now(timezone.utc)

        for cluster in clusters:
            if cluster.disinfo_score < self._disinfo_threshold:
                continue

            # Inferir tipo de campanha
            if cluster.is_amplification and cluster.disinfo_score >= 0.6:
                camp_type = "influence_op"
            elif cluster.is_amplification:
                camp_type = "amplification"
            elif cluster.disinfo_score >= 0.5:
                camp_type = "disinfo"
            else:
                camp_type = "disinfo"

            severity = (
                "CRITICAL" if cluster.disinfo_score >= 0.8 else
                "HIGH"     if cluster.disinfo_score >= 0.6 else
                "MEDIUM"
            )

            campaigns.append({
                "campaign_name":       f"Narrativa-{cluster.cluster_id}",
                "campaign_type":       camp_type,
                "description":         f"Cluster de {cluster.source_count} fonte(s): {cluster.central_text[:200]}",
                "first_seen":          now,
                "last_seen":           now,
                "item_count":          len(cluster.item_ids),
                "source_count":        cluster.source_count,
                "disinfo_score":       cluster.disinfo_score,
                "amplification_score": 0.8 if cluster.is_amplification else 0.3,
                "confidence":          0.6 + cluster.disinfo_score * 0.3,
                "central_narrative":   cluster.central_text,
                "key_topics":          cluster.key_topics,
                "key_entities":        {},
                "target_audience":     [],
                "geo_targets":         [],
                "severity":            severity,
                "analysis_status":     "active",
                "alert_generated":     "false",
                "related_cyber_threat_ids": [],
            })

        return campaigns

    # ── NLP helpers ─────────────────────────────────────────────────────────────

    def _extract_entities(self, text: str) -> dict:
        cves    = list(set(_CVE_RE.findall(text)))
        ips     = [ip for ip in _IP_RE.findall(text) if not ip.startswith("0.")]
        domains = [
            d for d in _DOMAIN_RE.findall(text)
            if len(d) > 4 and "." in d and not _IP_RE.match(d)
        ]
        hashes  = (
            list(set(_HASH_SHA256.findall(text))) +
            list(set(_HASH_MD5.findall(text)))
        )
        orgs = [org for org in _KNOWN_ORGS if org.lower() in text.lower()]

        return {
            "cves":    cves[:10],
            "ips":     list(set(ips))[:10],
            "domains": list(set(domains))[:10],
            "hashes":  hashes[:10],
            "orgs":    orgs[:10],
        }

    def _compute_sentiment(self, text: str, language: str) -> float:
        lexicon = _THREAT_LEXICON.get(language, _THREAT_LEXICON["en"])
        text_lower = text.lower()
        scores = [score for word, score in lexicon.items() if word in text_lower]
        if not scores:
            return 0.0
        return float(np.clip(np.mean(scores), -1.0, 1.0))

    def _sentiment_label(self, score: float) -> str:
        if score <= -0.6:
            return "threat"
        if score <= -0.2:
            return "negative"
        if score >= 0.2:
            return "positive"
        return "neutral"

    def _extract_keywords(self, text: str, language: str, top_n: int = 10) -> list[str]:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            stop_words = "english" if language == "en" else None
            tfidf = TfidfVectorizer(
                max_features=200, stop_words=stop_words,
                ngram_range=(1, 2), min_df=1,
            )
            matrix = tfidf.fit_transform([text])
            feature_names = tfidf.get_feature_names_out()
            scores = matrix.toarray()[0]
            top_idx = np.argsort(scores)[::-1][:top_n]
            return [feature_names[i] for i in top_idx if scores[i] > 0]
        except Exception:
            # Fallback: frequência de palavras
            words = re.findall(r"\b[a-zA-ZÀ-ú]{4,}\b", text.lower())
            counter = Counter(words)
            return [w for w, _ in counter.most_common(top_n)]

    def _compute_disinfo_score(self, text: str, language: str) -> float:
        text_lower = text.lower()
        signals    = _DISINFO_SIGNALS.get(language, _DISINFO_SIGNALS["en"])
        matches    = sum(1 for s in signals if s in text_lower)

        # Score base: proporção de sinais detectados
        base_score = min(matches / max(len(signals) * 0.3, 1), 1.0)

        # Boost: uso de múltiplas fontes não verificadas
        unverified = text_lower.count("unverified") + text_lower.count("não verificado")
        boost = min(unverified * 0.1, 0.2)

        return min(base_score + boost, 1.0)

    def _extract_topics_batch(self, texts: list[str]) -> list[list[str]]:
        from sklearn.decomposition import NMF
        from sklearn.feature_extraction.text import TfidfVectorizer

        tfidf = TfidfVectorizer(
            max_features=300, stop_words="english",
            ngram_range=(1, 2), min_df=1,
        )
        matrix = tfidf.fit_transform(texts)
        n_components = min(self._n_topics, len(texts), matrix.shape[1])
        if n_components < 1:
            return [[] for _ in texts]

        nmf = NMF(n_components=n_components, random_state=42, max_iter=200)
        W   = nmf.fit_transform(matrix)  # docs × topics
        H   = nmf.components_            # topics × terms

        feature_names = tfidf.get_feature_names_out()
        # Top 3 termos por tópico
        topic_labels = [
            "_".join(feature_names[np.argsort(H[t])[::-1][:3]])
            for t in range(n_components)
        ]

        # Para cada documento, retorna o tópico dominante
        result: list[list[str]] = []
        for doc_row in W:
            top_topic = int(np.argmax(doc_row))
            result.append([topic_labels[top_topic]])

        return result
