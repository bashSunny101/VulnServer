"""
========================================
Elasticsearch Client
========================================
LEARNING: Elasticsearch for full-text search and analytics
- Search across all honeypot events
- Aggregations for dashboards
- Real-time queries
"""

from elasticsearch import AsyncElasticsearch
from config import settings

# Global Elasticsearch client
es_client: AsyncElasticsearch = None


async def init_elasticsearch():
    """Initialize Elasticsearch connection"""
    global es_client
    es_client = AsyncElasticsearch(
        [settings.elasticsearch_url],
        basic_auth=("elastic", settings.elastic_password),
        verify_certs=False  # In production, use proper certs
    )
    # Test connection
    info = await es_client.info()
    print(f"✅ Elasticsearch initialized: {info['version']['number']}")


async def close_elasticsearch():
    """Close Elasticsearch connection"""
    global es_client
    if es_client:
        await es_client.close()
    print("✅ Elasticsearch connection closed")


def get_elasticsearch():
    """Get Elasticsearch client"""
    return es_client
