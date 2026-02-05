"""
========================================
MongoDB Database Connection
========================================
LEARNING: MongoDB stores semi-structured data
- Raw honeypot logs
- Malware samples metadata
- Session recordings
- Full packet captures
"""

from motor.motor_asyncio import AsyncIOMotorClient
from config import settings

# Global MongoDB client
mongodb_client: AsyncIOMotorClient = None


async def init_mongodb():
    """Initialize MongoDB connection"""
    global mongodb_client
    mongodb_client = AsyncIOMotorClient(settings.mongo_url)
    # Test connection
    await mongodb_client.admin.command('ping')
    print("✅ MongoDB initialized")


async def close_mongodb():
    """Close MongoDB connection"""
    global mongodb_client
    if mongodb_client:
        mongodb_client.close()
    print("✅ MongoDB connection closed")


def get_mongodb():
    """Get MongoDB database instance"""
    return mongodb_client[settings.mongo_db]


# Collection helpers
def get_cowrie_collection():
    """Cowrie logs collection"""
    db = get_mongodb()
    return db.cowrie_logs


def get_dionaea_collection():
    """Dionaea logs collection"""
    db = get_mongodb()
    return db.dionaea_logs


def get_malware_collection():
    """Malware samples collection"""
    db = get_mongodb()
    return db.malware_samples
