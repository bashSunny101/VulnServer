"""
========================================
Configuration Management
========================================
LEARNING: Centralized configuration using Pydantic Settings
Loads from environment variables with validation
"""

from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """
    Application settings
    LEARNING: Pydantic validates types and provides defaults
    """
    
    # General
    project_name: str = "HoneyNet Intelligence Platform"
    environment: str = "development"
    log_level: str = "INFO"
    backend_port: int = 8000
    
    # Security
    api_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440
    
    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost"]
    
    # PostgreSQL
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "honeynet"
    postgres_password: str
    postgres_db: str = "honeynet_db"
    
    # MongoDB
    mongo_host: str = "mongodb"
    mongo_port: int = 27017
    mongo_user: str = "admin"
    mongo_password: str
    mongo_db: str = "honeynet_logs"
    
    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password: str
    
    # Elasticsearch
    elastic_host: str = "elasticsearch"
    elastic_port: int = 9200
    elastic_password: str
    
    # Threat Intelligence APIs
    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    geoip_db_path: str = "/app/data/geoip/GeoLite2-City.mmdb"
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    
    @property
    def postgres_url(self) -> str:
        """PostgreSQL connection URL"""
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
    
    @property
    def mongo_url(self) -> str:
        """MongoDB connection URL"""
        return f"mongodb://{self.mongo_user}:{self.mongo_password}@{self.mongo_host}:{self.mongo_port}"
    
    @property
    def redis_url(self) -> str:
        """Redis connection URL"""
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}"
    
    @property
    def elasticsearch_url(self) -> str:
        """Elasticsearch connection URL"""
        return f"http://{self.elastic_host}:{self.elastic_port}"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Instantiate settings
settings = Settings()
