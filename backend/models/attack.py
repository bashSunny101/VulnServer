"""
Attack Models - Pydantic schemas for API
"""
from pydantic import BaseModel, Field, IPvAnyAddress
from typing import List, Optional
from datetime import datetime


class AttackBase(BaseModel):
    """Base attack information"""
    src_ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    attack_type: str
    threat_score: int = Field(ge=0, le=100)


class AttackSession(AttackBase):
    """Complete attack session"""
    id: int
    honeypot_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    commands_executed: int = 0
    malware_downloaded: int = 0
    mitre_techniques: List[str] = []
    
    class Config:
        from_attributes = True


class AttackCommand(BaseModel):
    """Individual command executed"""
    id: int
    session_id: int
    command: str
    timestamp: datetime
    mitre_technique: Optional[str] = None
    
    class Config:
        from_attributes = True


class AttackDetail(BaseModel):
    """Detailed attack information"""
    attacker_ip: str
    total_attacks: int
    first_seen: datetime
    last_seen: datetime
    attack_types: List[str]
    malware_downloaded: int
    threat_score: int
    mitre_techniques: List[str]
    countries: List[str]
    timeline: List[dict]


class DashboardStats(BaseModel):
    """Dashboard statistics"""
    total_attacks_24h: int
    unique_ips_24h: int
    critical_threats: int
    high_threats: int
    top_countries: List[dict]
    top_attack_types: List[dict]
    malware_samples: int
    avg_threat_score: float


class AttackSearch(BaseModel):
    """Search parameters"""
    country: Optional[str] = None
    min_threat_score: Optional[int] = Field(None, ge=0, le=100)
    max_threat_score: Optional[int] = Field(None, ge=0, le=100)
    attack_type: Optional[str] = None
    time_range: str = "24h"  # 1h, 24h, 7d, 30d
    limit: int = Field(100, ge=1, le=1000)
