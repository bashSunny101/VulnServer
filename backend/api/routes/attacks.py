"""
Attacks API Routes
Query and search attack data
"""
from fastapi import APIRouter, HTTPException, Query, Body
from typing import List, Optional
from datetime import datetime, timedelta

from models.attack import AttackDetail, AttackSearch, AttackSession
from database.elasticsearch_client import get_es_client
from services.correlation_engine import correlate_by_ip
from services.threat_scoring import calculate_threat_score

router = APIRouter(prefix="/attacks", tags=["Attacks"])


@router.get("/recent")
async def get_recent_attacks(
    limit: int = Query(50, ge=1, le=500, description="Number of attacks to return"),
    min_threat_score: int = Query(0, ge=0, le=100, description="Minimum threat score")
):
    """Get recent attacks sorted by time"""
    try:
        es = get_es_client()
        
        query = {
            "query": {
                "range": {"threat_score": {"gte": min_threat_score}}
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": limit
        }
        
        result = await es.search(index="cowrie-*,dionaea-*,snort-*", body=query)
        
        attacks = []
        for hit in result["hits"]["hits"]:
            source = hit["_source"]
            attacks.append({
                "id": hit["_id"],
                "timestamp": source.get("@timestamp"),
                "src_ip": source.get("src_ip"),
                "country": source.get("geoip", {}).get("geo", {}).get("country_name"),
                "city": source.get("geoip", {}).get("geo", {}).get("city_name"),
                "attack_type": source.get("eventid"),
                "threat_score": source.get("threat_score", 0),
                "honeypot": hit["_index"].split("-")[0]
            })
        
        return {"attacks": attacks, "total": len(attacks)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get attacks: {str(e)}")


@router.get("/{ip_address}")
async def get_attack_details(ip_address: str):
    """
    Get detailed attack information for specific IP
    Includes correlation across all honeypots
    """
    try:
        # Use correlation engine to get full attack profile
        details = await correlate_by_ip(ip_address)
        
        if not details or details.get("total_events", 0) == 0:
            raise HTTPException(status_code=404, detail=f"No attacks found for IP {ip_address}")
        
        return details
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get attack details: {str(e)}")


@router.post("/search")
async def search_attacks(search: AttackSearch = Body(...)):
    """
    Advanced attack search with filters
    
    Parameters:
    - country: Filter by country name
    - min_threat_score: Minimum threat score
    - max_threat_score: Maximum threat score
    - attack_type: Filter by attack type/eventid
    - time_range: 1h, 24h, 7d, 30d
    - limit: Max results
    """
    try:
        es = get_es_client()
        
        # Build time range
        time_ranges = {
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30)
        }
        time_ago = (datetime.utcnow() - time_ranges.get(search.time_range, timedelta(hours=24))).isoformat()
        
        # Build query filters
        must = [{"range": {"@timestamp": {"gte": time_ago}}}]
        
        if search.country:
            must.append({"match": {"geoip.geo.country_name": search.country}})
        
        if search.attack_type:
            must.append({"match": {"eventid": search.attack_type}})
        
        if search.min_threat_score is not None:
            must.append({"range": {"threat_score": {"gte": search.min_threat_score}}})
        
        if search.max_threat_score is not None:
            must.append({"range": {"threat_score": {"lte": search.max_threat_score}}})
        
        query = {
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": search.limit
        }
        
        result = await es.search(index="cowrie-*,dionaea-*,snort-*", body=query)
        
        attacks = []
        for hit in result["hits"]["hits"]:
            source = hit["_source"]
            attacks.append({
                "timestamp": source.get("@timestamp"),
                "src_ip": source.get("src_ip"),
                "country": source.get("geoip", {}).get("geo", {}).get("country_name"),
                "city": source.get("geoip", {}).get("geo", {}).get("city_name"),
                "attack_type": source.get("eventid"),
                "threat_score": source.get("threat_score", 0),
                "details": source.get("message", source.get("input"))
            })
        
        return {
            "attacks": attacks,
            "total": result["hits"]["total"]["value"],
            "returned": len(attacks)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/top/attackers")
async def get_top_attackers(
    limit: int = Query(10, ge=1, le=100),
    hours: int = Query(24, ge=1, le=168)
):
    """Get top attacking IPs"""
    try:
        es = get_es_client()
        
        time_ago = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        query = {
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_ago}}}
                    ],
                    "must_not": [
                        {"term": {"src_ip.keyword": "49.36.190.93"}}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "top_ips": {
                    "terms": {
                        "field": "src_ip.keyword",
                        "size": limit,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "avg_threat": {"avg": {"field": "threat_score"}},
                        "countries": {
                            "terms": {"field": "geoip.geo.country_name.keyword", "size": 1}
                        }
                    }
                }
            }
        }
        
        result = await es.search(index="cowrie-*,dionaea-*,snort-*", body=query)
        
        attackers = []
        for bucket in result["aggregations"]["top_ips"]["buckets"]:
            country = bucket["countries"]["buckets"][0]["key"] if bucket["countries"]["buckets"] else "Unknown"
            attackers.append({
                "ip": bucket["key"],
                "attack_count": bucket["doc_count"],
                "avg_threat_score": round(bucket["avg_threat"]["value"] or 0, 1),
                "country": country
            })
        
        return {"top_attackers": attackers}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get top attackers: {str(e)}")


@router.get("/mitre/techniques")
async def get_mitre_techniques(hours: int = Query(24, ge=1, le=168)):
    """Get MITRE ATT&CK techniques observed"""
    try:
        es = get_es_client()
        
        time_ago = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        query = {
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_ago}}},
                        {"exists": {"field": "mitre_technique"}}
                    ]
                }
            },
            "size": 0,
            "aggs": {
                "techniques": {
                    "terms": {
                        "field": "mitre_technique.keyword",
                        "size": 50
                    }
                }
            }
        }
        
        result = await es.search(index="cowrie-*,dionaea-*,snort-*", body=query)
        
        techniques = [
            {
                "technique_id": bucket["key"],
                "count": bucket["doc_count"]
            }
            for bucket in result["aggregations"]["techniques"]["buckets"]
        ]
        
        return {"mitre_techniques": techniques, "total": len(techniques)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get MITRE techniques: {str(e)}")
