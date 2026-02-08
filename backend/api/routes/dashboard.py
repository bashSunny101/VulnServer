"""
Dashboard API Routes
Provides statistics and overview data
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List
from datetime import datetime, timedelta

from models.attack import DashboardStats
from database.elasticsearch_client import get_es_client
from database.postgres import get_db

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Get dashboard statistics
    
    Returns:
        - Total attacks in last 24 hours
        - Unique attacker IPs
        - Critical/high threat counts
        - Top countries
        - Top attack types
        - Malware sample count
    """
    try:
        es = get_es_client()
        
        # Time range: last 24 hours
        time_24h_ago = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        
        # Query all honeypot indices
        query = {
            "query": {
                "range": {
                    "@timestamp": {"gte": time_24h_ago}
                }
            },
            "size": 0,
            "aggs": {
                "unique_ips": {
                    "cardinality": {"field": "src_ip.keyword"}
                },
                "critical_threats": {
                    "filter": {"range": {"threat_score": {"gte": 76}}}
                },
                "high_threats": {
                    "filter": {"range": {"threat_score": {"gte": 51, "lt": 76}}}
                },
                "by_country": {
                    "terms": {"field": "geoip.country_name.keyword", "size": 10}
                },
                "by_type": {
                    "terms": {"field": "eventid.keyword", "size": 10}
                },
                "avg_score": {
                    "avg": {"field": "threat_score"}
                }
            }
        }
        
        result = await es.search(index="cowrie-*,dionaea-*,snort-*", body=query)
        
        aggs = result["aggregations"]
        
        return DashboardStats(
            total_attacks_24h=result["hits"]["total"]["value"],
            unique_ips_24h=aggs["unique_ips"]["value"],
            critical_threats=aggs["critical_threats"]["doc_count"],
            high_threats=aggs["high_threats"]["doc_count"],
            top_countries=[
                {"country": b["key"], "count": b["doc_count"]}
                for b in aggs["by_country"]["buckets"][:5]
            ],
            top_attack_types=[
                {"type": b["key"], "count": b["doc_count"]}
                for b in aggs["by_type"]["buckets"][:5]
            ],
            malware_samples=0,  # TODO: Query from MongoDB
            avg_threat_score=round(aggs["avg_score"]["value"] or 0, 2)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")


@router.get("/timeline")
async def get_attack_timeline(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back")
):
    """Get attack timeline data for charts"""
    try:
        es = get_es_client()
        
        time_ago = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        
        query = {
            "query": {
                "range": {"@timestamp": {"gte": time_ago}}
            },
            "size": 0,
            "aggs": {
                "attacks_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0
                    },
                    "aggs": {
                        "avg_threat": {"avg": {"field": "threat_score"}}
                    }
                }
            }
        }
        
        result = await es.search(index="cowrie-*,dionaea-*,snort-*", body=query)
        
        timeline = [
            {
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"],
                "avg_threat_score": round(bucket["avg_threat"]["value"] or 0, 1)
            }
            for bucket in result["aggregations"]["attacks_over_time"]["buckets"]
        ]
        
        return {"timeline": timeline}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get timeline: {str(e)}")


@router.get("/geographic")
async def get_geographic_distribution():
    """Get attack distribution by geography for map visualization"""
    try:
        es = get_es_client()
        
        time_24h_ago = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        
        query = {
            "query": {
                "range": {"@timestamp": {"gte": time_24h_ago}}
            },
            "size": 0,
            "aggs": {
                "by_location": {
                    "terms": {
                        "field": "geoip.country_iso_code.keyword",
                        "size": 100
                    },
                    "aggs": {
                        "avg_threat": {"avg": {"field": "threat_score"}},
                        "location": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["geoip.country_name", "geoip.location"]
                            }
                        }
                    }
                }
            }
        }
        
        result = await es.search(index="cowrie-*,dionaea-*", body=query)
        
        locations = []
        for bucket in result["aggregations"]["by_location"]["buckets"]:
            hit = bucket["location"]["hits"]["hits"][0]["_source"]
            if "geoip" in hit and "geo" in hit["geoip"] and "location" in hit["geoip"]["geo"]:
                locations.append({
                    "country_code": bucket["key"],
                    "country": hit["geoip"]["geo"].get("country_name", "Unknown"),
                    "latitude": hit["geoip"]["geo"]["location"]["lat"],
                    "longitude": hit["geoip"]["geo"]["location"]["lon"],
                    "attack_count": bucket["doc_count"],
                    "avg_threat_score": round(bucket["avg_threat"]["value"] or 0, 1)
                })
        
        return {"locations": locations}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get geographic data: {str(e)}")
