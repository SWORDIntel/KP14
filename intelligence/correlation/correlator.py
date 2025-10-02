"""
Correlation Engine

Links related samples and campaigns:
- Sample similarity analysis
- Infrastructure correlation
- TTP clustering
- Timeline reconstruction
- Campaign tracking
"""

from typing import Dict, List, Any, Tuple
from datetime import datetime
import hashlib


class CorrelationEngine:
    """
    Correlate samples, infrastructure, and campaigns.

    Features:
    - Sample similarity scoring
    - C2 infrastructure clustering
    - TTP-based correlation
    - Timeline analysis
    """

    def __init__(self):
        """Initialize correlation engine."""
        self.sample_database = {}
        self.infrastructure_graph = {}
        self.campaigns = {}

    def add_sample(self, sample_id: str, intelligence_data: Dict[str, Any]):
        """Add sample to correlation database."""
        self.sample_database[sample_id] = {
            'data': intelligence_data,
            'timestamp': datetime.utcnow().isoformat(),
            'correlations': []
        }

        # Update infrastructure graph
        self._update_infrastructure(sample_id, intelligence_data)

    def correlate_sample(self, sample_id: str) -> Dict[str, Any]:
        """Find correlations for a sample."""
        if sample_id not in self.sample_database:
            return {'error': 'Sample not found'}

        sample_data = self.sample_database[sample_id]['data']
        correlations = {
            'similar_samples': self._find_similar_samples(sample_id, sample_data),
            'shared_infrastructure': self._find_shared_infrastructure(sample_id, sample_data),
            'related_campaigns': self._find_related_campaigns(sample_id, sample_data),
            'ttp_clusters': self._find_ttp_clusters(sample_id, sample_data)
        }

        return correlations

    def _find_similar_samples(self, sample_id: str, sample_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar samples based on multiple factors."""
        similar = []

        for other_id, other_sample in self.sample_database.items():
            if other_id == sample_id:
                continue

            similarity = self._calculate_similarity(sample_data, other_sample['data'])
            if similarity >= 70:  # 70% similarity threshold
                similar.append({
                    'sample_id': other_id,
                    'similarity_score': similarity,
                    'timestamp': other_sample['timestamp']
                })

        return sorted(similar, key=lambda x: x['similarity_score'], reverse=True)[:10]

    def _calculate_similarity(self, sample1: Dict, sample2: Dict) -> int:
        """Calculate similarity score between samples."""
        score = 0
        factors = 0

        # Family match
        if sample1.get('threat_assessment', {}).get('family') == sample2.get('threat_assessment', {}).get('family'):
            score += 30
        factors += 1

        # C2 infrastructure overlap
        c2_1 = set(ep.get('value', '') for ep in sample1.get('c2_endpoints', []) if isinstance(ep, dict))
        c2_2 = set(ep.get('value', '') for ep in sample2.get('c2_endpoints', []) if isinstance(ep, dict))
        if c2_1 and c2_2:
            overlap = len(c2_1 & c2_2) / max(len(c2_1), len(c2_2))
            score += int(overlap * 30)
        factors += 1

        # MITRE technique overlap
        tech_1 = set(t.get('technique_id', '') for t in sample1.get('threat_assessment', {}).get('mitre_techniques', []))
        tech_2 = set(t.get('technique_id', '') for t in sample2.get('threat_assessment', {}).get('mitre_techniques', []))
        if tech_1 and tech_2:
            overlap = len(tech_1 & tech_2) / max(len(tech_1), len(tech_2))
            score += int(overlap * 25)
        factors += 1

        # Capability overlap
        cap_1 = set(c.get('capability', '') for c in sample1.get('threat_assessment', {}).get('capabilities', []))
        cap_2 = set(c.get('capability', '') for c in sample2.get('threat_assessment', {}).get('capabilities', []))
        if cap_1 and cap_2:
            overlap = len(cap_1 & cap_2) / max(len(cap_1), len(cap_2))
            score += int(overlap * 15)
        factors += 1

        return min(100, score)

    def _find_shared_infrastructure(self, sample_id: str, sample_data: Dict) -> List[Dict[str, Any]]:
        """Find samples sharing C2 infrastructure."""
        shared = []
        sample_c2 = set(ep.get('value', '') for ep in sample_data.get('c2_endpoints', []) if isinstance(ep, dict))

        for other_id, other_sample in self.sample_database.items():
            if other_id == sample_id:
                continue

            other_c2 = set(ep.get('value', '') for ep in other_sample['data'].get('c2_endpoints', []) if isinstance(ep, dict))
            common_c2 = sample_c2 & other_c2

            if common_c2:
                shared.append({
                    'sample_id': other_id,
                    'shared_endpoints': list(common_c2),
                    'count': len(common_c2)
                })

        return sorted(shared, key=lambda x: x['count'], reverse=True)[:10]

    def _find_related_campaigns(self, sample_id: str, sample_data: Dict) -> List[Dict[str, Any]]:
        """Find related campaigns."""
        related = []
        family = sample_data.get('threat_assessment', {}).get('family', 'unknown')
        apt_group = sample_data.get('threat_assessment', {}).get('attribution', {}).get('apt_group', 'unknown')

        for campaign_id, campaign_data in self.campaigns.items():
            if campaign_data.get('family') == family or campaign_data.get('apt_group') == apt_group:
                related.append({
                    'campaign_id': campaign_id,
                    'name': campaign_data.get('name', ''),
                    'confidence': campaign_data.get('confidence', 0)
                })

        return related

    def _find_ttp_clusters(self, sample_id: str, sample_data: Dict) -> List[Dict[str, Any]]:
        """Find TTP-based clusters."""
        clusters = []
        sample_ttps = set(t.get('technique_id', '') for t in sample_data.get('threat_assessment', {}).get('mitre_techniques', []))

        if not sample_ttps:
            return clusters

        # Group samples by TTP overlap
        ttp_groups = {}
        for other_id, other_sample in self.sample_database.items():
            if other_id == sample_id:
                continue

            other_ttps = set(t.get('technique_id', '') for t in other_sample['data'].get('threat_assessment', {}).get('mitre_techniques', []))
            common_ttps = sample_ttps & other_ttps

            if len(common_ttps) >= 2:  # At least 2 common techniques
                cluster_key = frozenset(common_ttps)
                if cluster_key not in ttp_groups:
                    ttp_groups[cluster_key] = []
                ttp_groups[cluster_key].append(other_id)

        # Convert to list format
        for ttps, samples in ttp_groups.items():
            clusters.append({
                'techniques': list(ttps),
                'sample_count': len(samples),
                'samples': samples[:5]  # Limit to 5 samples
            })

        return sorted(clusters, key=lambda x: x['sample_count'], reverse=True)[:5]

    def _update_infrastructure(self, sample_id: str, intelligence_data: Dict):
        """Update infrastructure correlation graph."""
        c2_endpoints = intelligence_data.get('c2_endpoints', [])

        for endpoint in c2_endpoints:
            if not isinstance(endpoint, dict):
                continue

            value = endpoint.get('value', '')
            if not value:
                continue

            if value not in self.infrastructure_graph:
                self.infrastructure_graph[value] = {
                    'type': endpoint.get('endpoint_type', 'unknown'),
                    'samples': [],
                    'first_seen': datetime.utcnow().isoformat(),
                    'last_seen': datetime.utcnow().isoformat()
                }

            self.infrastructure_graph[value]['samples'].append(sample_id)
            self.infrastructure_graph[value]['last_seen'] = datetime.utcnow().isoformat()

    def create_campaign(self, campaign_name: str, sample_ids: List[str]) -> str:
        """Create a new campaign from sample IDs."""
        campaign_id = hashlib.md5(campaign_name.encode()).hexdigest()[:16]

        # Aggregate data from samples
        families = set()
        apt_groups = set()
        techniques = set()

        for sample_id in sample_ids:
            if sample_id in self.sample_database:
                data = self.sample_database[sample_id]['data']
                threat = data.get('threat_assessment', {})

                families.add(threat.get('family', 'unknown'))
                apt_groups.add(threat.get('attribution', {}).get('apt_group', 'unknown'))

                for tech in threat.get('mitre_techniques', []):
                    if isinstance(tech, dict):
                        techniques.add(tech.get('technique_id', ''))

        self.campaigns[campaign_id] = {
            'name': campaign_name,
            'samples': sample_ids,
            'families': list(families),
            'apt_groups': list(apt_groups),
            'techniques': list(techniques),
            'created': datetime.utcnow().isoformat(),
            'confidence': 75  # Base confidence
        }

        return campaign_id

    def get_infrastructure_timeline(self) -> List[Dict[str, Any]]:
        """Get timeline of infrastructure usage."""
        timeline = []

        for endpoint, data in self.infrastructure_graph.items():
            timeline.append({
                'endpoint': endpoint,
                'type': data['type'],
                'sample_count': len(data['samples']),
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen']
            })

        return sorted(timeline, key=lambda x: x['first_seen'], reverse=True)

    def export_correlation_data(self) -> Dict[str, Any]:
        """Export all correlation data."""
        return {
            'sample_count': len(self.sample_database),
            'infrastructure_nodes': len(self.infrastructure_graph),
            'campaign_count': len(self.campaigns),
            'infrastructure_timeline': self.get_infrastructure_timeline(),
            'campaigns': self.campaigns
        }
