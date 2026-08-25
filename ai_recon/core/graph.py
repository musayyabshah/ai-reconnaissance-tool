from __future__ import annotations

from pydantic import BaseModel, Field

from ai_recon.models.entities import ScanReport


class GraphNode(BaseModel):
    node_id: str
    node_type: str
    label: str
    properties: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    relationship: str
    target: str
    evidence: list[str] = Field(default_factory=list)


class AssetGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    def to_cytoscape(self) -> dict[str, list[dict]]:
        return {
            "nodes": [
                {
                    "data": {
                        "id": node.node_id,
                        "label": node.label,
                        "type": node.node_type,
                        **node.properties,
                    }
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "data": {
                        "source": edge.source,
                        "target": edge.target,
                        "relationship": edge.relationship,
                    }
                }
                for edge in self.edges
            ],
        }


def build_asset_graph(report: ScanReport) -> AssetGraph:
    graph = AssetGraph()
    seen_nodes: set[str] = set()

    def node(
        node_id: str, node_type: str, label: str, **properties: str | int | float | bool | None
    ) -> None:
        if node_id not in seen_nodes:
            graph.nodes.append(
                GraphNode(node_id=node_id, node_type=node_type, label=label, properties=properties)
            )
            seen_nodes.add(node_id)

    def edge(source: str, relationship: str, target: str, *evidence: str) -> None:
        graph.edges.append(
            GraphEdge(
                source=source, relationship=relationship, target=target, evidence=list(evidence)
            )
        )

    root_id = f"domain:{report.target.value}"
    node(root_id, "domain", report.target.value, scope=report.target.scope_status.value)
    for asset in report.assets:
        asset_id = f"asset:{asset.name}"
        node(
            asset_id,
            asset.kind,
            asset.name,
            scope=asset.scope_status.value,
            criticality=asset.criticality,
            environment=asset.environment,
            owner=asset.owner,
        )
        edge(root_id, "DISCOVERS", asset_id)
        for ip in asset.ips:
            ip_id = f"ip:{ip}"
            node(ip_id, "ip", ip)
            edge(asset_id, "RESOLVES_TO", ip_id)
        for service in asset.services:
            service_id = f"service:{asset.name}:{service.port}:{service.protocol}"
            node(
                service_id,
                "service",
                f"{service.protocol}/{service.port}",
                service=service.service,
                state=service.state,
            )
            edge(asset_id, "EXPOSES", service_id)
        for technology in asset.technologies:
            tech_id = f"technology:{technology.name}"
            node(tech_id, "technology", technology.name, confidence=technology.confidence)
            edge(asset_id, "USES", tech_id, *technology.evidence)
    return graph
