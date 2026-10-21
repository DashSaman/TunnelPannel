"""Deterministic workload quotes and atomic, tenant-local daily reservations."""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from fastapi import HTTPException
from sqlalchemy import func

from core.models import Job, Node, NodeInventory
from orchestrator.benchmarking import PROFILES
from orchestrator.host_lease import HostLease
from orchestrator.mesh_campaign import directed_routes


def estimate_campaign(nodes, methods, profile, directions=None):
    try:
        all_routes = directed_routes(nodes)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None
    if profile not in PROFILES or not methods or len(set(methods)) != len(methods):
        raise HTTPException(400, 'select a known profile and unique methods')
    try:
        routes = all_routes if directions is None else [(r['source'], r['destination']) for r in directions]
    except (KeyError, TypeError):
        raise HTTPException(400, 'each direction requires source and destination') from None
    if not routes or len(set(routes)) != len(routes) or not set(routes) <= set(all_routes):
        raise HTTPException(400, 'select unique directed routes between selected nodes')
    config = PROFILES[profile]
    units = len(routes) * len(methods)
    return {'candidate_units': units, 'route_count': len(routes), 'method_count': len(methods),
            'directions': [{'source': a, 'destination': b} for a, b in routes],
            'candidate_timeout_ceiling_s': units * config.overall_timeout_s,
            'profile_config': {'throughput_seconds': config.throughput_seconds},
            'traffic_bytes_estimate': None, 'preparation_included': False,
            'duration_note': 'Serial candidate timeout ceiling, not an ETA; dependency builds and queue wait excluded.',
            'budget_note': 'Reserved candidate units are workload, not money; cancellation does not refund today.'}


def daily_budget(session, limits):
    day = dt.datetime.now(dt.timezone.utc).date().isoformat()
    used = session.query(func.coalesce(func.sum(Job.payload['candidate_units'].as_integer()), 0)).filter(
        Job.payload['budget_day'].as_string() == day).scalar()
    limit = limits.get('max_daily_candidate_units', 25000)
    return {'day': day, 'used': int(used), 'limit': limit, 'remaining': max(0, limit-int(used))}


def reserve_fields(session, units, limits):
    budget = daily_budget(session, limits)
    if units > budget['remaining']:
        raise HTTPException(429, 'daily candidate budget exceeded; reduce methods/directions or wait for UTC reset')
    return {'candidate_units': units, 'budget_day': budget['day']}


def campaign_quote(session, request, limits):
    from core.catalog import CATALOG
    methods = request.methods if request.methods is not None else list(CATALOG.identities)
    if not methods or len(set(methods)) != len(methods) or not set(methods) <= set(CATALOG.identities):
        raise HTTPException(400, 'select unique known methods')
    if (len(request.nodes) > limits['max_nodes'] or len(methods) > limits['max_campaign_methods']
            or request.recommend_count > limits['max_tunnels_per_route']):
        raise HTTPException(400, 'workspace node, method or tunnel limit exceeded')
    quote = estimate_campaign(request.nodes, methods, request.profile, getattr(request, 'directions', None))
    snapshots, identities, hosts = [], [], []
    for identity in request.nodes:
        node = session.get(Node, identity)
        if node is None:
            raise HTTPException(400, 'all nodes must belong to this workspace')
        inventory = session.query(NodeInventory).filter_by(node_id=node.id).order_by(
            NodeInventory.collected_at.desc(), NodeInventory.id.desc()).first()
        if inventory is None:
            raise HTTPException(400, 'discover every selected node before starting')
        key = HostLease({'host': node.host, 'host_key_fingerprint': node.host_key_fingerprint}).key
        identities.append(key)
        hosts.append(node.host)
        snapshots.append([node.id, node.host, key, inventory.id])
    if len(set(identities)) != len(identities) or len(set(hosts)) != len(hosts):
        raise HTTPException(400, 'register distinct physical hosts, not duplicate aliases')
    quote['budget'] = daily_budget(session, limits)
    quote['within_budget'] = quote['candidate_units'] <= quote['budget']['remaining']
    material = {'quote': quote, 'nodes': snapshots, 'methods': methods, 'profile': request.profile,
                'objective': getattr(request, 'objective', 'balanced'),
                'encrypted_only': getattr(request, 'recommend_encrypted_only', False),
                'purpose': request.purpose, 'recommend_count': request.recommend_count, 'limits': limits}
    quote['fingerprint'] = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
    return quote, methods
