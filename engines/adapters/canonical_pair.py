"""SDK bridge to the owned canonical pair lifecycle, never a second installer."""
from engines.adapters import EngineAdapter, PlanAction, ProbeResult, register_adapter


class CanonicalPairAdapter(EngineAdapter):
    method = ''

    def _pair(self):
        from orchestrator.pair_runtime import RealPairAdapter
        pair = self.params.get('pair_adapter')
        if not isinstance(pair, RealPairAdapter) or pair.candidate.legacy_method_id != self.method:
            raise RuntimeError('use a matching canonical prepared pair adapter with ownership and pinned node access')
        return pair

    def detect(self):
        return not self.precheck()

    def inventory(self):
        pair = self._pair()
        return {'method': self.method, 'configured': bool(pair.artifact), 'scope': 'canonical owned pair'}

    def precheck(self):
        try:
            self._pair()
            return []
        except RuntimeError as error:
            return [str(error)]

    def plan(self):
        return [PlanAction('ALLOCATE', self.method, 'Fresh host inventories, leases, ports and journal before deployment'),
                PlanAction('CONFIGURE', self.method, 'Canonical real-pair body; no global/default route changes')]

    def install(self):
        self._pair()  # Installation occurs inside configure's owned preparation.

    def configure(self):
        self._pair().configure()

    def start(self):
        if not self._pair().artifact:
            raise RuntimeError('configure the canonical pair before start')

    def probe(self):
        if self.precheck() or not self._pair().artifact:
            return ProbeResult(False, 'canonical owned pair has not been configured')
        return self._pair().probe()

    def metrics(self):
        return self._pair().metrics()

    def stop(self):
        self._pair().rollback()

    def remove(self):
        self._pair().rollback()

    def rollback(self):
        self._pair().rollback()


@register_adapter
class BackhaulAdapter(CanonicalPairAdapter):
    engine_id, profile_id, method = 'backhaul', 'tcp', 'BACKHAUL_TCP'


@register_adapter
class AmneziaWGAdapter(CanonicalPairAdapter):
    engine_id, profile_id, method = 'amneziawg', 'default', 'AMNEZIAWG'


@register_adapter
class Native4in6Adapter(CanonicalPairAdapter):
    engine_id, profile_id, method = 'ip4in6', 'native', 'IP4IN6'
