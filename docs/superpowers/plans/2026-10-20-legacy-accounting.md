# Existing gateway accounting implementation plan

Execute directly in the existing isolated feature worktree. Spec: ../specs/2026-10-20-legacy-accounting-design.md. User explicitly authorized execution and chose unlimited recording; no repeat approval is needed. One focused independent review may be used for a concrete unresolved migration risk; no recursive delegation.

- [x] RED/GREEN `core/monthly_usage.py`: additive unlimited-period and preserved-existing-route flags, old schema compatibility, strict quota transition, no hidden expiry or reset.
- [x] RED/GREEN `apps/api/monthly_api.py`: narrow owner-enrolled existing-traffic entitlement without unpaid new-work or disabled-workspace bypass. Existing callback/client protocol remains unchanged.
- [x] RED/GREEN `orchestrator/mesh_gateway.py` warm startup and a focused `orchestrator/accounting_migration.py` gateway-only guard/cutover helper with root-only CLI. Refuse configuration drift, non-idle or unowned resources; retain rollback/counters.
- [x] Update existing FA/EN administrator/customer views for unlimited accounting and first quota assignment; browser-check readouts and policy edits with an isolated fixture.
- [x] Appropriate regressions, exact-tree/expected-head publication and successful CI. Fresh both-host baseline/admission freeze/backups, own API upgrades, isolated two-node migration/traffic/cap/restart and physical metadata-loss recovery QA; forced rollback remains fault-injection unit coverage, not a physical claim.
- [x] Migrate the two original gateways sequentially after fresh idle proof, measure real stable-entry interruption, prove unchanged transport workers/settings and all ten member receipts plus shared usage.
- [x] Dedicated static site rollout, fresh encrypted resident backups per original host, bilingual actual reports/AGENTS/installer, final PR2/tree/CI proof. Main stays unmerged; no payment/account changes.
