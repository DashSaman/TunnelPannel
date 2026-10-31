# Tehran Network: owner accounts, plans and manual payments

The account portal is https://tehnet.ir/tunnels/. Use your assigned **username
or email and password**. A system owner automatically sees **Users & sales
administration**; customers see only their own workspace. An API key is not
needed for everyday account sign-in. Two-factor codes remain required when
enabled. Passwords are hashed; they are not stored in source or published here.

The owner console has four sections:

- **Users:** create a customer with its own isolated workspace, or explicitly
  select a system administrator for installation setup. Search and edit names,
  usernames, email, role, enabled state and optional new password. Saving account
  edits revokes that account's sessions. The last active owner is protected.
- **Access & quotas:** edit a customer workspace's name, enabled state, maximum
  servers, members per route, methods per test, simultaneous tests, active
  routes and daily candidate units. Effective limits are the lower of these
  customer caps and the purchased plan. Accounts sharing a workspace share its
  quotas; the default customer-creation flow creates an independent workspace.
- **Plans & prices:** create/edit a plan ID, title, integer price, IRT (toman)
  or IRR (rial), duration in days, quotas and availability. A plan needs an
  explicit positive price before manual payment activation. No selling price
  is invented by the installer. Existing purchases retain their plan limits
  until renewal; an explicit customer quota change takes effect immediately.
- **Manual payments:** after checking funds **outside this application**, pick
  the customer/plan and enter the matching amount/currency and receipt reference.
  Confirm receipt and save. This records the owner's confirmation and activates
  access in one transaction; it does not transfer money or contact a gateway.
  Identical retries cannot extend twice and reference reuse is rejected.
  Renewals extend remaining paid time. Keep the receipt history for accounting.

Production installations default to `TP_BILLING_MODE=manual`. Without paid
activation, a customer can sign in/read/export/request access but cannot start
new tests or deployments. Old sandbox credit does not become paid access when
switching to manual mode. Expiry blocks new work; existing tunnel workers are
preserved unless an explicit owned stop policy is configured. A system owner
can administer/validate the service without buying its own customer plan.
The standalone historical sandbox and signed bridge remain available only
when separately configured. Public signup and online checkout remain disabled.

The website host serves static UI and proxies authenticated requests. The
controller stores account/plan/payment state; selected customer nodes perform
builds, tests and tunnel execution. Never place the API/database/queue on the
website host to simplify deployment.

Root on a customer node can inspect files, binaries and process memory; this
application cannot promise copy prevention or zero footprint against root.
The central commercial/account logic is not copied to those nodes. New owned
generated service units use private umask and discard process stdout/stderr;
required binaries/configuration remain for operation. Owned temporary test
resources are cleaned. Existing journals/unrelated services are not purged.
Central access and payment/audit records are retained for correct accounting.

See [upstream source review](UPSTREAM-REVIEW-20261019.md),
[website container deployment](TEHNET-CONTAINER.md) and the installed evidence
linked from the main README. A new UI or unit test alone is not proof of a
completed live upgrade.
