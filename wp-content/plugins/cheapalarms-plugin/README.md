# CheapAlarms Platform Bridge (v2)

Modernised WordPress plugin that exposes the CheapAlarms backend integration (GHL bridge, secure uploads, client portal) using production-grade architecture.

## Requirements

- WordPress 6.0+
- PHP 8.0+
- Constants defined in `wp-config.php`:
  ```php
  define('CA_GHL_TOKEN', 'your-ghl-token');
  define('CA_LOCATION_ID', 'ghl-location-id');
  define('CA_SERVICEM8_API_KEY', 'your-servicem8-api-key'); // Optional: ServiceM8 integration
  define('CA_UPLOAD_SHARED_SECRET', 'strong-shared-secret');
  define('CA_UPLOAD_MAX_MB', 12); // optional, defaults to 10MB
  define('CA_UPLOAD_ALLOWED_ORIGINS', 'https://cheapalarms.com.au,https://app.cheapalarms.com.au');
  ```

## Installation

1. Copy this plugin folder into `wp-content/plugins/cheapalarms-plugin`.
2. Confirm `cheapalarms-plugin.php` is present at the root and activate the plugin in wp-admin.
3. Build and deploy the React app (in `cheapalarm/react-app`) so the admin dashboard can load from the manifest.

## REST API Overview

| Endpoint | Purpose | Auth |
| --- | --- | --- |
| `GET /wp-json/ca/v1/diag` | Validate GHL credentials | public |
| `GET /wp-json/ca/v1/estimate` | Fetch estimate by ID/email | public |
| `GET /wp-json/ca/v1/estimate/list` | List estimates (debug) | public |
| `GET /wp-json/ca/v1/estimate/search` | Search latest estimate by email | public |
| `POST /wp-json/ca/v1/estimate/create` | Create estimate then append upload link | public |
| `PUT /wp-json/ca/v1/estimate/update` | Update estimate (ensures upload link) | public |
| `POST /wp-json/ca/v1/estimate/photos` | Store photo mapping metadata | public |
| `POST /wp-json/ca/v1/estimate/apply-photos` | Apply stored photos into estimate items | public |
| `POST /wp-json/ca/v1/estimate/annotate` | Append upload link to terms | public |
| `POST /wp-json/ca/v1/upload/start` | Issue upload token (HMAC protected) | public |
| `POST /wp-json/ca/v1/upload` | Handle photo uploads | public |
| `GET /wp-json/ca/v1/portal/status` | Client portal snapshot | public |
| `POST /wp-json/ca/v1/portal/accept` | Mark estimate accepted | public |
| `POST /wp-json/ca/v1/portal/create-account` | Provision customer account | public |
| `POST /wp-json/ca/v1/portal/resend-invite` | Resend portal invite (admin only) | requires `manage_options` |
| `GET /wp-json/ca/v1/servicem8/test` | Test ServiceM8 API connection | requires `ca_view_estimates` |
| `GET /wp-json/ca/v1/servicem8/companies` | List companies (clients) | requires `ca_view_estimates` |
| `POST /wp-json/ca/v1/servicem8/companies` | Create a company | requires `ca_manage_portal` |
| `GET /wp-json/ca/v1/servicem8/jobs` | List jobs | requires `ca_view_estimates` |
| `POST /wp-json/ca/v1/servicem8/jobs` | Create a job | requires `ca_manage_portal` |
| `GET /wp-json/ca/v1/servicem8/jobs/{uuid}` | Get a specific job | requires `ca_view_estimates` |
| `DELETE /wp-json/ca/v1/servicem8/jobs/{uuid}` | Delete a job | requires `ca_manage_portal` |
| `GET /wp-json/ca/v1/ghl/contacts` | Check GHL contacts config | requires `ca_view_estimates` |
| `POST /wp-json/ca/v1/ghl/contacts` | Create/update GHL contact | requires `ca_manage_portal` |
| `POST /wp-json/ca/v1/ghl/messages` | Send GHL message | requires `ca_manage_portal` |

> Each public endpoint still validates plugin configuration and rate-limits uploads. Add additional nonce/cookie validation when embedding in templates.

## Admin Dashboard Loader

The plugin embeds the React admin SPA at `/wp-admin/admin.php?page=cheapalarms-estimates`.  
The view expects the compiled Vite manifest under your theme at `react-app/.vite/manifest.json`.

## Portal Metadata Storage

Portal state is stored in WordPress options using the key `ca_portal_meta_{estimateId}`.  
Each option contains:

```json
{
  "quote": {"status": "...", "statusLabel": "...", "acceptedAt": "...", "canAccept": true},
  "photos": {"total": 3, "required": 6, "missingCount": 3, "items": []},
  "installation": {"status": "pending", "statusLabel": "Not scheduled", "message": null, "canSchedule": false},
  "documents": [],
  "account": {"status": "pending", "statusLabel": "Invite pending", "lastInviteAt": null, "canResend": true}
}
```

## Migration Notes (from legacy plugin)

- `cheapalarms-ghl-bridge.php.php` replaced with structured classes and autoloader.
- All REST logic moved into controllers under `includes/REST/Controllers`.
- Upload and estimate helpers now live in services; global functions removed.
- Portal endpoints centralised in `PortalService` and persist metadata via options.
- Admin loader moved to `includes/Admin/Menu.php` using `views/admin-dashboard.php`.

## Development

```bash
# lint PHP via phpcs if available
vendor/bin/phpcs --standard=WordPress
```

The plugin does not ship Composer dependencies, but the autoloader is PSR-4 compatible if you want to add one later.

