# Production Configuration Checklist

## ⚠️ CRITICAL: Before Deploying to Production

### WordPress Configuration (`wp-config.php`)

Ensure these settings are correct in production:

```php
// Debug mode MUST be disabled in production
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);

// SECURITY: Development bypass MUST be disabled or removed
// Option 1: Remove the line entirely
// Option 2: Set to false
define('CA_DEV_BYPASS', false);

// OR make it conditional (recommended):
define('CA_DEV_BYPASS', defined('WP_DEBUG') && WP_DEBUG);
```

### Plugin Secrets (`config/secrets.php`)

Required secrets that must be configured:
- ✅ `ghl_token` - GoHighLevel API token
- ✅ `ghl_location_id` - GoHighLevel location ID
- ✅ `upload_shared_secret` - HMAC secret for file uploads

**The plugin will fail to start if these are missing.**

### CORS Configuration

- ✅ Localhost origins are automatically removed in production (when `WP_DEBUG = false`)
- ✅ Only production URLs should be in `api_allowed_origins` and `upload_allowed_origins`
- ✅ To allow localhost in production (not recommended), set `CA_ALLOW_LOCALHOST_CORS=true` env var

### Verification

After deployment, verify:
1. Plugin loads without errors
2. API endpoints respond (check `/wp-json/ca/v1/health`)
3. CORS works from production frontend
4. No localhost in CORS allowed origins
5. Error messages are generic (not detailed)

---

**Last Updated:** 2025-01-XX
**Version:** 2.0.0

