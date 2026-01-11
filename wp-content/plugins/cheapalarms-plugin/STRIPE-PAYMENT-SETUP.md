# Stripe Payment Implementation - Setup Guide

This guide covers the setup and deployment of the Stripe payment integration.

## Prerequisites

1. **Composer** - PHP dependency manager
   - Download: https://getcomposer.org/download/
   - Or install via: `php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"`
   - Verify: `composer --version`

2. **Stripe Account** - Active Stripe account with API keys

## Installation Steps

### 1. Install Stripe PHP Library

Navigate to the plugin directory and install dependencies:

```bash
cd wordpress/wp-content/plugins/cheapalarms-plugin
composer install --no-dev --optimize-autoloader
```

This will:
- Install `stripe/stripe-php` library
- Create `vendor/` directory with autoloader
- The plugin bootstrap already includes Composer autoloader support

### 2. Configure Stripe API Keys

Add to your environment variables or `config/secrets.php`:

```php
// In config/secrets.php or environment variables
'stripe_secret_key' => 'sk_live_...', // or sk_test_... for testing
'stripe_publishable_key' => 'pk_live_...', // or pk_test_... for testing
'stripe_webhook_secret' => 'whsec_...', // From Stripe dashboard
```

Or set environment variables:
- `CA_STRIPE_SECRET_KEY`
- `CA_STRIPE_PUBLISHABLE_KEY`
- `CA_STRIPE_WEBHOOK_SECRET`

### 3. Configure Stripe Webhook Endpoint

1. Go to Stripe Dashboard → Developers → Webhooks
2. Click "Add endpoint"
3. Endpoint URL: `https://yourdomain.com/wp-json/ca/v1/stripe/webhook`
4. Select events to listen to:
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
   - `charge.refunded`
5. Copy the "Signing secret" (starts with `whsec_`)
6. Add to `CA_STRIPE_WEBHOOK_SECRET` environment variable

### 4. Database Migration

The webhook events table will be created automatically on plugin activation or when the schema version changes.

To manually trigger migration:
- Deactivate and reactivate the plugin, OR
- The migration runs automatically when `ca_db_schema_version` option doesn't match current version

Verify table creation:
```sql
SHOW TABLES LIKE 'wp_ca_webhook_events';
```

### 5. Verify Installation

Check that Stripe library is loaded:
```php
// Should return true
class_exists('\Stripe\Webhook')
```

## Testing

### Test Payment Intent Creation

1. Create an invoice for an estimate
2. Configure deposit (optional) via: `POST /ca/v1/admin/invoices/{invoiceId}/configure-deposit`
3. Create payment intent via: `POST /ca/v1/stripe/create-payment-intent`
4. Verify payment intent is created in Stripe dashboard

### Test Webhook Processing

1. Use Stripe CLI for local testing:
   ```bash
   stripe listen --forward-to http://localhost/wp-json/ca/v1/stripe/webhook
   ```

2. Trigger test event:
   ```bash
   stripe trigger payment_intent.succeeded
   ```

3. Check webhook events table:
   ```sql
   SELECT * FROM wp_ca_webhook_events ORDER BY created_at DESC LIMIT 10;
   ```

4. Verify payment records in portal meta:
   - Check `ca_portal_meta_{estimateId}` option
   - Payment should be recorded in `payment.payments[]` array

## Production Deployment Checklist

- [ ] Stripe PHP library installed (`vendor/` directory exists)
- [ ] Composer autoloader loads successfully
- [ ] Stripe API keys configured (secret + publishable)
- [ ] Webhook secret configured (`CA_STRIPE_WEBHOOK_SECRET`)
- [ ] Webhook endpoint configured in Stripe dashboard
- [ ] Webhook events table created (`wp_ca_webhook_events`)
- [ ] WP-Cron enabled (or use server cron for reliability)
- [ ] Test webhook processing works
- [ ] Test payment flow end-to-end
- [ ] Monitor webhook retry logs

## Troubleshooting

### Webhook Signature Verification Fails

- Verify `CA_STRIPE_WEBHOOK_SECRET` matches the signing secret from Stripe dashboard
- Check that webhook endpoint URL matches exactly
- Ensure Stripe PHP library is installed: `composer require stripe/stripe-php`

### Webhook Events Not Processing

- Check WP-Cron is enabled: `wp cron event list`
- Verify `ca_process_stripe_webhook` hook is registered
- Check webhook events table for pending events:
  ```sql
  SELECT * FROM wp_ca_webhook_events WHERE processed_at IS NULL;
  ```

### Payment Records Not Updating

- Verify `estimateId` is included in payment intent metadata
- Check webhook events are being stored in database
- Review logs for processing errors
- Use reconciliation endpoint if needed

## File Structure

```
cheapalarms-plugin/
├── composer.json              # Composer dependencies
├── vendor/                    # Composer packages (gitignored)
│   └── stripe/
│       └── stripe-php/
├── includes/
│   ├── Services/
│   │   ├── StripeService.php
│   │   ├── StripeWebhookProcessor.php
│   │   ├── WebhookEventRepository.php
│   │   └── WebhookRetryService.php
│   ├── REST/Controllers/
│   │   └── StripeController.php
│   └── Db/
│       └── Schema.php        # Webhook events table migration
```

## Support

For issues or questions:
1. Check webhook events table for failed events
2. Review WordPress error logs
3. Check Stripe dashboard for webhook delivery status
4. Use reconciliation endpoint to fix payment state drift
