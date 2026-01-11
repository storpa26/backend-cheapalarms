# Deployment Notes - CheapAlarms Plugin

## ✅ **Configuration Status**

This plugin is **pre-configured** and ready for deployment!

---

## 🔧 **Before Deploying to Production**

### **Step 1: Update CORS Origins** (After Vercel Deployment)

**File:** `config/secrets.php`

**Find the TODO comments and add your actual URLs:**

```php
'upload_allowed_origins' => [
    // ... existing production URLs ...
    'https://your-actual-vercel-url.vercel.app',  // ← Replace with real URL
],

'api_allowed_origins' => [
    // ... existing production URLs ...
    'https://your-actual-vercel-url.vercel.app',  // ← Replace with real URL
],
```

**When to do this:**
- After you deploy Next.js to Vercel
- Vercel will give you a URL like: `https://headless-cheapalarms.vercel.app`
- Add that URL to both arrays
- Re-upload the plugin (or edit directly on Plesk)

---

## 📦 **What's Already Configured**

✅ **GHL Credentials** - Already in secrets.php  
✅ **ServiceM8 API Key** - Already in secrets.php  
✅ **Upload Security** - HMAC secret configured  
✅ **JWT Secret** - Updated for production  
✅ **CORS** - Localhost URLs preserved for local dev  
✅ **File Upload Limits** - 10MB max  
✅ **Stripe Payment Integration** - See STRIPE-PAYMENT-SETUP.md  

---

## 🚀 **Deployment Checklist**

### **Plesk WordPress:**
- [ ] Install fresh WordPress via Plesk WordPress Toolkit
- [ ] Install Composer dependencies: `composer install --no-dev` (see STRIPE-PAYMENT-SETUP.md)
- [ ] Upload this plugin (ZIP it first, include `vendor/` directory)
- [ ] Activate plugin via WP Admin
- [ ] Set Permalinks to "Post name" (Settings → Permalinks)
- [ ] Configure Stripe API keys (see STRIPE-PAYMENT-SETUP.md)
- [ ] Test API: `https://yourdomain.com/wp-json/ca/v1/health`

### **After Vercel Deployment:**
- [ ] Get Vercel URL from deployment
- [ ] Add Vercel URL to `secrets.php` (both arrays)
- [ ] Re-upload plugin OR edit file directly on Plesk
- [ ] Test CORS from Vercel app

---

## 🔍 **Testing Production API**

### **Health Check:**
```
GET https://yourdomain.com/wp-json/ca/v1/health
```

**Expected:**
```json
{
  "ok": true,
  "message": "CheapAlarms plugin is active",
  "version": "1.0.0"
}
```

### **Test Estimate Fetch:**
```
GET https://yourdomain.com/wp-json/ca/v1/estimate?estimateId=test
```

**Expected:** 401 or authentication error (normal - means API is working)

---

## ⚠️ **Important Notes**

### **Local Development Still Works:**
- ✅ Localhost URLs are kept in arrays
- ✅ Your local dev environment unchanged
- ✅ Can develop and deploy without conflicts

### **Security:**
- ✅ Credentials in `secrets.php` (never in Git)
- ✅ JWT secret is strong
- ✅ CORS limits which domains can access API
- ✅ HMAC signatures on uploads

### **No wp-config.php Editing Needed:**
- ✅ Plugin reads from `secrets.php`
- ✅ No manual WordPress configuration
- ✅ Clean separation of concerns

---

## 🔐 **Credentials Reference**

**All credentials are in:** `config/secrets.php`

**GHL Integration:**
- API Token: `pit-195d44e7...` (configured)
- Location ID: `aLTXtdwNknfmEFo3WBIX` (configured)

**ServiceM8 Integration:**
- API Key: `smk-fbb848...` (configured)

**Security:**
- Upload Secret: Configured
- JWT Secret: Updated for production

**Stripe Integration:**
- Secret Key: Configure in `secrets.php` or `CA_STRIPE_SECRET_KEY`
- Publishable Key: Configure in `secrets.php` or `CA_STRIPE_PUBLISHABLE_KEY`
- Webhook Secret: Configure in `secrets.php` or `CA_STRIPE_WEBHOOK_SECRET`
- See STRIPE-PAYMENT-SETUP.md for complete setup instructions

---

## 📝 **Post-Deployment Tasks**

### **Immediately After Deploying:**

1. **Add Vercel URL** to secrets.php
2. **Test API from Vercel** (check browser console)
3. **Send test portal invite**
4. **Test complete workflow**
5. **Monitor logs** for any errors

### **Within First Week:**

1. Configure email (WP Mail SMTP plugin recommended)
2. Set up monitoring (error logs, uptime)
3. Test all features thoroughly
4. Gather user feedback
5. Fix any production-specific issues

---

## 📧 **Email Configuration** (Recommended)

**For reliable email delivery:**

1. Install "WP Mail SMTP" plugin
2. Configure with SendGrid, Mailgun, or Gmail SMTP
3. Test email sending
4. Update `ghl_from_email` in WordPress options if needed

---

## 🎯 **Quick Reference**

**Plugin Location on Server:**
```
/httpdocs/wp-content/plugins/cheapalarms-plugin/
```

**Config File:**
```
/httpdocs/wp-content/plugins/cheapalarms-plugin/config/secrets.php
```

**Logs:**
```
/httpdocs/wp-content/plugins/cheapalarms-plugin/logs/cheapalarms.log
```

**WordPress Debug Log:**
```
/httpdocs/wp-content/debug.log
```

---

## ✅ **Status: Ready for Deployment**

- ✅ Plugin configured
- ✅ JWT secret updated
- ✅ CORS pre-configured
- ✅ Localhost preserved
- ⏳ Waiting for Vercel URL to complete CORS config

**You're good to go!** 🚀

