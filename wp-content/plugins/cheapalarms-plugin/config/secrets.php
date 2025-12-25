<?php

/**
 * Secrets configuration file
 * 
 * This file is gitignored. Never commit real secrets.
 * 
 * Load secrets from environment variables (recommended for production)
 * or set them directly here for local development only.
 * 
 * Environment variable names:
 * - CA_GHL_TOKEN
 * - CA_LOCATION_ID
 * - CA_SERVICEM8_API_KEY
 * - CA_UPLOAD_SHARED_SECRET
 * - CA_JWT_SECRET
 * - CA_XERO_CLIENT_ID
 * - CA_XERO_CLIENT_SECRET
 * - CA_STRIPE_PUBLISHABLE_KEY
 * - CA_STRIPE_SECRET_KEY
 */

return [
    // GHL Integration Credentials
    'ghl_token'              => getenv('CA_GHL_TOKEN') ?: '',
    'ghl_location_id'        => getenv('CA_LOCATION_ID') ?: '',
    
    // ServiceM8 Integration
    'servicem8_api_key'      => getenv('CA_SERVICEM8_API_KEY') ?: '',
    
    // Upload Security
    'upload_shared_secret'   => getenv('CA_UPLOAD_SHARED_SECRET') ?: '',
    'upload_max_mb'          => (int)(getenv('CA_UPLOAD_MAX_MB') ?: 10),
    
    // CORS Configuration - Allowed Origins for Photo Uploads
    'upload_allowed_origins' => [
        // Production
        'https://cheapalarms.com.au',
        'https://staging.cheapalarms.com.au',
        'https://headless-cheapalarms.vercel.app',
        
        // Local Development (keep these for local work)
        'http://localhost',
        'http://localhost:3000',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
    ],
    
    // CORS Configuration - Allowed Origins for API Access
    'api_allowed_origins' => [
        // Production
        'https://cheapalarms.com.au',
        'https://staging.cheapalarms.com.au',
        'https://headless-cheapalarms.vercel.app',
        
        // Local Development (keep these for local work)
        'http://localhost:3000',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
    ],
    
    // JWT Authentication Secret
    'jwt_secret'       => getenv('CA_JWT_SECRET') ?: '',
    'jwt_ttl_seconds'  => (int)(getenv('CA_JWT_TTL_SECONDS') ?: 3600),
    
    // Frontend URL (Next.js on Vercel)
    'frontend_url'     => getenv('CA_FRONTEND_URL') ?: 'https://headless-cheapalarms.vercel.app',
    
    // GHL User ID (authorized employee/user ID for sending estimates)
    'ghl_user_id'      => getenv('CA_GHL_USER_ID') ?: '',
    
    // Xero Integration Credentials
    'xero_client_id'     => getenv('CA_XERO_CLIENT_ID') ?: '',
    'xero_client_secret' => getenv('CA_XERO_CLIENT_SECRET') ?: '',
    // Redirect URI should match your Next.js app URL + /xero/callback
    'xero_redirect_uri'  => getenv('CA_XERO_REDIRECT_URI') ?: 'https://headless-cheapalarms.vercel.app/xero/callback',
    
    // Stripe Integration Credentials (Test Mode)
    // Load from environment variables - NEVER commit real keys
    'stripe_publishable_key' => getenv('CA_STRIPE_PUBLISHABLE_KEY') ?: '',
    'stripe_secret_key'      => getenv('CA_STRIPE_SECRET_KEY') ?: '',
];
