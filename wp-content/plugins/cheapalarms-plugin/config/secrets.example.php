<?php
/**
 * Example secrets configuration file
 * 
 * Copy this file to secrets.php and fill in your actual values
 * OR set them as environment variables (recommended for production)
 * 
 * secrets.php is gitignored - never commit real secrets
 */

return [
    // GHL Integration Credentials
    'ghl_token'              => '', // or set CA_GHL_TOKEN env var
    'ghl_location_id'        => '', // or set CA_LOCATION_ID env var
    
    // ServiceM8 Integration
    'servicem8_api_key'      => '', // or set CA_SERVICEM8_API_KEY env var
    
    // Upload Security
    'upload_shared_secret'   => '', // or set CA_UPLOAD_SHARED_SECRET env var
    'upload_max_mb'          => 10,
    
    // CORS Configuration - Allowed Origins for Photo Uploads
    'upload_allowed_origins' => [
        // Production
        'https://cheapalarms.com.au',
        'https://staging.cheapalarms.com.au',
        'https://headless-cheapalarms.vercel.app',
        
        // Local Development
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
        
        // Local Development
        'http://localhost:3000',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
    ],
    
    // JWT Authentication Secret
    'jwt_secret'       => '', // or set CA_JWT_SECRET env var
    'jwt_ttl_seconds'  => 3600, // 1 hour
    
    // Frontend URL (Next.js on Vercel)
    'frontend_url'     => 'https://headless-cheapalarms.vercel.app',
    
    // GHL User ID (authorized employee/user ID for sending estimates)
    'ghl_user_id'      => '', // or set CA_GHL_USER_ID env var
    
    // Xero Integration Credentials
    'xero_client_id'     => '', // or set CA_XERO_CLIENT_ID env var
    'xero_client_secret' => '', // or set CA_XERO_CLIENT_SECRET env var
    // Redirect URI should match your Next.js app URL + /xero/callback
    'xero_redirect_uri'  => 'https://headless-cheapalarms.vercel.app/xero/callback',
    
    // Stripe Integration Credentials (Test Mode)
    'stripe_publishable_key' => '', // or set CA_STRIPE_PUBLISHABLE_KEY env var
    'stripe_secret_key'      => '', // or set CA_STRIPE_SECRET_KEY env var
];

