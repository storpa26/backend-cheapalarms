<?php

return [
    // GHL Integration Credentials
    'ghl_token'              => 'pit-195d44e7-6b55-4e86-aa33-1c039d458e5c',
    'ghl_location_id'        => 'aLTXtdwNknfmEFo3WBIX',
    
    // ServiceM8 Integration
    'servicem8_api_key'      => 'smk-fbb848-de965f5b73c126d0-3358deb36d0b2bef',
    
    // Upload Security
    'upload_shared_secret'   => 'WsP0DZcLrHRHC9wA3I2Ex2q1hZ/g0W26N+vJ1S3hSei3pusOlI2CaS7zOOG9iKPn',
    'upload_max_mb'          => 10,
    
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
    
    // JWT Authentication Secret (changed for production security)
    'jwt_secret'       => 'aB3$kL9@mN2pQ7*xZ4vR8tY6uW1sE5oI0cD2fG4hJ6lM8nP0qS2tV4wX6yA8bC0',
    'jwt_ttl_seconds'  => 3600, // 1 hour
    
    // Frontend URL (Next.js on Vercel)
    'frontend_url'     => 'https://headless-cheapalarms.vercel.app',
    
    // GHL User ID (authorized employee/user ID for sending estimates)
    // Get this from your GHL account settings or API
    // This is required for the send estimate endpoint
    'ghl_user_id'      => '', // TODO: Add your GHL authorized employee/user ID here
];

