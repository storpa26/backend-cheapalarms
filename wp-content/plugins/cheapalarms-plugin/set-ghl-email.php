<?php
/**
 * Quick setup script to configure GHL from email
 * Run once from WordPress admin or via WP-CLI
 */

// Set the from email address for GHL emails
update_option('ghl_from_email', 'quotes@cheapalarms.com.au');

echo "✅ GHL from email configured: quotes@cheapalarms.com.au\n";
echo "All emails will now be sent via GoHighLevel Conversations API.\n";
echo "\nYou can change this anytime by running:\n";
echo "update_option('ghl_from_email', 'your-email@domain.com');\n";


