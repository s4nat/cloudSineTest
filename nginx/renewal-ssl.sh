#!/bin/sh

# Renew the certificate
certbot renew --nginx --non-interactive

# Reload nginx to pick up the new certificate
nginx -s reload