# Silver Assist Security Essentials

A comprehensive WordPress security plugin designed to resolve critical security vulnerabilities identified in security assessments, specifically targeting admin protection (login security & URL hiding), HTTPOnly cookie implementation, and GraphQL security misconfigurations.

## 🛡️ Overview

**Silver Assist Security Essentials** addresses three critical security vulnerabilities commonly found in WordPress security audits:

1. **WordPress Admin Protection & Access Control** - Comprehensive protection against brute force attacks, unauthorized access, and admin discovery
2. **Missing HTTPOnly Flag on Cookies** - Prevents XSS attacks from accessing authentication cookies  
3. **GraphQL Security Misconfigurations** - Comprehensive protection against DoS attacks, introspection abuse, and resource exhaustion

This plugin automatically implements enterprise-level security measures without requiring technical knowledge, making it perfect for WordPress sites that need to pass security audits and compliance requirements.

## 🎯 Security Issues Resolved

### 🔐 WordPress Admin Protection & Access Control
**Problem**: Publicly accessible admin area vulnerable to brute force attacks, user enumeration, bot crawling, and automated discovery
**Solution**:
- **Login Protection**: IP-based login attempt limiting (configurable 1-20 attempts)
- **Session Management**: Session timeout management (5-120 minutes)
- **User Enumeration Protection**: Login error standardization prevents user discovery
- **Strong Password Enforcement**: Mandatory complex passwords (12+ characters, mixed case, numbers, symbols)
- **Bot and Crawler Protection**: Automatic blocking of suspicious crawlers, scanners, and automated tools
- **Anti-Reconnaissance**: Blocks security scanning tools (Nmap, Nikto, WPScan, Nuclei, etc.)
- **Rate Limiting**: Prevents rapid-fire login attempts from automated scripts
- **Custom Admin URLs**: Configure personalized admin access paths (e.g., `/my-secure-admin`)
- **404 Redirect Protection**: Direct access to standard admin URLs returns 404 errors to hide admin existence
- **Real-Time Path Validation**: Live feedback while typing custom paths with security keyword filtering
- **Intelligent Path Blocking**: Prevents use of obvious paths like 'admin', 'login', 'dashboard', 'wp-admin'

### 🍪 HTTPOnly Cookie Flag Missing
**Problem**: Cookies accessible to client-side JavaScript, vulnerable to XSS attacks  
**Solution**:
- Automatic HTTPOnly flag implementation for all WordPress authentication cookies
- Secure cookie configuration for HTTPS sites
- SameSite protection against CSRF attacks
- Session cookie security enhancement

### 🛡️ GraphQL Security Misconfigurations
**Problem**: Multiple GraphQL vulnerabilities including introspection exposure, unlimited aliases, field duplication, and circular queries  
**Solution**:
- **Introspection Blocking**: Disabled in production environments
- **Query Depth Limits**: Configurable limits (1-20 levels, default: 8) 
- **Query Complexity Control**: Prevents resource exhaustion (10-1000 points, default: 100)
- **Query Timeout Protection**: Configurable timeouts (1-30 seconds, default: 5)
- **Rate Limiting**: 30 requests per minute per IP to prevent DoS attacks
- **Alias & Field Duplication Protection**: Prevents excessive aliases and field repetition

## ✨ Additional Security Features

### 🔒 WordPress Hardening *(Automatic)*
- **Secure Headers**: Essential security headers (X-Frame-Options, X-XSS-Protection, etc.)
- **File Editing Disabled**: Prevents unauthorized file modifications through admin panel
- **XML-RPC Disabled**: Blocks XML-RPC attacks and vulnerabilities
- **Version Hiding**: Conceals WordPress version information from potential attackers

### 🤖 Advanced Bot Protection *(Login Page)*
- **Crawler Detection**: Automatically identifies and blocks known bot user agents
- **Scanner Blocking**: Stops security scanners (Nmap, Nikto, WPScan, Nuclei, Dirb, etc.)
- **404 Responses**: Returns "Not Found" to suspicious automated requests
- **Rate Limiting**: Prevents rapid-fire access attempts from scripts
- **Header Analysis**: Detects missing browser headers typical of automated tools
- **Enhanced Security Headers**: X-Frame-Options, X-XSS-Protection, Content Security Policy
- **WordPress Hardening**: XML-RPC blocking, version hiding, file editing restrictions
- **User Enumeration Protection**: Prevents discovery of valid usernames
- **Behavioral Tracking**: Monitors and extends blocks for persistent bot activity

## 📊 Real-Time Monitoring Dashboard
- **Security Status Overview**: View all security configurations at a glance
- **Live Statistics**: Real-time login attempt tracking and blocked IPs monitoring
- **GraphQL Activity**: Query analysis and rate limiting statistics

## 🌍 Enterprise Features
- **Easy Configuration**: Simple admin panel with toggle switches and sliders
- **Instant Updates**: All settings take effect immediately
- **Multi-Language Support**: Full Spanish translation included
- **No Technical Knowledge Required**: Works automatically after activation
- **Automatic Updates**: Built-in update system for latest security patches

## 📦 Installation & Setup

### Installation Methods

**WordPress Admin Dashboard** *(Recommended)*
1. Download the latest `silver-assist-security.zip` file
2. Go to **Plugins → Add New → Upload Plugin**
3. Choose the ZIP file and click **Install Now**
4. Click **Activate Plugin**

**Manual FTP Upload**
1. Extract the ZIP file to get the `silver-assist-security` folder
2. Upload the folder to `/wp-content/plugins/` via FTP
3. Activate from **WordPress Admin → Plugins**

**WP-CLI** *(Advanced)*
```bash
wp plugin install silver-assist-security.zip --activate
```

## 🚀 Quick Start & Configuration

### Immediate Protection *(No Configuration Required)*
The plugin starts protecting your website immediately after activation:

✅ **HTTPOnly cookies** are automatically enabled  
✅ **Login protection** blocks brute force attempts  
✅ **GraphQL security** prevents DoS attacks  
✅ **Security headers** are added to all pages  
✅ **File editing** is disabled in admin  
✅ **XML-RPC** is blocked  
✅ **User enumeration** is prevented  
✅ **Admin URL hiding** (optional - requires configuration)  

### Configuration Dashboard

#### Settings Hub Integration (v1.1.13+)
**🎯 NEW**: Silver Assist Security now integrates with the centralized Settings Hub!

**With Settings Hub Installed**:
- Access via **Silver Assist → Security** (top-level menu)
- Professional plugin dashboard with cards and metadata
- One-click "Check Updates" button in plugin card
- Seamless navigation between Silver Assist plugins
- Enhanced user experience with unified interface

**Without Settings Hub** (Fallback):
- Access via **Settings → Security Essentials** (legacy menu)
- Full functionality maintained
- All security features work identically

**Install Settings Hub** (Optional but Recommended):
```bash
composer require silverassist/wp-settings-hub
```

**Login Security Configuration**
- 🔧 **Max Login Attempts**: 1-20 failed attempts before lockout (default: 5)
- 🔧 **Lockout Duration**: 60-3600 seconds blocking period (default: 900s/15min)
- 🔧 **Session Timeout**: 5-120 minutes user session duration (default: 30min)
- 🔧 **Bot Protection**: Enable/disable bot and crawler blocking (default: enabled)

**GraphQL Security Configuration** *(If WPGraphQL is Active)*
- 🔧 **Query Depth Limit**: 1-20 levels (default: 8)
- 🔧 **Query Complexity**: 10-1000 points (default: 100)
- 🔧 **Query Timeout**: 1-30 seconds (default: 5)
- ✅ **Rate Limiting**: 30 requests/minute per IP (automatic)
- ✅ **Introspection**: Disabled in production (automatic)

**Admin URL Hide Configuration** *(Optional Security Layer)*
- 🔧 **Enable Admin Hiding**: Toggle on/off admin URL protection
- 🔧 **Custom Admin Path**: Set your personalized admin access URL (e.g., 'my-secure-admin')
- ✅ **Real-Time Validation**: Live feedback prevents weak or forbidden paths
- ✅ **404 Protection**: Standard admin URLs automatically return "Not Found" errors
- 🆘 **Emergency Access**: Built-in recovery system for forgotten custom paths (see Emergency Access section below)

#### 🆘 Emergency Access Recovery
If you forget your custom admin path, you can regain access via FTP:

**Step 1**: Access your WordPress files via FTP or cPanel File Manager  
**Step 2**: Open the `wp-config.php` file in your website root  
**Step 3**: Add this line anywhere before `/* That's all, stop editing! */`:
```php
define('SILVER_ASSIST_HIDE_ADMIN', false);
```
**Step 4**: Save the file and refresh your website  
**Step 5**: You can now access admin at the standard `/wp-admin` URL  
**Step 6**: After regaining access, you can reconfigure the admin path and remove the constant

### Security Compliance Verification
After configuration, your website will be protected against the three critical security issues:

✅ **Admin Protection**: Complete admin area protection with login security, URL hiding, and access control  
✅ **HTTPOnly Cookies**: All cookies have HTTPOnly flags to prevent XSS exploitation  
✅ **GraphQL Secured**: GraphQL endpoint has comprehensive DoS protection and introspection disabled  

## 🔄 Automatic Updates

### Built-in Update System
✅ **Automatic Update Checks**: Daily checks for security patches  
✅ **One-Click Updates**: Update directly from WordPress admin  
✅ **Security Priority**: Critical security updates are prioritized  
✅ **Changelog Display**: Shows what's new in each version  

⚠️ **Always backup your website before applying updates**

## 💡 Frequently Asked Questions

**Will this plugin slow down my website?**  
No. Silver Assist Security Essentials is optimized for performance and adds minimal overhead.

**Do I need technical knowledge to use this plugin?**  
No. The plugin works automatically after activation with simple toggle controls for customization.

**Is it compatible with other security plugins?**  
Yes, but we recommend using Silver Assist Security Essentials as your primary security solution to avoid conflicts.

**What happens to my login page after installation?**  
Your login page remains at the standard WordPress location but gains enhanced protection against brute force attacks, bot detection, and user enumeration.

**Can I customize the security settings?**  
Yes! Go to **Settings → Security Essentials** to configure login attempt limits, session timeouts, GraphQL security settings, and other features.

## ⚠️ System Requirements & Notes

**System Requirements**
- **WordPress**: 6.5 or higher
- **PHP**: 8.3 or higher
- **HTTPS**: Recommended for full security features

**Important Notes**
- Always backup your website before installing security plugins
- Currently optimized for single WordPress installations
- Multisite compatibility coming in future versions

## 🆘 Support & Troubleshooting

**Common Issues**

*GraphQL not working after activation?*
- Verify WPGraphQL plugin is installed and active
- Check GraphQL query complexity limits in settings

*Website seems slower?*
- Review rate limiting settings in Security Essentials
- Adjust GraphQL query limits if needed

## 🌍 Multi-Language Support

- **English**: Default language
- **Spanish**: Complete translation included (`es_ES`)
- **Translation Ready**: `.pot` file included for additional languages

---

**Made with ❤️ by [Silver Assist](https://silverassist.com)**
