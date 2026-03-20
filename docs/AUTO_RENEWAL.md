# Auto-Renewal Feature

## Overview

The auto-renewal feature automatically refreshes your AWS credentials before they expire, eliminating the need to manually re-authenticate throughout your workday.

## Quick Start

### 1. Enable Auto-Renewal

```bash
tokendito --auto-renew-enable \
    --auto-renew-profiles default \
    --auto-renew-profiles dev \
    --auto-renew-profiles prod
```

### 2. Check Status

```bash
tokendito --auto-renew-status
```

Output:
```
Tokendito Auto-Renewal Status
============================================================
Enabled: True
Renewal threshold: 30 minutes
Check interval: 10 minutes (fallback)
Max sleep time: 60 minutes (config refresh)

Monitored Profiles (3):
  - default: expires in 11.5 hours (2026-03-20 20:00:00+00:00)
  - dev: expires in 11.5 hours (2026-03-20 20:00:05+00:00)
  - prod: expires in 11.5 hours (2026-03-20 20:00:10+00:00)
```

### 3. Disable Auto-Renewal

```bash
tokendito --auto-renew-disable
```

## How It Works

1. **Background Service**: On macOS, a launchd service runs in the background monitoring your credentials
2. **Smart Scheduling**: The daemon calculates when credentials expire and sleeps until renewal is needed (no constant polling)
3. **Batch Renewal**: Multiple profiles expiring around the same time are renewed together with a single authentication
4. **Automatic Recovery**: The service automatically restarts after system sleep/wake

## Configuration

Auto-renewal settings are stored in your tokendito configuration file (typically `~/.config/tokendito/tokendito.ini`):

```ini
[auto-renewal]
enabled = true
profiles = default, dev, prod
renewal_threshold_minutes = 30
check_interval_minutes = 10
max_sleep_minutes = 60
```

### Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable/disable auto-renewal | `false` |
| `profiles` | Comma-separated list of profiles to monitor | (empty) |
| `renewal_threshold_minutes` | Renew credentials this many minutes before expiration | `30` |
| `check_interval_minutes` | Fallback interval when expiration time is unknown | `10` |
| `max_sleep_minutes` | Maximum time between config checks (ensures responsiveness) | `60` |

### Manual Configuration

You can edit the configuration file directly:

```bash
vi ~/.config/tokendito/tokendito.ini
```

After manual changes, restart the service:

```bash
tokendito --auto-renew-disable
tokendito --auto-renew-enable --auto-renew-profiles <profiles>
```

## Passwordless Renewal with Device Tokens

For unattended renewal without password prompts, enable device tokens:

```bash
tokendito --profile default --use-device-token
```

After the initial authentication, the device token is saved and future renewals don't require your password or MFA approval.

## Command Reference

### Enable Auto-Renewal

```bash
tokendito --auto-renew-enable \
    --auto-renew-profiles <profile1> \
    --auto-renew-profiles <profile2>
```

Enables auto-renewal for the specified profiles. Can specify `--auto-renew-profiles` multiple times.

### Check Status

```bash
tokendito --auto-renew-status
```

Displays:
- Whether auto-renewal is enabled
- Monitored profiles and their expiration times
- Daemon service status (macOS)
- Configuration settings

### Disable Auto-Renewal

```bash
tokendito --auto-renew-disable
```

Disables auto-renewal and stops the background service (macOS).

### Manual Renewal Check

```bash
tokendito-renew-daemon --check-once
```

Runs a single renewal check and exits. Useful for testing or manual renewal.

## Advanced Topics

### Multiple Profiles with Different Lifetimes

The daemon intelligently handles profiles with different expiration times:

```
profile_a expires in 12 hours → Renewed in 11.5 hours
profile_b expires in 6 hours  → Renewed in 5.5 hours
profile_c expires in 2 hours  → Renewed in 1.5 hours
```

The daemon wakes up when the earliest renewal is needed, handles it, then recalculates for the next renewal.

### Efficient Batch Renewal

When multiple profiles expire around the same time, they're renewed together with **a single authentication**:

```bash
# Instead of 6 separate authentications:
tokendito --profile profile1  # Authenticate
tokendito --profile profile2  # Authenticate again
# ... (4 more times)

# The daemon does this:
tokendito --multi-profiles profile1 \
          --multi-profiles profile2 \
          --multi-profiles profile3 \
          --multi-profiles profile4 \
          --multi-profiles profile5 \
          --multi-profiles profile6
# Authenticate once!
```

### Config Responsiveness

The `max_sleep_minutes` setting (default: 60) ensures config changes are picked up promptly:

- If credentials don't expire for 12 hours, the daemon doesn't sleep for 12 hours
- Instead, it wakes every 60 minutes to check for config changes
- This means if you add a new profile, it's noticed within an hour

### Viewing Logs (macOS)

```bash
# Standard output
tail -f ~/Library/Logs/tokendito/renewal.log

# Error output
tail -f ~/Library/Logs/tokendito/renewal.error.log
```

### Service Management (macOS)

```bash
# Check if service is running
launchctl list | grep tokendito

# Manually load service
launchctl load ~/Library/LaunchAgents/com.tokendito.renewal.plist

# Manually unload service
launchctl unload ~/Library/LaunchAgents/com.tokendito.renewal.plist
```

## Platform Support

| Platform | Auto-renewal | Background Service | System Wake Support |
|----------|--------------|-------------------|---------------------|
| **macOS** | ✅ | ✅ (launchd) | ✅ |
| **Linux** | ✅ | Manual* | Manual* |
| **Windows** | ✅ | Manual* | Manual* |

\* On Linux/Windows, run the daemon manually: `tokendito-renew-daemon` or set up with systemd/Task Scheduler

## Troubleshooting

### Service Not Running

Check service status:
```bash
tokendito --auto-renew-status
```

Restart service:
```bash
tokendito --auto-renew-disable
tokendito --auto-renew-enable --auto-renew-profiles <profiles>
```

### Credentials Still Expiring

- Verify the profile name in config matches your tokendito profile
- Check `renewal_threshold_minutes` isn't too low
- Verify daemon has necessary credentials (password or device token)

### "Password not set" Error

Enable device tokens for passwordless renewal:
```bash
tokendito --profile <name> --use-device-token
```

Or store password in config (less secure):
```ini
[profile_name]
okta_password = your_password
```

### Check Daemon Logs

View recent daemon activity:
```bash
tail -20 ~/Library/Logs/tokendito/renewal.error.log
```

## Security Considerations

1. **Device Tokens**: Preferred method for automated renewal - no password stored
2. **Stored Passwords**: If using stored passwords, ensure proper file permissions
3. **Expiration Tracking**: Expiration times stored in plaintext (similar to AWS CLI)
4. **User-Level Service**: Daemon runs as your user, not system-wide

## Examples

### Example 1: Development Workflow

Enable auto-renewal for your dev and staging environments:

```bash
tokendito --auto-renew-enable \
    --auto-renew-profiles dev \
    --auto-renew-profiles staging

# Work all day without re-authenticating
```

### Example 2: Multi-Account Setup

Monitor multiple AWS accounts:

```ini
# tokendito.ini
[account-a]
okta_tile = https://company.okta.com/home/amazon_aws/abc123/456
aws_role_arn = arn:aws:iam::111111111111:role/engineer

[account-b]
okta_tile = https://company.okta.com/home/amazon_aws/def456/789
aws_role_arn = arn:aws:iam::222222222222:role/engineer

[account-c]
okta_tile = https://company.okta.com/home/amazon_aws/ghi789/012
aws_role_arn = arn:aws:iam::333333333333:role/engineer
```

```bash
tokendito --auto-renew-enable \
    --auto-renew-profiles account-a \
    --auto-renew-profiles account-b \
    --auto-renew-profiles account-c
```

### Example 3: Custom Thresholds

Adjust renewal timing:

```ini
[auto-renewal]
enabled = true
profiles = default
renewal_threshold_minutes = 60    # Renew 1 hour before expiration
check_interval_minutes = 5        # Check every 5 minutes (fallback)
max_sleep_minutes = 30            # Check config every 30 minutes
```

## Best Practices

1. **Use Device Tokens**: Enable `--use-device-token` to avoid storing passwords
2. **Monitor Selectively**: Only add profiles you actively use to avoid unnecessary renewals
3. **Check Logs Periodically**: Verify renewals are succeeding
4. **Test Configuration**: Run `tokendito-renew-daemon --check-once` after setup

## FAQ

**Q: Will this work if my computer is asleep?**
A: On macOS, the launchd service restarts after wake and immediately checks/renews credentials.

**Q: How many times will I need to authenticate per day?**
A: Once at the beginning when enabling device tokens, then the daemon handles renewals automatically. If you have multiple profiles expiring simultaneously, they're renewed with a single authentication.

**Q: What happens if renewal fails?**
A: The daemon logs the error and continues monitoring. It will retry at the next check interval. Check logs at `~/Library/Logs/tokendito/renewal.error.log`.

**Q: Can I use this in CI/CD pipelines?**
A: Yes, but for CI/CD you may want to use scheduled tasks instead of the daemon for better control.

**Q: Does this use `--multi-profiles` for efficiency?**
A: Yes! When multiple profiles need renewal at the same time, they're all renewed together with a single authentication, not separately.

## See Also

- [Configuration File Format](tokendito.ini.md)
- [Multi-Profile Usage](README.md#multi-profile-usage)
- [Command Line Reference](README.md#additional-command-line-reference)
