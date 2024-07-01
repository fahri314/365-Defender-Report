# 365 Defender Report

This tool uses incident and device data from the 365 Defender product to provide data for report writing.
It automatically calculates the last one-week date range based on the day the report was written and provides the following data:

- Date range
- Total incident
- Severity distribution of True Positive events
- Category distribution
- Total number of endpoints (Appearing in the last week)
- Endpoint OS distribution
- True Positive events:
 - Incident ID, Last activity, Incident Name, Severity, Classification, Impacted Assets
 - Analyst comments
- Incident source distribution

## Config File

Before running the script, you must modify the values in the config file.

- Uses the entered report day in automatic date calculation.
- Supports multiple tenants and offers options at startup.
- Exclusion of e-mail alerts.
- It can exclude from the incident title according to the given keyword list.

Scauth and xsrf_token values ​​are automatically calculated from the entered cookie value.

## Get Cookie from Defender 365

You can obtain this cookie data from the network section of your browser while logged in to the session at the address below. `Scauth` and `xsrf_token` values ​​are automatically calculated from the entered cookie value.

<https://security.microsoft.com/incidents?tid=your_tenant_id>

## Limitations

- Maximum page size is:
  - incident: 100
  - Device: 200
- Maximum rate of requests is 50 calls per minute and 1500 calls per hour.