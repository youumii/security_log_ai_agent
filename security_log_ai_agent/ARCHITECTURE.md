# Architecture

```text
[Log File]
    |
    v
[Parser]
 CSV / SSH
    |
    +----> Broken Log List
    |
    v
[Detection Engine]
    |
    +--> User Brute Force
    +--> Multi-account from same IP
    +--> Success after failures
    +--> Multiple source IPs
    |
    v
[Risk Scoring]
    |
    +-------------------+
    |                   |
    v                   v
[AI Summary]        [Webhook]
    |
    v
[Flask Dashboard]
    |
    +--> TXT Report
    +--> JSON Report
```
