# End-to-End Windows Log Monitoring with an Elastic SIEM

This project documents the setup of a complete Security Information and Event Management (SIEM) solution using the Elastic Stack. The primary goal is to collect, process, and analyze critical Windows security event logs to detect common administrative and potentially malicious activities.

The data pipeline is configured as follows: **Winlogbeat (Windows Host) → Logstash (Ubuntu SIEM) → Elasticsearch (Ubuntu SIEM)**.

<img width="1616" height="793" alt="FINAL RESULT" src="https://github.com/user-attachments/assets/15348d23-5a0f-45ac-ad25-a2f14faaf9ac" />



## ✨ Key Features & Use Cases

This project successfully implements the detection of the following critical Windows security events:

  * 👤 **User Account Creation** (Event ID 4720)
  * 🚫 **User Account Disabled** (Event ID 4725)
  * ⏫ **User Privilege Escalation** (Event ID 4732)
  * 🗑️ **User Account Deletion** (Event ID 4726)
  * 📜 **System Audit Policy Change** (Event ID 4719)
  * 🔒 **User Account Lockout** (Event ID 4740)
  * 🕵️ **Brute Force Attack Correlation:** A high-fidelity EQL rule to detect a sequence of failed logins followed by a success.

## 📋 Prerequisites

  * **SIEM Server:** An Ubuntu Server with Elasticsearch, Kibana, and Logstash installed.
  * **Host Machine:** A Windows machine to be monitored.
  * **Software Packages:**
      * `elasticsearch-9.1.1-amd64.deb`
      * `kibana-9.1.1-amd64.deb`
      * `logstash-9.1.1-amd64.deb`
      * `winlogbeat-9.1.1-windows-x86_64.zip`

## 🚀 Step-by-Step Installation & Configuration Guide

This guide details the final, working configuration for the entire pipeline.

### Part 1: Setting up the SIEM Server (Ubuntu)

#### 1.1 - Install Elasticsearch & Kibana

Install the `.deb` packages for Elasticsearch and Kibana. Configure the `elasticsearch.yml` file to listen on the network and start both services.

```yaml
# /etc/elasticsearch/elasticsearch.yml
network.host: 0.0.0.0
discovery.type: single-node
```

#### 1.2 - Install Logstash

Download and install the Logstash `.deb` package on the Ubuntu server.

```bash
wget https://artifacts.elastic.co/downloads/logstash/logstash-9.1.1-amd64.deb
sudo dpkg -i logstash-9.1.1-amd64.deb
```

#### 1.3 - Configure the Logstash Pipeline

Create a pipeline configuration file to receive data from Winlogbeat and send it to Elasticsearch.

**File: `/etc/logstash/conf.d/02-winlogbeat-input.conf`**

```conf
input {
  beats {
    port => 5044
  }
}

output {
  elasticsearch {
    hosts => ["https://localhost:9200"]
    user => "elastic"
    password => "YOUR_ELASTIC_PASSWORD"
    ssl_verification_mode => "none"
    index => "winlogbeat-%{+YYYY.MM.dd}"
  }
}
```

*Note: The `elastic` user's password must be set and configured correctly. See the Troubleshooting section for details on password resets.*

#### 1.4 - Configure the Firewall (UFW)

Open the necessary ports on the Ubuntu server's firewall.

```bash
sudo ufw allow ssh
sudo ufw allow 5601/tcp # Kibana
sudo ufw allow 9200/tcp # Elasticsearch
sudo ufw allow 5044/tcp # Logstash Beats Input
sudo ufw enable
```

### Part 2: Setting up the Windows Host

#### 2.1 - Configure Windows Audit Policies

Before installing the agent, ensure Windows is configured to generate the necessary security logs. Run these commands in an **Administrator PowerShell**.

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
```

#### 2.2 - Install and Configure Winlogbeat

1.  Download and extract the `winlogbeat-9.1.1-windows-x86_64.zip` file to `C:\Program Files\Winlogbeat`.

2.  Edit the `winlogbeat.yml` configuration file. Disable the `output.elasticsearch` section and enable the `output.logstash` section, pointing it to your SIEM server's IP address.

    ```yaml
    # C:\Program Files\Winlogbeat\winlogbeat.yml
    output.logstash:
      hosts: ["<your_siem_server_ip>:5044"]
    ```

3.  Install and start the Winlogbeat service from an **Administrator PowerShell**.

    ```powershell
    cd "C:\Program Files\Winlogbeat"
    .\install-service-winlogbeat.ps1
    Start-Service winlogbeat
    ```

-----

### 🧪 Testing the Pipeline: Generating and Finding Events

A PowerShell script, `Generate-Test-Logs.ps1`, was used to generate events for all 6 core test cases. The script automates user creation, modification, and policy changes.


After running the script, each event can be found in Kibana Discover using the appropriate KQL query.

| Test Case | Event ID | KQL Query | Verification Screenshot |
| :--- | :--- | :--- | :--- |
| **User Creation** | 4720 | `winlog.event_id : 4720` | |
| **User Disabled** | 4725 | `winlog.event_id : 4725` | |
| **Privilege Escalation** | 4732 | `winlog.event_id : 4732` | |
| **User Deletion** | 4726 | `winlog.event_id : 4726` | |
| **Policy Change** | 4719 | `winlog.event_id : 4719` | |
| **User Lockout** | 4740 | `winlog.event_id : 4740` | |

-----

### 🛡️ Creating Detection Rules

The final step is to turn these manual searches into automated detection rules within the Kibana Security app.

<img width="1605" height="606" alt="New User Account Created" src="https://github.com/user-attachments/assets/3f19cafb-7f3e-4ec5-b2af-d2c861797745" />


#### **Custom KQL Rule: User Account Creation**

A custom KQL rule was created to automatically detect new user accounts.



####  - EQL Correlation Rule: Brute Force Attack**

An advanced Event Correlation rule was designed to detect a successful brute-force attack pattern.

  * **Rule Name:** Potential Brute Force Attack Followed by Successful Logon
  * **Detection Logic (EQL):**
    ```eql
    sequence by user.name, source.ip with maxspan=5m
        [authentication where event.outcome == "failure"] with runs=5
        [authentication where event.outcome == "success"]
    ```
  * **Alert Description:** This high-fidelity rule triggers when five or more failed logon attempts from the same user and source IP are immediately followed by a successful logon within a five-minute window, strongly indicating a compromised credential.

-----

### 🛠️ Troubleshooting Guide: Common Problems & Solutions

This project encountered several real-world challenges. This section documents the obstacles and their solutions.

#### **Server Installation Issues (Elasticsearch, Kibana, Logstash)**

  * **Obstacle:** Command-line tools failed with SSL certificate validation errors (`No subject alternative names matching IP address...`).

      * **Solution:** The server's IP address was dynamic. The fix was to force tools to connect via localhost by adding the `--url "https://127.0.0.1:9200"` flag to commands.

  * **Obstacle:** Logstash failed to start, reporting a `401 Unauthorized` error.

      * **Solution:** The password for the `elastic` user in the Logstash configuration file was incorrect. This was resolved by resetting the `elastic` password with `elasticsearch-reset-password` and updating the config file.

  * **Obstacle:** Logstash failed to start, reporting a `400 Bad Request` when trying to install an index template.

      * **Solution:** A template priority conflict was identified in the logs. This was resolved by adding `template_priority => 201` to the `elasticsearch` output block in the Logstash configuration.

#### **Windows Agent Installation & Testing**

  * **Obstacle:** The test script failed because the `Disable-LocalAccount` PowerShell command was not recognized.

      * **Solution:** The modern cmdlet was replaced with the more universal legacy command `net user "username" /active:no` in the script.

  * **Obstacle:** The automated user lockout test was skipped.

      * **Solution:** The script correctly identified that the Windows "Account lockout threshold" was set to 'Never'. The policy was enabled using the command `net accounts /lockoutthreshold:3`. The script's test username was also shortened to be under the 20-character limit.

#### **Kibana Data Visibility**

  * **Obstacle:** Logs were not visible in the Kibana Discover tab ("No results match").

      * **Solution:** The time range filter was set too narrowly (e.g., "Last 15 minutes"). Expanding the time range to "Today" revealed the logs.

  * **Obstacle:** EQL rule creation failed due to a mapping conflict (`event.outcome` was `text` instead of `keyword`).

      * **Solution:** A correcting index template was created manually in Elasticsearch using the Template API. This template enforces that for all future `winlogbeat-*` indices, the `event.outcome` field is correctly mapped as a `keyword` type.
