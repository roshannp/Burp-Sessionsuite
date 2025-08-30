# Sessionsuite
Burp Extension for Granular session checks




### Step 1: Set the Jython JAR File in Extensions (I have used the latest jython-standalone-2.7.4) 

<img width="1318" height="781" alt="Screenshot 2025-08-30 at 11 07 07 AM" src="https://github.com/user-attachments/assets/96de8a97-83b4-4f40-a867-b523173558f8" />

### Step 2: Download the SessionSuite.py file and add it to Extensions->Python(type)->Add File.
<img width="1318" height="758" alt="Screenshot 2025-08-30 at 11 08 38 AM" src="https://github.com/user-attachments/assets/55329d51-092e-412b-a068-dafd9b005a93" />

### Step 3: Add the domains in scope

<img width="1269" height="592" alt="Screenshot 2025-08-30 at 11 05 48 AM" src="https://github.com/user-attachments/assets/31428143-33ec-45e0-9a47-a24361318989" />

### Step 4: Run Burp with FoxyProxy on and intercept the traffic

### Step 5: Session tracker features/metrics are logged when you login/logout.

Example Screenshots below:
#### Tracker
<img width="1318" height="758" alt="Screenshot 2025-08-30 at 11 10 58 AM" src="https://github.com/user-attachments/assets/db4bbcdc-2886-4171-bdc6-2e8fa3e45b2e" />
#### Checklist
<img width="1318" height="758" alt="Screenshot 2025-08-30 at 11 11 23 AM" src="https://github.com/user-attachments/assets/8b666786-4bae-4592-9df7-3ee4d2cddd89" />
#### Auth Flow
<img width="1318" height="758" alt="Screenshot 2025-08-30 at 11 12 15 AM" src="https://github.com/user-attachments/assets/9db0f4bb-14a3-47d8-acf8-4a73e1603323" />
### Analyzer ( Key details like, JWT missing exp, token reuse, algo check)
<img width="1318" height="758" alt="Screenshot 2025-08-30 at 11 12 39 AM" src="https://github.com/user-attachments/assets/a342e2f1-6d82-4a59-8e90-d698a204d587" />
