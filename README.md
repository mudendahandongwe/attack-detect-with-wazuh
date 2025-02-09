# Attack and Detect with Wazuh

## Objective
Understanding attacks and being able to detect them are important skills for SOC analysts. In this home lab, I created a virtual enterprise enviornment, introduced vulnerable configurations, performed a multi-phase end-to-end attack, and identified specific activity with detection rules and alerts created in Wazuh. 

This project was created by Grant Collins and can be accessed for free <a href = "https://projectsecurity.teachable.com/p/build-a-cybersecurity-homelab-a-practical-guide-to-offense-defense-enterprise-101"> here</a>. 

## Skills Involved
- Computer Networking
- Firewall Configurations
-	Active Directory
-	Attack Tactics: reconnaissance, phishing, brute force, lateral movement, privilege escalation, data exfiltration, persistence mechanisms
-	Security Monitoring with Security Onion & Wazuh

## Main Steps

### 1. Build an Enterprise Environment

The first phase of the project involved building an enterprise environment using VirtualBox. 

![image](https://github.com/user-attachments/assets/585600ba-de56-41c7-b194-42dcc4919f23)


As shown in the topology above, the email and server and 3 PC's were connected to the Active Directory domain controller.

![image](https://github.com/user-attachments/assets/f2fbc317-9bdc-4a05-b1eb-a1ab3be9b357)



### 2. Introduce Vulnerable Configurations
In order to conduct the end-to-end attack, a number of vulnerabile configurations were introduced into the environment. 
- Install and/or enable SSH (port 22) and RDP (port 3389) on relevant machines.
- Install and enable Linux firewall on relevant machines.
- Allow relevant services and ports (22 & 3389) on firewalls.
- Create an intentionally weak password on the email server to create susceptiblity to brute force attack.

### 3. Create Detection Rules in Wazuh
In order to detect activities from the end-to-end attack, three rules and alerts were created in Wazuh.
1. Rule to detect RDP logins.
    Windows does not have an event ID specifically for WinRM so a rule was created to detect authentication via Kerberos (which WinRM uses for remote connections) and successful logins.       Specifically, two filters were used:
   - data.win.eventdata.logonProcessName is Kerberos
   - data.win.system.eventID is 4624
   
3. Rule to monitor access of sensitive data (file integrity monitoring). This rule used two filters:
    -  full_log contains secrets.txt (the file containing the "sensitive" data)
    -  syscheck.event is modified
   
5. Rule to detect 3 failed SSH login attempts. This rule used two filters:
   -  decoder.name is sshd
   -  rule.groups contains authentication_failed

![image](https://github.com/user-attachments/assets/a1fd08e0-e9fb-4e89-a54f-bad203e0e9c4)

### 4. Conduct End-to-End Attack

Using Kali Linux as the attacker machine, an end-to-end multi-phase attack was conducted involving a number of tactics. Some of the main steps and tactics are presented below.

Initial **reconnaissance** began with using nmap to scan ports on the machine at 10.0.0.8: 

![image](https://github.com/user-attachments/assets/83830f4b-c999-4776-95e0-98e2af1cf157)


Nmap identified 2 services on open ports:

![image](https://github.com/user-attachments/assets/b98b634d-0a31-448b-8df3-1d8a3622f30a)



Since port 22 (SSH) was identified as open, I probed for SSH access. The results show that password authentication is enabled:

![image](https://github.com/user-attachments/assets/ee227069-de8d-413d-b6f5-883af2ec0adc)

Using Hydra and the rockyou.txt password list, I conducted a **brute force** on the SSH password:

![image](https://github.com/user-attachments/assets/89c22cfc-3c20-43e9-bd24-82881b0fdf98)


Hydra identified an account and password:

![image](https://github.com/user-attachments/assets/a7a00103-f9b7-4620-a595-d7a3b83d4f09)

Using this password, I **accessed** the machine via SSH and conducted further **reconnaissance** on the machine, identifying the OS, hostname, installed and running services, file structure, configuration files, and usernames from the /etc/passwd file. This revealed an account named email-svr, which became the target. 

After **moving** to this account, I investigated the contents of the home directory, which further suggest that the machine is functioning as an email server:

![image](https://github.com/user-attachments/assets/c00669f0-4cca-4b7a-ac7a-cac417801a99)

**Reconnaissance** on the emails on the server revealed mail previously sent to janed[@]corp.project-x-dc.com. 

I created a web page for **harvesting credentials** from the user:

![image](https://github.com/user-attachments/assets/0930351f-4b0f-455b-bce1-75733c307c87)


I then sent a **phishing** email with an embedded link to the *credential harvesting** page. The user entered her credentials, which were captured in a log file:

![image](https://github.com/user-attachments/assets/11c667f7-7013-44ff-b3c4-4639060ee644)

Using these credentials, I **accessed** the workstation of janed (which had been previously identified via the network scan), and conducted further **reconnaissance**, which revealed wsman and wsmans running on ports 5985 and 5986. These are associated with WinRM, which is a remote management tool that can be exploited.

![image](https://github.com/user-attachments/assets/c2591aed-7a37-4d03-b901-cb2b24856b5b)


Using this protocol and the NetExec tool, I conducted a **password spraying attack** focusing on the Windows workstation that had been revealed in earlier network scans. This password spraying attack revealed an account with the username Administrator and the password:

![image](https://github.com/user-attachments/assets/a96aa739-b513-48da-a09e-cc259877193e)


Using this information I **moved** to the Windows workstation and examined the domain information on that machine:

![image](https://github.com/user-attachments/assets/11cd3665-ca7e-4ef2-bd16-8f5aa587654d)

This revealed the IP address of the domain controller, which is a high value target. An nmap scan of the domain controller revealed that port 3389 (RDP) was open. Using this information, I attempted to **access** the domain controller using xfreerdp and was successful, resulting in further **lateral movement**:

![image](https://github.com/user-attachments/assets/98a442b2-550f-4c3c-9b78-3f9ca8612e80)

This gave remote desktop **access** to the domain controller with the administrator account, resulting in **privilege escalation**.

Earlier I had placed a file on the domain controller named “secrets.txt” which represents sensitive information to be exfiltrated. Using the secure copy command, I copied this file to my Kali Linux machine, accomplishing **data exfiltration**. 

Using the command line from Kali Linux, I ran the following commands to create a new user, add the user to the Administrators group and to the Domain Admins. This is one mechanism of establishing **persistence** for future actions on objectives.

    net user project-x-user @mysecurepassword1! /add

    net localgroup Administrators project-x-user /add

    net group “Domain Admins” project-x-user /add

As an additional means of **persistence**, I ran a Powershell script which created a scheduled task with the purpose of initiating a reverse shell daily at 12:00. 

![image](https://github.com/user-attachments/assets/940bda35-ee6d-449e-a15b-ebcc19e8dacc)

The scheduled task was successfully created:

![image](https://github.com/user-attachments/assets/804c776e-4ba0-4793-b153-9e6951e1a691)

### 5. Wazuh Alerts and Logs

The rules created earlier in Wazuh successfully detected the relevant activity and alerts were generated:

![image](https://github.com/user-attachments/assets/07eaa262-13a6-4177-978c-d39e442824e4)

**File integrity compromise shown in log data:**

![image](https://github.com/user-attachments/assets/f948f69d-1c8e-4223-a23e-3270e9dd6daf)


**WinRM (Kerberos) logins:**

![image](https://github.com/user-attachments/assets/7a0cca3c-7766-4b15-aff1-83d5ccfa9d65)


**Failed SSH login attempts:**

![image](https://github.com/user-attachments/assets/b0506883-461a-4b92-acc9-f023d5562626)
