### Scan7  

#### The Problem  
There is not a great solution in the Open-Source community for performing license, vulnerability and secret detection in a single platform. You end up having to resort to a bunch of shell scripts or purchasing a commercial tool.

#### What does it do?  
Scans private/public code repositories for license, vulnerability and secrets data. Track data overtime in the web console and is ideal for security teams.

#### What is the perfect use case?  
The current design is ideal for a Security Assurance team that wishes to run out-of-band scans against their company repo's to track licenses, vulnerabilities and secrets at a code level.

#### Limitations?  
+ Not ideal to be placed in the CI/CD flow. There is not a API to start/stop commands but that is on the roadmap  
+ Not ideal if you need quick and fast results

#### Getting Started  
Unfortunately I have not got around to "Dockerizing" this project..  
1.) Install postgresql server  
2.) Install docker  
3.) Clone this repo  
4.) Run `pip3 install -r requirements.txt`  
5.) Run `flask run --cert=adhoc -h 0.0.0.0 -p 443` (May have to install openssl for using Adhoc certs)

#### Roadmap  
+ Support for CI/CD  
+ Customization for the different scan types  
+ Dockerize everything

#### Credits  
Scan7 utilizes the following Open-Source tools to perform the scanning functionality:  
+ Scancode (https://github.com/nexB/scancode-toolkit)  
+ Gitleaks (https://github.com/zricethezav/gitleaks)  
+ OWASP Dependency Check (https://jeremylong.github.io/DependencyCheck/) 
