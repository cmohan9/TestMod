I have reviewed your query regarding the network connectivity required for our services.
To use the Idira EPM SaaS solution, endpoints where EPM agents are installed must have network access to different service URLs.
In addition, make sure that third-party application installed on the endpoints do not block communication with EPM SaaS.
For a comprehensive list of required URLs, please refer to our documentation:
https://docs.cyberark.com/epm/latest/en/content/installation/network-setup.htm

https://docs.cyberark.com/epm/latest/en/content/installation/network-setup.htm#ServiceURLs

https://docs.cyberark.com/epm/latest/en/content/installation/network-setup.htm#ServiceURLsforaspecificregion

You can conduct some agent connectivity tests to verify:
- S3 URL test:
PowerShell: Type the command: “tnc {URL’s} -p 443” and replace {URL’s} with the actual URL from the table above:
For example, region USA:
tnc files-na.epm.cyberark.com -p 443
A successful response should have the line “TcpTestSucceeded : True”

- URL for endpoints-service communication test:
PowerShell: Type the command: “tnc {URL’s} -p 443” and replace {URL’s} with the actual URL from the table above:
For example, region USA:
tnc agents-na.epm.cyberark.com -p 443
A successful response should have the line “TcpTestSucceeded : True”

- DNS Lookup test:
Run the following command in CMD:
"nslookup {URL's}"
and replace {URL’s} with the actual URL from the table above.
For example, region USA:
agents-na.epm.cyberark.com

It is also crucial to ensure TLS inspection is disabled, as this functionality is not supported by EPM agents.
In order to validate if SSL Inspection is in-place, there's a few options depending upon your platform:
https://community.cyberark.com/s/article/EPM-Agent-and-SSL-TLS-Inspection
