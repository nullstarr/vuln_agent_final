# Sources of the real sentences - open only when you have finished labeling

The sentences come from these public pages. **Note on accuracy:** retrieved with a tool that summarizes pages;
the sentences were requested as verbatim quotes and taken over unchanged (only formatting characters
removed), but a small deviation from the original page is possible. If you want to quote a sentence publicly, check it against the source.

- https://access.redhat.com/security/cve/cve-2021-44228
  > For Log4j versions >=2.10 set the system property log4j2.formatMsgNoLookups or the environment variable LOG4J_FORMAT_MSG_NO_LOOKUPS to true.
- https://access.redhat.com/security/cve/cve-2021-44228
  > This issue only affects log4j versions between 2.0 and 2.14.1.
- https://cwiki.apache.org/confluence/display/WW/S2-045
  > No backward incompatibility issues are expected with the recommended upgrades.
- https://cwiki.apache.org/confluence/display/WW/S2-045
  > Implement a Servlet filter which will validate Content-Type and throw away request with suspicious values not matching multipart/form-data.
- https://cwiki.apache.org/confluence/display/WW/S2-045
  > If you are using Jakarta based file upload Multipart parser, upgrade to Apache Struts version 2.3.32 or 2.5.10.1.
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  > Log4j version 2.15.0 contained an earlier fix for the vulnerability, but that patch did not disable attacker-controlled JNDI lookups in all situations.
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  > Additional backports of this fix have been made available in versions 2.3.1, 2.12.2, and 2.12.3.
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  > From log4j 2.16.0, this behavior has been disabled by default.
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  > Only the org.apache.logging.log4j:log4j-core package is directly affected by this vulnerability.
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  > Please note that Log4J v1 is End Of Life (EOL) and will not receive patches for this issue.
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  > Users who want to avoid attacker-controlled JNDI lookups but cannot upgrade to 2.16.0 must ensure that no such lookups resolve to attacker-provided data and ensure that the JndiLookup class is not loaded.
- https://heartbleed.com/
  > OpenSSL 1.0.1g is NOT vulnerable.
- https://heartbleed.com/
  > As long as the vulnerable version of OpenSSL is in use it can be abused. Fixed OpenSSL has been released and now it has to be deployed.
- https://heartbleed.com/
  > Service providers and users have to install the fix as it becomes available for the operating systems, networked appliances and software they use.
- https://heartbleed.com/
  > OpenSSL 1.0.1g released on 7th of April 2014 fixes the bug.
- https://logging.apache.org/security.html
  > It was found that the fix to address CVE-2021-44228 in Log4j 2.15.0 was incomplete in certain non-default configurations.
- https://logging.apache.org/security.html
  > Upgrade to Log4j 2.3.1 (for Java 6), 2.12.2 (for Java 7), or 2.15.0 (for Java 8 and later).
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
  > Any workarounds are documented in the product-specific Cisco bugs, which are identified in the Vulnerable Products section.
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
  > Product fixes that are listed in this advisory will address both CVE-2021-44228 and CVE-2021-45046 unless otherwise noted.
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
  > Cisco has reviewed CVE-2021-45105 and CVE-2021-44832 and has determined that no Cisco products or cloud offerings are impacted.
- https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
  > Cisco assessed all products and services for impact from both CVE-2021-44228 and CVE-2021-45046.
- https://spring.io/security/cve-2022-22965
  > Users of affected versions should upgrade to the corresponding fixed version.
- https://spring.io/security/cve-2022-22965
  > There are other mitigation steps for applications that cannot upgrade to the above versions.
- https://spring.io/security/cve-2022-22965
  > If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable.
- https://spring.io/security/cve-2022-22965
  > The specific exploit requires the application to run on Tomcat as a WAR deployment.
- https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/23618
  > VMware products will update open source components (including log4j) to the latest available versions in future releases.
- https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/23618
  > VMware has investigated and has found no evidence that these vulnerabilities are exploitable in VMware products.
- https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/
  > The Jenkins infrastructure team is currently checking all Jenkins project infrastructure for the presence of vulnerable versions of the Log4j library.
- https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/
  > It is using the built-in Jetty web application container that is bundled inside Jenkins and does not include Log4j.
- https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/
  > If you are hosting your Jenkins in a separate web application container like Tomcat, Websphere, or Glassfish, check with the providers of those containers to assess if they are using a vulnerable version of Log4j.
- https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/
  > Jenkins plugins may be using Log4j.
- https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/
  > We may decide to disable some services temporarily out of an abundance of caution.
- https://www.jenkins.io/blog/2021/12/10/log4j2-rce-CVE-2021-44228/
  > The Jenkins security team has confirmed that Log4j is not used in Jenkins core.
- https://www.kb.cert.org/vuls/id/930724
  > FreeBSD does not ship Java or Apache log4j as part of the base operating system.
- https://www.kb.cert.org/vuls/id/930724
  > We have updated our software to prevent attacks, in some cases by upgrading log4j.
- https://www.kb.cert.org/vuls/id/930724
  > In Log4j 2.12.2 (for Java 7) and 2.16.0 (for Java 8 or later) the message lookups feature has been completely removed.
