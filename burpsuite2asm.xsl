<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" >

<xsl:output omit-xml-declaration="yes" indent="yes"/>
<xsl:template match="/">
  <scanner_vulnerabilities>
      <xsl:for-each select="//issue">
        <vulnerability>
          <xsl:variable name="Attack" select="current()/name"/>
          <xsl:choose>
              <xsl:when test="contains($Attack, 'OS command injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SQL injection')">              <attack_type>SQL-Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SQL injection (second order)')">              <attack_type>SQL-Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'ASP.NET tracing enabled')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'File path traversal')">              <attack_type>Path Traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'XML external entity injection')">              <attack_type>XML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'LDAP injection')">              <attack_type>LDAP Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'XPath injection')">              <attack_type>XPath Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'XML injection')">              <attack_type>XML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'ASP.NET debugging enabled')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTTP PUT method is enabled')">              <attack_type>HTTP Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Out-of-band resource load (HTTP)')">              <attack_type>HTTP Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'File path manipulation')">              <attack_type>Path Traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'PHP code injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Server-side JavaScript code injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Perl code injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Ruby code injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Python code injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Expression Language injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Unidentified code injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Server-side template injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SSI injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-site scripting (stored)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTTP response header injection')">              <attack_type>HTTP Response Splitting</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-site scripting (reflected)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side template injection')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-site scripting (DOM-based)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-site scripting (reflected DOM-based)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-site scripting (stored DOM-based)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'JavaScript injection (DOM-based)')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'JavaScript injection (reflected DOM-based)')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'JavaScript injection (stored DOM-based)')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Path-relative style sheet import')">              <attack_type>Path Traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side SQL injection (DOM-based)')">              <attack_type>SQL-Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side SQL injection (reflected DOM-based)')">              <attack_type>SQL-Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side SQL injection (stored DOM-based)')">              <attack_type>SQL-Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'WebSocket hijacking (DOM-based)')">              <attack_type>WebSocket Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'WebSocket hijacking (reflected DOM-based)')">              <attack_type>WebSocket Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'WebSocket hijacking (stored DOM-based)')">              <attack_type>WebSocket Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Local file path manipulation (DOM-based)')">              <attack_type>Path Traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Local file path manipulation (reflected DOM-based)')">              <attack_type>Path Traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Local file path manipulation (stored DOM-based)')">              <attack_type>Path Traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side XPath injection (DOM-based)')">              <attack_type>XPath Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side XPath injection (reflected DOM-based)')">              <attack_type>XPath Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side XPath injection (stored DOM-based)')">              <attack_type>XPath Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side JSON injection (DOM-based)')">              <attack_type>JSON Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side JSON injection (reflected DOM-based)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side JSON injection (stored DOM-based)')">              <attack_type>Cross Site Scripting (XSS)</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Flash cross-domain policy')">              <attack_type>Cross-site Request Forgery</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Silverlight cross-domain policy')">              <attack_type>Cross-site Request Forgery</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-origin resource sharing')">              <attack_type>Cross-site Request Forgery</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-origin resource sharing: arbitrary origin trusted')">              <attack_type>Cross-site Request Forgery</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-origin resource sharing: unencrypted origin trusted')">              <attack_type>Weak clientaccesspolicy.xml or crossdomain.xml policy</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-origin resource sharing: all subdomains trusted')">              <attack_type>Weak clientaccesspolicy.xml or crossdomain.xml policy</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-site request forgery')">              <attack_type>Cross-site Request Forgery</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SMTP header injection')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cleartext submission of password')">              <attack_type>Authentication/Authorization Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'External service interaction (DNS)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'External service interaction (HTTP)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'External service interaction (SMTP)')">              <attack_type>Other Applications Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Referer-dependent response')">              <attack_type>Other Applications Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Spoofable client IP address')">              <attack_type>HTTP Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'User agent-dependent response')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Password returned in later response')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Password submitted using GET method')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Password returned in URL query string')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SQL statement in request parameter')">              <attack_type>SQl-Injection</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-domain POST')">              <attack_type>Cross-site Request Forgery</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'ASP.NET ViewState without MAC enabled')">              <attack_type>Other Applications Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'XML entity expansion')">              <attack_type>XML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Long redirection response')">              <attack_type>Large request body allowed</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Serialized object in HTTP message')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Duplicate cookies set')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Input returned in response (stored)')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Input returned in response (reflected)')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Suspicious input transformation (reflected)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Suspicious input transformation (stored)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Open redirection (reflected)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Open redirection (stored)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Open redirection (DOM-based)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Open redirection (reflected DOM-based)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Open redirection (stored DOM-based)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SSL cookie without secure flag set')">              <attack_type>Set-Cookie does not use Secure keyword</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cookie scoped to parent domain')">              <attack_type>HTTP Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-domain Referer leakage')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cross-domain script include')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cookie without HttpOnly flag set')">              <attack_type>Set-Cookie does not use HTTPOnly keyword</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Session token in URL')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Password field with autocomplete enabled')">              <attack_type>Autocomplete not disabled on login form</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Password value set in cookie')">              <attack_type>Logins sent over unencrypted</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'File upload functionality')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Frameable response (potential Clickjacking)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Browser cross-site scripting filter disabled')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTTP TRACE method is enabled')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cookie manipulation (DOM-based)')">              <attack_type>Abuse of Functionality</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cookie manipulation (reflected DOM-based)')">              <attack_type>Abuse of Functionality</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cookie manipulation (stored DOM-based)')">              <attack_type>Abuse of Functionality</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Ajax request header manipulation (DOM-based)')">              <attack_type>Abuse of Functionality</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Ajax request header manipulation (reflected DOM-based)')">              <attack_type>Abuse of Functionality</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Ajax request header manipulation (stored DOM-based)')">              <attack_type>Abuse of Functionality</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Denial of service (DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Denial of service (reflected DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Denial of service (stored DOM-based)')">              <attack_type>Denial of Service</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML5 web message manipulation (DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML5 web message manipulation (reflected DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML5 web message manipulation (stored DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML5 storage manipulation (DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML5 storage manipulation (reflected DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML5 storage manipulation (stored DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Link manipulation (DOM-based)')">              <attack_type>Parameter Tampering</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Link manipulation (reflected DOM-based)')">              <attack_type>Parameter Tampering</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Link manipulation (stored DOM-based)')">              <attack_type>Parameter Tampering</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Link manipulation (reflected)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Link manipulation (stored)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Document domain manipulation (DOM-based)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Document domain manipulation (reflected DOM-based)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Document domain manipulation (stored DOM-based)')">              <attack_type>Open Redirect</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'DOM data manipulation (DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'DOM data manipulation (reflected DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'DOM data manipulation (stored DOM-based)')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'CSS injection (reflected)')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'CSS injection (stored)')">              <attack_type>Injection Attempt</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side HTTP parameter pollution (reflected)')">              <attack_type>Parameter pollution allowed</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Client-side HTTP parameter pollution (stored)')">              <attack_type>Parameter pollution allowed</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Form action hijacking (reflected)')">              <attack_type>Parameter Tampering</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Form action hijacking (stored)')">              <attack_type>Parameter Tampering</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Database connection string disclosed')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Source code disclosure')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Directory listing')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Email addresses disclosed')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Private IP addresses disclosed')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Social security numbers disclosed')">              <attack_type>Information Leakage - SSN</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Credit card numbers disclosed')">              <attack_type>Information Leakage - Credit Card</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Private key disclosed')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Robots.txt file')">              <attack_type>Information Leakage</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Cacheable HTTPS response')">              <attack_type>Form caching detected</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Base64-encoded data in parameter')">              <attack_type>Detection Evasion</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Multiple content types specified')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML does not specify charset')">              <attack_type>HTML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'HTML uses unrecognized charset')">              <attack_type>HTML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Content type incorrectly stated')">              <attack_type>HTML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Content type is not specified')">              <attack_type>HTML Parser Attack</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'SSL certificate')">              <attack_type>Mixed content found</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Unencrypted communications')">              <attack_type>Mixed content found</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Strict transport security not enforced')">              <attack_type>Mixed content found</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Mixed content')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Extension generated issue')">              <attack_type>Other Application Attacks</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Frameable response (potential Clickjacking)')">              <attack_type>Clickjacking</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Path-relative style sheet import')">              <attack_type>Path traversal</attack_type>            </xsl:when>
              <xsl:when test="contains($Attack, 'Base64-encoded data in parameter')">              <attack_type>Detection Evasion</attack_type>            </xsl:when>
            <xsl:otherwise>
              <attack_type>Other Application Attacks</attack_type>
            </xsl:otherwise>
          </xsl:choose>
          <originalattack><xsl:value-of select="name" /></originalattack>
          <host><xsl:value-of select="host"/></host>
          <request><xsl:value-of select="requestresponse/request"/></request>
          <url><xsl:value-of select="path"/></url>
          <cookie></cookie>
          <threat><xsl:value-of select="severity"/></threat>
          <xsl:variable name="threat_score" select="confidence"/>
          <!--<xsl:choose>
            <xsl:when test="$threat_score='Certain'">
              <threat>High</threat>
            </xsl:when>
            <xsl:when test="$threat_score='Firm'">
              <threat>Medium</threat>
            </xsl:when>
            <otherwise>
              <threat>Low</threat>
            </otherwise>
          </xsl:choose> -->
          <score></score>
          <severity><xsl:value-of select="severity"/></severity>
          <status>open</status>
          <opened>1</opened>
          <method><xsl:value-of select="requestresponse/request/@method"/></method>
          <response-encoding><xsl:value-of select="requestresponse/request/@base64"/></response-encoding>
          <source-address><xsl:value-of select="host/@ip"/></source-address>
          <issueDetail><xsl:value-of select="issueDetail"/></issueDetail>
          <issueDetailItems><xsl:value-of select="issueDetailItems"/>
          </issueDetailItems>
      </vulnerability>
      </xsl:for-each>
    </scanner_vulnerabilities>
</xsl:template>
</xsl:stylesheet>