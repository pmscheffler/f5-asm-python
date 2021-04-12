# f5-asm-python

April 12 2021

Peter Scheffler

This Python script will take a Burp Suite Scan Report XML file and output an F5 WAF-compatible XML file.

The script takes the following parameters:
    --input is the Burp Suite XML scan file
    --output is the F5 WAF-compatible file to be loaded into the Policy (as a 'Generic Scanner')
    --transform is the transformation file (the one supplied it burpsuite2asm.xsl)

The Input file is generated directly from a Burp Suite Scan

The Output file includes more info than ASM will consume but can be helpful for reviewing and assessing policy changes in the future.

The Transform file is a work in progress and if you encounter Vulnerabilities that need to be modified, I encourage you to open an Issue here and I am happy to review them.  The list I currently have are listed in the vuln-mappings CSV but if you feel some need to be re-mapped, please let me know


----

Note: 
This is supplied as-is and please ensure that you validate your scan report vs the mitigation settings before pushing this out to production and the WW-whacky-W.  I am happy to review the vulns-to-mitigations with you as you find discrepancies but make sure you test thoroughly.

