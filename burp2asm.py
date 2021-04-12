from lxml import etree
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, Comment, dump, tostring as xmlToString
import base64
import email
from io import StringIO
from urllib import parse
import sys
import argparse


from xml.etree import ElementTree
from xml.dom import minidom

def prettify(elem):
    """Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")

def openReport(XSL, reportFile):
    # reportFile = './report_.xml'
    dom = etree.parse(reportFile)
    transform = etree.XSLT(etree.fromstring(XSL))
    s = str(transform(dom))
    tree = ElementTree.fromstring(s)
    # ElementTree.dump(tree)
    return tree

def addParam(f5Vuln, req, idi):
  if idi != None:
    for paramItem in req[1].split("&"):
      param = paramItem.split("=")
      if param[0] in idi:
        xmlOutParam = SubElement(f5Vuln, 'parameter')
        xmlOutParam.text = param[0]
        break

def openTransformFile(transformFile):
    with open(transformFile, 'r') as file:
        XSL = file.read().replace('\n', '')
    return XSL


def processXML(addParam, debugApp, tree):
    foundone = 0
    rootOutput = ElementTree.Element('scanner_vulnerabilities')
    for burpIssue in tree:
      rows = 1
      idiLines = None
      issueDetailItems = burpIssue.find('issueDetailItems')
      if issueDetailItems.text != None:
        idiLinesT = issueDetailItems.text.splitlines()
        idiLines = []
        for iditem in idiLinesT:
          if iditem != None:
            idiLines.append(iditem.strip())
            splititem = iditem.lstrip().split(" ")
        idiRows = len(idiLines)
        rows = idiRows - 2
        cookiesAdded = []
      for cnt in range(0, rows):
        f5Vuln = SubElement(rootOutput, "vulnerability")
        hostname = ""
        path = ""
        for burpIssueItem in burpIssue:
          if burpIssueItem.tag == "host":
            hostname = burpIssueItem.text
          if burpIssueItem.tag == "url":
            path = burpIssueItem.text
          if burpIssueItem.tag == "request":
            text_bytes = base64.b64decode(burpIssueItem.text)
            requestData = text_bytes.decode('ascii')
            xmlOutRequest = SubElement(f5Vuln, 'request-data')
            xmlOutRequest.text = requestData
            requestLines = requestData.split('\r\n')
            if requestLines[0][0:3] == "GET":
              if debugApp == 1:
                print("Request: " + requestLines[0])
              if requestLines[0].find("?") > 0:
                req = requestLines[0].split("?")
                addParam(f5Vuln, req, idiLines)
            elif requestLines[0][0:4] == "POST":
              rowCount = 0
              for postline in requestLines:
                if postline == "":
                  payload = requestLines[rowCount + 1]
                  addParam(f5Vuln, req, idiLines)
                  break
                rowCount +=1
              foundone = 0
            else:
              
              print("\n\n\n***** Error *****")
              print("Found an unhandled Method")
              print("Request: " + requestLines[0])
              print("Full request: " + requestData)
            _, headers = requestData.split('\r\n',1)
            message = email.message_from_file(StringIO(headers))
            # construct a dictionary containing the headers
            headers = dict(message.items())
            for header in headers:
              if header.lower() == "cookie":
                cookieBreakOut = False
                if idiLines != None:
                  cookies = headers[header].split("; ")
                  for cookie in cookies:
                    if cookieBreakOut:
                      break
                    cookiesplit = cookie.split("=")
                    # now we look to see if we need to add the cookie from the ,                
                    # list is the issueDetailItems
                    for iditem in idiLines:
                      if cookieBreakOut:
                        break
                      splititem = iditem.lstrip().split(" ")
                      if len(splititem) > 1:
                        if cookiesplit[0] in splititem[1] and (splititem[1] not in cookiesAdded):
                          xmlCookie = SubElement(f5Vuln, 'cookie')
                          xmlCookie.text = cookiesplit[0]
                          cookiesAdded.append(splititem[1])
                          cookieBreakOut = True
                          break
              else:
                xmlHeaderItem = SubElement(f5Vuln, 'header')
                xmlHeaderItem.text = header
          else:
            if burpIssueItem.tag != "url":
              xmlOutItem = SubElement(f5Vuln, burpIssueItem.tag)
              xmlOutItem.text = burpIssueItem.text
        # out of the vulnerability, add some concatenated items
        xmlOutURL = SubElement(f5Vuln, "url")
        xmlOutURL.text = hostname + path
        if foundone == 1:
          break
    return rootOutput

if __name__ == "__main__":
  
  parser = argparse.ArgumentParser(description='Convert from Burp Suite Scan to F5 ASM format')
  parser.add_argument('--input', type=str, help='The file created by Burp Suite from the Scan in XML format')
  parser.add_argument('--transform', type=str, help='The Transform File, default is ./transform.xsd', default='./transform.xsd')
  parser.add_argument('--output', help='Output file to be opened by ASM, default is out.xml', default='./out.xml')

  args = parser.parse_args()

  debugApp = 0
  transformFile = args.transform
  reportFile = args.input  #'./report_.xml'
  XSL = openTransformFile(transformFile)

  tree = openReport(XSL, reportFile)
  rootOutput = processXML(addParam, debugApp, tree)
  # print(prettify(rootOutput))
  with open(args.output, 'w') as writer:
    writer.writelines(prettify(rootOutput))


