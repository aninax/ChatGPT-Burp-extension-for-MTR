# ChatGPT-Burp-extension-for-MTR

make me Burp script for MTR


Creating an MTR (My Traceroute) script in Burp Suite using Jython involves combining the functionalities of the ping and traceroute commands. Here's a basic example:
```
python

from java.lang import Runtime
from java.io import BufferedReader, InputStreamReader

def mtr(target_host):
    print "MTR Results for: ", target_host
    print "--------------------------------------"

    try:
        process_ping = Runtime.getRuntime().exec("ping -c 1 " + target_host)
        ping_reader = BufferedReader(InputStreamReader(process_ping.getInputStream()))
        ping_line = ping_reader.readLine()

        if "0 received" in ping_line:
            print "Ping to", target_host, "failed."
            return

        for ttl in range(1, 31):
            print "TTL=", ttl, "\t"
            process_traceroute = Runtime.getRuntime().exec("traceroute -n -m " + str(ttl) + " " + target_host)
            traceroute_reader = BufferedReader(InputStreamReader(process_traceroute.getInputStream()))
            traceroute_line = traceroute_reader.readLine()

            while traceroute_line:
                print traceroute_line
                traceroute_line = traceroute_reader.readLine()

    except Exception, e:
        print "Error: ", e
```
# Example usage:
mtr("example.com")

This script sends a ping to the specified host and then performs a traceroute for increasing Time-To-Live (TTL) values up to 30. Ensure that the necessary permissions are granted to execute the ping and traceroute commands.

To use this script in Burp Suite:

    Open Burp Suite.
    Go to the "Extender" tab.
    Click on the "Extensions" tab and then the "BApp Store" tab.
    Search for the "Jython" extension and install it.
    Go back to the "Extender" tab and click the "Extensions" tab.
    Click "Add" and select the Jython extension.
    Load the script and run it using the provided interface.

Make sure to adjust the script and handle exceptions appropriately based on the specific requirements of your use case.

User
change in this code target host with scope from Burp

ChatGPT

To access the scope from Burp Suite in a Jython script, you can use the IBurpExtenderCallbacks interface. Here's an updated version of the MTR script that fetches the target hosts from Burp's scope:
```
python

from java.io import BufferedReader, InputStreamReader
from java.lang import Runtime
from burp import IBurpExtender
from burp import IHttpRequestResponse
from burp import IScannerInsertionPointProvider

class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("MTR Tool")

        callbacks.registerScannerInsertionPointProvider(CustomScannerInsertionPointProvider())

class CustomScannerInsertionPointProvider(IScannerInsertionPointProvider):
    def __init__(self):
        self.target_hosts = []

    def getInsertionPoints(self, baseRequestResponse):
        self.target_hosts = self.fetch_scope()
        insertion_points = []
        for host in self.target_hosts:
            insertion_points.append(CustomInsertionPoint(baseRequestResponse, host))
        return insertion_points

    def fetch_scope(self):
        http_traffic = self._callbacks.getProxyHistory()
        target_hosts = set()
        for traffic in http_traffic:
            request_info = self._helpers.analyzeRequest(traffic)
            url = request_info.getUrl()
            target_hosts.add(url.getHost())
        return list(target_hosts)

class CustomInsertionPoint:
    def __init__(self, baseRequestResponse, target_host):
        self._baseRequestResponse = baseRequestResponse
        self._target_host = target_host

    def buildRequest(self, payload):
        mtr(self._target_host)

def mtr(target_host):
    print "MTR Results for: ", target_host
    print "--------------------------------------"

    try:
        process_ping = Runtime.getRuntime().exec("ping -c 1 " + target_host)
        ping_reader = BufferedReader(InputStreamReader(process_ping.getInputStream()))
        ping_line = ping_reader.readLine()

        if "0 received" in ping_line:
            print "Ping to", target_host, "failed."
            return

        for ttl in range(1, 31):
            print "TTL=", ttl, "\t"
            process_traceroute = Runtime.getRuntime().exec("traceroute -n -m " + str(ttl) + " " + target_host)
            traceroute_reader = BufferedReader(InputStreamReader(process_traceroute.getInputStream()))
            traceroute_line = traceroute_reader.readLine()

            while traceroute_line:
                print traceroute_line
                traceroute_line = traceroute_reader.readLine()

    except Exception, e:
        print "Error: ", e

# Instantiate the BurpExtender
if __name__ == "__main__":
    BurpExtender()
```
This script fetches the target hosts from the Burp scope using the IScannerInsertionPointProvider interface and then runs the MTR function for each target host. Make sure to configure the Burp Suite to use Jython and run the script. Adjust the script and handle exceptions appropriately based on the specific requirements of your use case.
