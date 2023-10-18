from java.io import BufferedReader, InputStreamReader
from java.lang import Runtime
import subprocess
import re
import platform
import os
from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint


class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("MTR Tool")
        self._callbacks.registerScannerInsertionPointProvider(CustomScannerInsertionPointProvider(self._callbacks))

class CustomScannerInsertionPointProvider(IScannerInsertionPointProvider):

    def __init__(self, callbacks):
        self._callbacks = callbacks

    def getInsertionPoints(self, baseRequestResponse):
        http_traffic = self._callbacks.getProxyHistory()
        target_hosts = set()
        for traffic in http_traffic:
            request_info = self._callbacks.getHelpers().analyzeRequest(traffic)
            url = request_info.getUrl()
            target_hosts.add(url.getHost())

        insertion_points = []
        for host in target_hosts:
            insertion_points.append(CustomInsertionPoint(baseRequestResponse, host, self._callbacks))
        return insertion_points

class CustomInsertionPoint(IScannerInsertionPoint):

    def __init__(self, baseRequestResponse, target_host, callbacks):
        self._baseRequestResponse = baseRequestResponse
        self._target_host = target_host
        self._callbacks = callbacks

    def getInsertionPointName(self):
        return "MTR Tool"

    def getBaseValue(self):
        if self._baseRequestResponse:
            return self._callbacks.getHelpers().bytesToString(self._baseRequestResponse.getRequest())
        else:
            return None

    def buildRequest(self, payload):
        if self._baseRequestResponse:
            mtr(self._target_host)
        else:
            print("Request is null.")



def mtr(target_host):
    traceroute_command = "tracert"  # Replace this with the appropriate traceroute command for Windows

    process_traceroute = os.popen(traceroute_command + " " + target_host)

    print("Tracing route to " + target_host)

    while True:
        hop = process_traceroute.readline()
        if not hop:
            break
        hop_data = hop.strip()
        print(hop_data)

        # Extract IP address
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hop_data)
        if ip_match:
            ip_address = ip_match.group()
            packet_loss = send_long_packet(ip_address)
            print("IP Address: {}, Packet Loss: {}%".format(ip_address, packet_loss))

def send_long_packet(ip_address):
    ping_command = "ping -n 3 -l 65500 " + ip_address  # Modify parameters as needed

    process = os.popen(ping_command)
    process_output = process.read()

    packet_loss = 0
    if "Lost = 0" not in process_output:  # Assuming 'Lost = 0' indicates no packet loss
        loss_match = re.search(r"Lost = (\d+)", process_output)
        if loss_match:
            lost_count = int(loss_match.group(1))
            packet_loss = (lost_count / 3) * 100  # Assuming the count is out of 3 packets

    return packet_loss

mtr("google.com")  # Example usage




# Instantiate the BurpExtender
if __name__ == "__main__":
    BurpExtender()
