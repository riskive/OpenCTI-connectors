from datetime import datetime
from zerofox.app.endpoints import CTIEndpoint
from typing import Any
from mappers.malwareToMalware import malware_to_malware
from mappers.ransomwareToMalware import ransomware_to_malware

def threat_feed_to_stix(feed: Any):
    return {
        CTIEndpoint.Malware: malware_to_malware,
        CTIEndpoint.Ransomware: ransomware_to_malware,


    }.get(feed)