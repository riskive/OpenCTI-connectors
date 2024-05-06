from zerofox.app.endpoints import CTIEndpoint

from mappers.malwareToMalware import malware_to_malware


def threat_feed_to_stix(feed):
    return {
        CTIEndpoint.Malware: malware_to_malware,


    }.get(feed)