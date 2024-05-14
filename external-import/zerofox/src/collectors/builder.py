from zerofox.app.endpoints import CTIEndpoint
from collectors.collector import Collector
from collectors.mappers import threat_feed_to_stix

def build_collectors(client, feeds):
    """Builds collectors for the ZeroFox connector.

    Args:
        client: The ZeroFox client.
        feeds: A list of feeds to collect.

    Returns:
        A dictionary of collectors.
    """
    collectors = {}
    feeds = feeds if feeds else CTIEndpoint

    for feed in feeds:
        collectors[str(feed)] = Collector(feed, threat_feed_to_stix(feed), client)
    return collectors