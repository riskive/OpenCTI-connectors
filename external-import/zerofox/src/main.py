import os
import sys
import time
from datetime import datetime
from typing import Any, List

import stix2
from lib.external_import import ExternalImportConnector
from mappers import threat_feed_to_stix
from zerofox.app import CTIEndpoint, ZeroFox


class ZeroFoxConnector(ExternalImportConnector):
    def __init__(self):
        """ ZeroFox connector for OpenCTI."""
        super().__init__()
        self.zerofox_username = os.environ.get("ZEROFOX_USERNAME", "")
        self.zerofox_password = os.environ.get("ZEROFOX_PASSWORD", "")
        self.client = ZeroFox(user=self.zerofox_username,
                              token=self.zerofox_password)

    def _collect_intelligence(self, last_run: datetime) -> List[Any]:
        """
        Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects.
        """
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []
        # ===========================
        for endpoint in [CTIEndpoint.Malware]:
            for entry in self.client.fetch_feed(endpoint, last_run):
                stix_objects.extend(threat_feed_to_stix(endpoint)(entry))
        self.helper.log_debug("Creating a sample reference using STIX2...")
        main_reference = stix2.ExternalReference(
            source_name="ZeroFox Threat Intelligence",
            url="https://www.zerofox.com/threat-intelligence/",
            description="ZeroFox provides comprehensive, accurate, and timely intelligence bundles through its API.",
        )

        self.helper.log_debug("Creating an observable for the IPv4...")
        ipv4_observable = stix2.IPv4Address(
            value="2.2.2.2",
            object_marking_refs=[stix2.TLP_GREEN],
            custom_properties={
                "description": "A sample observable created for the tutorial.",
                "labels": ["test", "tutorial"],
                "x_opencti_create_indicator": False,
                "external_references": [main_reference],
            },
        )
        stix_objects.append(ipv4_observable)
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = ZeroFoxConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
