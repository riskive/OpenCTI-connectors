# standard library
from datetime import datetime

# first-party
from http_ import http_request
from zerofox.app.endpoints import CTIEndpoint


class CTIPoller:
    """ZeroFox client for the different Cyber Threat Intelligence Endpoints."""

    def __init__(self, user, token) -> None:
        """Client requires user and token for retrieving CTI token."""
        self._base_url = "https://api.zerofox.com"
        self.cti_token = self._get_cti_authorization_token(username=user, token=token)

    def fetch_feed(self, endpoint: CTIEndpoint, last_run: datetime):
        return self._cti_request(
            constructor=endpoint.factory, endpoint=endpoint.value, params={endpoint.after_key: last_run.isoformat()}
        )

    def _cti_request(
        self,
        constructor: type,
        endpoint,
        params=None,
        data=None,
    ):
        """Perform requests on ZeroFox's CTI endpoints.

        :param endpoint: Specific CTI endpoint
        :param params: The request's query parameters
        :param data: The request's body parameters
        :return: Returns the content of the response received from the API.
        """
        headers = self._get_cti_request_header()

        url = f"{self._base_url}/cti/{endpoint}/"

        response = http_request(
            method="GET",
            url=url,
            headers=headers,
            params=params,
            data=data,
            ok_code=200,
        )

        for result in response["results"]:
            yield constructor(**result)
        while response["next"]:
            response = http_request(
                method="GET",
                headers=headers,
                ok_code=200,
                url=response["next"],
            )
            for result in response["results"]:
                yield constructor(**result)

    def _get_cti_authorization_token(self, username, token) -> str:
        """Retrieve uthorization token for the CTI feed."""
        response_content = http_request(
            method="POST",
            ok_code=200,
            url=f"{self._base_url}/auth/token/",
            data=dict(username=username, password=token),
        )
        return response_content.get("access", "")

    def _get_cti_request_header(self):
        return {
            "Authorization": f"Bearer {self.cti_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
