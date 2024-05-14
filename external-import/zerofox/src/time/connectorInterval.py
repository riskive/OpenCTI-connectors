def get_interval(interval: str):
    """Returns the interval to use for the connector

    This SHOULD always return the interval in seconds. If the connector expects
    the parameter to be received as hours uncomment as necessary.
    """
    unit = interval[-1:]
    value = interval[:-1]

    try:
        if unit == "d":
            # In days:
            return int(value) * 60 * 60 * 24
        if unit == "h":
            # In hours:
            return int(value) * 60 * 60
        if unit == "m":
            # In minutes:
            return int(value) * 60
        if unit == "s":
            # In seconds:
            return int(value)
    except Exception as ex:
        raise ValueError(
            f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{interval}'. {str(ex)}"
        ) from ex
