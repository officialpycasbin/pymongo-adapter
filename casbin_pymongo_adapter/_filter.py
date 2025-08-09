class Filter:
    """
    Filter rule model
    """

    ptype = []
    v0 = []
    v1 = []
    v2 = []
    v3 = []
    v4 = []
    v5 = []

    # `raw_query` expected dict.
    # if set `raw_query`, all other filters are ignored
    raw_query = None
