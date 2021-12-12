"""Module containing methods common to IOC processing"""

import re, os

# standardized date time format
# DATE_FMT = '{dt.month}/{dt.day}/{dt:%y} {dt.hour}:{dt.minute:02}'
DATE_FORMAT = '%m/%d/%y'# %H:%M'  # equates to MM/DD/YYYY

# Supported indicator types
INDICATOR_TYPES = [
    "ip",
    "domain",
    "email",
    "url",
    "md5",
    "sha1",
    "sha256",
    "misc"
]


web_url_regex =  re.compile("^" +
    # protocol identifier (optional)
    # short syntax // still required
    "(?:(?:(?:https?|ftp):)?\\/\\/)" +
    # user:pass BasicAuth (optional)
    "(?:\\S+(?::\\S*)?@)?" +
    "(?:" +
        # IP address exclusion
        # private & local networks
        "(?!(?:10|127)(?:\\.\\d{1,3}){3})" +
        "(?!(?:169\\.254|192\\.168)(?:\\.\\d{1,3}){2})" +
        "(?!172\\.(?:1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})" +
        # IP address dotted notation octets
        # excludes loopback network 0.0.0.0
        # excludes reserved space >= 224.0.0.0
        # excludes network & broadcast addresses
        # (first & last IP address of each class)
        "(?:[1-9]\\d?|1\\d\\d|2[01]\\d|22[0-3])" +
        "(?:\\.(?:1?\\d{1,2}|2[0-4]\\d|25[0-5])){2}" +
        "(?:\\.(?:[1-9]\\d?|1\\d\\d|2[0-4]\\d|25[0-4]))" +
    "|" +
    # host & domain names, may end with dot
    # can be replaced by a shortest alternative
    # (?![-_])(?:[-\\w\\u00a1-\\uffff]{0,63}[^-_]\\.)+
    "(?:" +
        "(?:" +
            "[a-z0-9\\u00a1-\\uffff]" +
            "[a-z0-9\\u00a1-\\uffff_-]{0,62}" +
        ")?" +
        "[a-z0-9\\u00a1-\\uffff]\\." +
    ")+" +
    # TLD identifier name, may end with dot
        "(?:[a-z\\u00a1-\\uffff]{2,}\\.?)" +
    ")" +
    # port number (optional)
    "(?::\\d{2,5})?" +
    # resource path (optional)
    "(?:[/?#]\\S*)?" +
  "$")


def indicator_type(indicator):
    """
    Matching the indicator with the correct regex. Indicator values consist of:
    ipv4, domain, email, sha256, sha1, md5. If none of these are the indicator,
    then the returned string will be 'unknown'
    :param str indicator: Indicator value -
    :return: data type or encryption method
    :rtype: str
    """

    # For IETF Standards, consult https://tools.ietf.org/html/rfc3696
    # TODO - IPv6 regex,
    # TODO - possibly update domain regex to handle '--' and '_'
    ipv4_regex = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    domain_regex = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}'
    email_regex = r'^(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
    sha256_regex = r'^[a-f0-9]{64}'
    sha1_regex = r'^[a-f0-9]{40}'
    md5_regex = r'^[a-f0-9]{32}'
    uri_regex = r'\w+:(\/?\/?)[^\s]+'
    # regex for ipv4 rfc1918 addresses
    ipv4_rfc1918_regex = r'(^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.1[6-9]{1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.2[0-9]{1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^172\.3[0-1]{1}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$)'

    if re.fullmatch(ipv4_regex, indicator):
        if re.fullmatch(ipv4_rfc1918_regex, indicator): return "misc"
        else: return "ip"
    elif re.fullmatch(domain_regex, indicator, re.IGNORECASE):
        return "host"
    elif re.fullmatch(email_regex, indicator):
        return "email"
    elif re.fullmatch(sha256_regex, indicator):
        return "hash"
    elif re.fullmatch(sha1_regex, indicator):
        return "hash"
    elif re.fullmatch(md5_regex, indicator):
        return "hash"
    elif re.fullmatch(web_url_regex, indicator):
        return "url"
    elif re.fullmatch(uri_regex, indicator):
        return "url"
    else: # miscellaneous IOC
        return "misc"


def www_strip(str):
    """
    Strips "www" from the front of a domain query
    :param str str: URL String
    :return: Stripped URL
    :rtype: str
    """
    www_regex = r'www[0-9]\.'
    if str.startswith('www.'):
        return str[4:]
    elif re.match(www_regex, str[0:5]):
        return str[5:]
    else:
        return str

class ResponseError(Exception):
    """
    Exception Class for when the response code is not 200
    """
    def __init__(self, value):
        # This 429 error code is specific to Crowdstrike Rate-Limit exceeded
        if value == 429:
            self.value = f"HTTP error code {value} received, rate-limit exceeded."
        self.value = f"HTTP error code {value} received"

    def __str__(self):
        return repr(self.value)


class InvalidAPIKey(Exception):
    """
    Exception Class for when the API Key is not correct.
    """
    def __init__(self, value=None):
        self.value = value or "Invalid API Key"

    def __str__(self):
        return repr(self.value)


class BadRequest(Exception):
    """
    Exception Class for when there is a Bad Request.
    """
    def __init__(self, value=None):
        self.value = value or "Bad Request"

    def __str__(self):
        return repr(self.value)


class RetryError(Exception):
    """
    Exception Class for when the maximum number of retries has happened.
    """
    def __init__(self, value=None):
        self.value = value or "Exceeded maximum number of retries"

    def __str__(self):
        return repr(self.value)

class DownloadError(Exception):
    """
    Exception Class for when the maximum number of retries has happened.
    """
    def __init__(self):
        self.value = "Download failed"

    def __str__(self):
        return repr(self.value)


class domain_whitelist:
    """
    Class to represent a domain whitelist

    Based on most common domains retrieved from https://github.com/MISP/misp-warninglists/tree/main/lists/cisco_top5k
    """

    def __init__(self):
        self.whitelist = []
        self.location = os.path.abspath('etc/local/domain_whitelist')


    def scan(self, str):
        """
        Scans whitelist for exact match to domain string

        :return: True/False on if string is found
        """
        for domain in self.whitelist:
            if domain == str: return True
        return False


class ip_whitelist:
    """
    Class to represent an IP whitelist
    """

    def __init__(self):
        self.whitelist = []


    def scan(self, str):
        """
        Scans whitelist for exact match to ip string

        :return: True/False on if string is found
        """
        for domain in self.whitelist:
            if domain == str: return True
        return False


# Static hash whitelist, best we have for now.
hash_whitelists = {
    "md5": {
        'd41d8cd98f00b204e9800998ecf8427e': "Empty file",
        '68b329da9893e34099c7d8ad5cb9c940': "One byte line break file (Unix) 0x0a",
        '81051bcc2cf1bedf378224b0a93e2877': "One byte line break file (Windows) 0x0d0a",
        '93b885adfe0da089cdf634904fd59f71': "One byte file with 0x00",
        '0f343b0931126a20f133d67c2b018a3b': "1024 bytes 0x00",
        'c99a74c555371a433d121f551d6c6398': "2048 bytes 0x00",
        '620f0b67a91f7f74151bc5be745b7110': "4096 bytes 0x00 - sometimes caused by an AV",
        'fa8715078d45101200a6e2bf7321aa04': "File filled with 99 zeros - sometimes caused by an AV",
        'c5e389341a0b19b6f045823abffc9814': "1x1 pixel JPEG",
        '325472601571f31e1bf00674c368d335': "1x1 tracking pixel GIF",
        'e617348b8947f28e2a280dd93c75a6ad': "Empty Word document",
        '200ceb26807d6bf99fd6f4f0d1ca54d4': "File that contains the word 'administrator'",
        'd3b07384d113edec49eaa6238ad5ff00': "File that contains the word 'foo\x0a'",
        'a6105c0a611b41b08f1209506350279e': "File that contains the word 'yes'",
        '10400c6faf166902b52fb97042f1e0eb': "File that contains 2\x0d\x0a",
        '4b6c7f3146f86136507497232d2f04a0': "File that contains 44 43 48 01 18 40 80 25 03 00 06 00 DCH..@.%.... (unknown)",
        'a11a2f0cfe6d0b4c50945989db6360cd': "WinPCap 4.1.3",
        '16e8e953c65d610c3bfc595240f3f5b7': "disallowedcertstl.cab",
        'e24133dd836d99182a6227dcf6613d08': "Powerpoint 2010",
        '41f958d2d3e9ed4504b6a8863fd72b49': "Special CAB file",
        'd378bffb70923139d6a4f546864aa61c': "MS Notepad",
        '86f1895ae8c5e8b17d99ece768a70732': "MSVCR71.DLL",
        'b6f9aa44c5f0565b5deb761b1926e9b6': "RecordedTV.library-ms",
        '8e325dc2fea7c8900fc6c4b8c6c394fe': "404 error message",
        '60ac8e889a1c2af330432bf793164a14': "404 error page"},
    "sha1": {
        'da39a3ee5e6b4b0d3255bfef95601890afd80709': "Empty file",
        'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc': "One byte line break file (Unix) 0x0a",
        'ba8ab5a0280b953aa97435ff8946cbcbb2755a27': "One byte line break file (Windows) 0x0d0a",
        '5ba93c9db0cff93f52b521d7420e43f6eda2784f': "One byte file with 0x00",
        '60cacbf3d72e1e7834203da608037b1bf83b40e8': "1024 bytes 0x00",
        '605db3fdbaff4ba13729371ad0c4fbab3889378e': "2048 bytes 0x00",
        '1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d': "4096 bytes 0x00 - sometimes caused by an AV",
        'd991c16949bd5e85e768385440e18d493ce3aa46': "File filled with 99 zeros - sometimes caused by an AV",
        'c82cee5f957ad01068f487eecd430a1389e0d922': "1x1 pixel JPEG",
        '2daeaa8b5f19f0bc209d976c02bd6acb51b00b0a': "1x1 tracking pixel GIF",
        '125da188e26bd119ce8cad7eeb1fc2dfa147ad47': "Empty Word document",
        'b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3': "File that contains the word 'administrator'",
        'f1d2d2f924e986ac86fdf7b36c94bcdf32beec15': "File that contains the word 'foo\x0a'",
        'fb360f9c09ac8c5edb2f18be5de4e80ea4c430d0': "File that contains the word 'yes'",
        'd583c3aa489ed954df3be71e71deae3a9895857e': "File that contains 2\x0d\x0a",
        'deabe082bc0f0f503292e537b2675c7c93dca40f': "File that contains 44 43 48 01 18 40 80 25 03 00 06 00 DCH..@.%.... (unknown)",
        'e2516fcd1573e70334c8f50bee5241cdfdf48a00': "WinPCap 4.1.3",
        '231a802e6ff1fae42f2b12561fff2767d473210b': "disallowedcertstl.cab",
        '72c2dbbb1fe642073002b30987fcd68921a6b140': "Powerpoint 2010",
        'f6d380b256b0e66ef347adc78195fd0f228b3e33': "Special CAB file",
        'f00aa51c2ed8b2f656318fdc01ee1cf5441011a4': "MS Notepad",
        'd5502a1d00787d68f548ddeebbde1eca5e2b38ca': "MSVCR71.DLL",
        '183d0929423da2aa83441ee625de92b213f33948': "RecordedTV.library-ms",
        '1b3291d4eea179c84145b2814cb53e6a506ec201': "404 error message",
        '3a92d2a4e959dfdffb53d106689682efcf23178b': "404 error page",
    },
    "sha256": {
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': "Empty file",
        '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b': "One byte line break file (Unix) 0x0a",
        '7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6': "One byte line break file (Windows) 0x0d0a",
        '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d': "One byte file with 0x00",
        '5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef': "1024 bytes 0x00",
        'e5a00aa9991ac8a5ee3109844d84a55583bd20572ad3ffcd42792f3c36b183ad': "2048 bytes 0x00",
        'ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7': "4096 bytes 0x00 - sometimes caused by an AV",
        '4b298058e1d5fd3f2fa20ead21773912a5dc38da3c0da0bbc7de1adfb6011f1c': "File filled with 99 zeros - sometimes caused by an AV",
        '995c770caeb45f7f0c1bc3affc60f11d8c40e16027df2cf711f95824f3534b6f': "1x1 pixel JPEG",
        'b1442e85b03bdcaf66dc58c7abb98745dd2687d86350be9a298a1d9382ac849b': "1x1 tracking pixel GIF",
        '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20': "Empty Word document",
        '4194d1706ed1f408d5e02d672777019f4d5385c766a8c6ca8acba3167d36a7b9': "File that contains the word 'administrator'",
        'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c': "File that contains the word 'foo\x0a'",
        '8a798890fe93817163b10b5f7bd2ca4d25d84c52739a645a889c173eee7d9d3d': "File that contains the word 'yes'",
        'df4e26a04a444901b95afef44e4a96cfae34690fff2ad2c66389c70079cdff2b': "File that contains 2\x0d\x0a",
        '4a15a6777284035dfd8df4ecf496b4f0557a9cc4ffaaf5887659031e843865e1': "File that contains 44 43 48 01 18 40 80 25 03 00 06 00 DCH..@.%.... (unknown)",
        'fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de': "WinPCap 4.1.3",
        '048846ed8ed185a26394adeb3f63274d1029bbd59cffa8e73a4ef8b19456de1d': "disallowedcertstl.cab",
        '4dde54cfc600dbd9a610645d197a632e064115ffaa3a1b595c3a23036e501678': "Powerpoint 2010",
        'c929701c67a05f90827563eedccf5eba8e65b2da970189a0371f28cd896708b8': "Special CAB file",
        'c4232ddd4d37b9c0884bd44d8476578c54d7f98d58945728e425736a6a07e102': "MS Notepad",
        '8094af5ee310714caebccaeee7769ffb08048503ba478b879edfef5f1a24fefe': "MSVCR71.DLL",
        '07c4c7ae2c4c7cb3ccd2ba9cd70a94382395ca8e2b0312c1631d09d790b6db33': "RecordedTV.library-ms",
        '0b52c5338af355699530a47683420e48c7344e779d3e815ff9943cbfdc153cf2': "404 error message",
        '70c65bd0e084398a87baa298c1fafa52afff402096cb350d563d309565c07e83': "404 error page",
    }
}