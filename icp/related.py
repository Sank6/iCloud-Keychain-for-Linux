"""Hand-curated sets of registrable domains that share one account system, so a login saved on
`google.com` also offers itself on `youtube.com`. Deliberately small and conservative - add a
group only when the sites really share sign-in. (Apple ships a similar list; this is not it.)"""

from . import psl

GROUPS = [
    {"google.com", "youtube.com", "gmail.com", "googleusercontent.com", "blogger.com"},
    {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "xbox.com", "bing.com",
     "outlook.com", "skype.com", "msn.com", "azure.com", "windows.com", "visualstudio.com"},
    {"apple.com", "icloud.com"},
    {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.co.jp",
     "amazon.it", "amazon.es", "amazon.in", "amazon.com.au", "audible.com", "twitch.tv"},
    {"facebook.com", "messenger.com", "fb.com"},
    {"twitter.com", "x.com"},
    {"github.com", "githubusercontent.com"},
    {"adobe.com", "behance.net"},
    {"paypal.com", "paypal.me"},
    {"ebay.com", "ebay.co.uk", "ebay.de"},
    {"yahoo.com", "aol.com"},
    {"steampowered.com", "steamcommunity.com"},
    {"dropbox.com", "dropboxapi.com"},
    {"atlassian.com", "atlassian.net", "bitbucket.org"},
]
_INDEX = {d: i for i, g in enumerate(GROUPS) for d in g}


def related(a: str, b: str) -> bool:
    """True if the two hosts belong to the same curated group (and are not simply identical)."""
    ra, rb = psl.registrable_domain(a), psl.registrable_domain(b)
    return ra != rb and ra in _INDEX and _INDEX.get(ra) == _INDEX.get(rb)
