"""Hosts where anyone can publish content or redirects: never allowlisted, never host-level
feed matches. Their popularity says nothing about a particular link."""

from openverdict.models.url import host_suffixes

USER_CONTENT_HOSTS = frozenset(
    {
        "docs.google.com",
        "drive.google.com",
        "sites.google.com",
        "forms.gle",
        "googleusercontent.com",
        "storage.googleapis.com",
        "firebaseapp.com",
        "web.app",
        "appspot.com",
        "github.io",
        "githubusercontent.com",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "r2.dev",
        "netlify.app",
        "vercel.app",
        "herokuapp.com",
        "glitch.me",
        "replit.app",
        "blob.core.windows.net",
        "azurewebsites.net",
        "web.core.windows.net",
        "sharepoint.com",
        "onedrive.live.com",
        "1drv.ms",
        "s3.amazonaws.com",
        "amazonaws.com",
        "cloudfront.net",
        "dropboxusercontent.com",
        "blogspot.com",
        "wordpress.com",
        "weebly.com",
        "weeblysite.com",
        "wixsite.com",
        "000webhostapp.com",
        "notion.site",
        "cdn.discordapp.com",
        "ngrok-free.app",
        "ngrok.io",
        "trycloudflare.com",
        "ipfs.io",
        "firebasestorage.googleapis.com",
        "script.google.com",
        "script.googleusercontent.com",
        "translate.goog",
        # URL shorteners and link hubs: the destination is unknown without following them.
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "lnkd.in",
        "linktr.ee",
        "rb.gy",
        "shorturl.at",
    }
)


def is_user_content(host: str) -> bool:
    return any(suffix in USER_CONTENT_HOSTS for suffix in host_suffixes(host))
