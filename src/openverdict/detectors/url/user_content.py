"""Hosts where anyone can publish content: never allowlisted, never host-level feed matches."""

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
    }
)


def is_user_content(host: str) -> bool:
    return any(suffix in USER_CONTENT_HOSTS for suffix in host_suffixes(host))
