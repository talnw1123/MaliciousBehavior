"""
Web scraper module to fetch and parse webpage HTML
"""

import random
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from config import REQUEST_TIMEOUT, USER_AGENTS


class WebScraper:
    """Fetches and parses webpages for analysis."""

    def __init__(self):
        self.session = requests.Session()

    def _get_headers(self):
        """Return random user-agent headers to avoid blocking."""
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    def fetch_page(self, url):
        """
        Fetch a webpage and return parsed HTML.

        Args:
            url: The URL to fetch

        Returns:
            tuple: (BeautifulSoup object, raw HTML string, status_code) or (None, None, error_message)
        """
        # Ensure URL has a scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            response = self.session.get(
                url,
                headers=self._get_headers(),
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            return soup, response.text, response.status_code

        except requests.exceptions.Timeout:
            return None, None, "Request timed out"
        except requests.exceptions.ConnectionError:
            return None, None, "Connection error - unable to reach the website"
        except requests.exceptions.HTTPError as e:
            return None, None, f"HTTP error: {e}"
        except requests.exceptions.RequestException as e:
            return None, None, f"Request failed: {str(e)}"
        except Exception as e:
            return None, None, f"Unexpected error: {str(e)}"

    def get_base_domain(self, url):
        """Extract the base domain from a URL."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        return parsed.netloc
