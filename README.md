<table style="border: none">
    <tr style="text-align: left; border: none">
        <th style="height: auto; width: 125px; padding-top: 55px; border: none">
            <a href="https://www.lostrabbitlabs.com"><img src="https://lostrabbitlabs.com/hubfs/LRL%20logo.jpg" width="400"></a>
        </th>
        <th style="border: none">
            <h1> --- WisQuas-CLI --- </h1>
            <p><strong>WisQuas-CLI</strong> strips illusion from creatures hidden by the cloak of invisibility, instantly revealing their position. Nightshade cut many times to form a paper-like sheet, then carved into lace is secured by spider silk. It is glazed, dried in the sun, then crystallized into a shiny powder that must be tossed in the sky over the field of battle as the spell is cast.</p>
            <p>Have any questions 🐇? Reach out to us at [lostrabbitlabs.com](https://lostrabbitlabs.com)</p>
        </th>
    </tr>
</table>

<br>

---

## Contributors

<strong>Jimi Allee</strong> & <strong>Will Lenzini</strong>

---

## What is WisQuas

<p>A simple 'URL Revealer' (fast and lightweight scanner, enumerator, fingerprinter, fuzzer, assessor, and collector). Assists with finding vulnerabilities, anomalies, unique servers, available files/dirs, methods, and containers.</p>

---

## How does it work?
<p>Provide a URL to WisQuas and it will perform the following functions...</p>

* Resolve hostname to IP address
* Perform ASN lookup on IP address to provide ownership info and possible geolocation
* Inventories all received headers and cookies
* Baseline original URL request (with SSL cert info if HTTPS) to compare to all other requests
* Tactical fuzzing and enumeration to generate unique errors and reveal layered web services
* Inspect robots.txt file if available
* Inspect possible common SBOM packages
* Automatically harvest server-status URLs
* Enumerate through possible HTTP Verbs
* Perform Host Header Manipulation to detect additional accessible containers
* Automatically analyze response differences in HTTP protocol specifications

---

## Installation

The following python dependencies are required to run <strong>WisQuas-CLI</strong>:

```sh
pip install aiohttp bs4 requests tldextract colorama lxml
```

This script requires Python 3.10 or later. We recommend running it inside a Python virtual environment.

---

## Example Commands and Usage

WisQuas on URL using 'Desktop Browser' profile:

```sh
python3 wisquas-cli.py -1 "http://example.com/"
```

WisQuas on URL using 'Mobile Browser' profile:

```sh
python3 wisquas-cli.py -2 "http://example.com/"
```

WisQuas on URL using custom 'host header' on requests:

```sh
python3 wisquas-cli.py -1 "http://example.com/" customhostname
```

Create a PDF report from output (requires additional software):

```sh
python3 wisquas-cli.py -1 "http://example.com/" > example.com.txt; cat example.com.txt | aha -b | wkhtmltopdf - example.com.pdf
```

![WQ1](img/1.png)

![WQ1](img/2.png)

---

## License

MIT License