# fortinet-psirt-ps
This script retrieves the list of vulnerabiltiies from FortiGuard Lab's [PSIRT RSS feed](https://www.fortiguard.com/rss-feeds).     
It returns the date the vulnerability was published, the CVE ID, CVSS3 score, and the title of the vulnerability

![A screenshot of the actual command line output](./preview.png)

Inspired by the MSRC-PatchReview project:
[https://github.com/f-bader/MSRC-PatchReview]https://github.com/f-bader/MSRC-PatchReview

## Usage

To get a report, just run the script without any additional parameters. Note that FortiGuard Lab's PSIRT RSS feed only includes the most recent items.

```bash
$ .\fortinet_psirt_patch_review.ps1
```

### Change output format

Default is **human-readable** which will write the output to stdout. But if you would like to use the data in any way after the script is run you can use either **json** or **psobject**.

```bash
$ .\fortinet_psirt_patch_review.ps1 -Output json
```

```bash
$ .\fortinet_psirt_patch_review.ps1 -Output psobject
```

### Change CVE BaseScore

The highest rated CVEs are by default all CVEs above **8.0**. This can be changed easily to fit your needs.

```bash
$ .\fortinet_psirt_patch_review.ps1 -BaseScore 6
```
