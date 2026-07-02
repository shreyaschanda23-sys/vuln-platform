from utils.logger import get_logger
from scanners.subfinder import SubfinderScanner
from scanners.nmap import NmapScanner
from scanners.httpx_scanner import HttpxScanner
from scanners.katana_scanner import KatanaScanner
from scanners.nuclei_scanner import NucleiScanner

logger = get_logger(__name__)


class Orchestrator:
    """
    Chains all pipeline stages in order.
    Manages scan state and passes output between stages.
    """

    def __init__(self, scan_id: int, domain: str):
        self.scan_id = scan_id
        self.domain = domain
        self.results = {
            "scan_id": scan_id,
            "domain": domain,
            "subdomains": [],
            "ports": [],
            "endpoints": [],
            "findings": []
        }

    def run(self) -> dict:
        logger.info(f"Starting pipeline for {self.domain}")

        # Stage 1 — subdomain enumeration
        self._run_stage("recon", self._stage_recon)

        # Stage 2 — port scanning
        self._run_stage("port_scan", self._stage_port_scan)

        # Stage 3 — live host probing
        self._run_stage("live_hosts", self._stage_live_hosts)

        # Stage 4 — crawling
        self._run_stage("crawl", self._stage_crawl)

        # Stage 5 — vulnerability scanning
        self._run_stage("vuln_scan", self._stage_vuln_scan)

        logger.info(f"Pipeline complete for {self.domain}")
        return self.results

    def _run_stage(self, stage_name: str, stage_fn):
        try:
            logger.info(f"Stage: {stage_name}")
            stage_fn()
        except Exception as e:
            logger.error(f"Stage {stage_name} failed: {e}")

    def _stage_recon(self):
        subdomains = SubfinderScanner().scan(self.domain)
        self.results["subdomains"] = subdomains
        logger.info(f"Found {len(subdomains)} subdomains")

    def _stage_port_scan(self):
        targets = [self.domain] + [
            s["host"] for s in self.results["subdomains"][:5]
        ]
        all_ports = []
        for target in targets:
            ports = NmapScanner().scan(target)
            all_ports.extend(ports)
        self.results["ports"] = all_ports
        logger.info(f"Found {len(all_ports)} open ports")

    def _stage_live_hosts(self):
        targets = [self.domain] + [
            s["host"] for s in self.results["subdomains"][:10]
        ]
        all_endpoints = []
        for target in targets:
            endpoints = HttpxScanner().scan(f"https://{target}")
            all_endpoints.extend(endpoints)
        self.results["endpoints"] = all_endpoints
        logger.info(f"Found {len(all_endpoints)} live endpoints")

    def _stage_crawl(self):
        endpoints = self.results["endpoints"][:5]
        all_urls = []
        for ep in endpoints:
            urls = KatanaScanner().scan(ep["url"])
            all_urls.extend(urls)
        logger.info(f"Crawled {len(all_urls)} URLs")

    def _stage_vuln_scan(self):
        targets = [ep["url"] for ep in self.results["endpoints"][:5]]
        all_findings = []
        for target in targets:
            findings = NucleiScanner().scan(target)
            all_findings.extend(findings)
        self.results["findings"] = all_findings
        logger.info(f"Found {len(all_findings)} vulnerabilities")
