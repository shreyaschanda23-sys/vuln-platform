from worker.celery import celery_app
from utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(bind=True, name="tasks.run_subfinder")
def run_subfinder(self, target: str) -> list[dict]:
    from scanners.subfinder import SubfinderScanner
    logger.info(f"Task: subfinder on {target}")
    self.update_state(state="RUNNING", meta={"stage": "recon", "tool": "subfinder"})
    return SubfinderScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_nmap")
def run_nmap(self, target: str) -> list[dict]:
    from scanners.nmap import NmapScanner
    logger.info(f"Task: nmap on {target}")
    self.update_state(state="RUNNING", meta={"stage": "port_scan", "tool": "nmap"})
    return NmapScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_httpx")
def run_httpx(self, target: str) -> list[dict]:
    from scanners.httpx_scanner import HttpxScanner
    logger.info(f"Task: httpx on {target}")
    self.update_state(state="RUNNING", meta={"stage": "live_hosts", "tool": "httpx"})
    return HttpxScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_katana")
def run_katana(self, target: str) -> list[dict]:
    from scanners.katana_scanner import KatanaScanner
    logger.info(f"Task: katana on {target}")
    self.update_state(state="RUNNING", meta={"stage": "crawl", "tool": "katana"})
    return KatanaScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_ffuf")
def run_ffuf(self, target: str) -> list[dict]:
    from scanners.ffuf_scanner import FfufScanner
    logger.info(f"Task: ffuf on {target}")
    self.update_state(state="RUNNING", meta={"stage": "crawl", "tool": "ffuf"})
    return FfufScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_nuclei")
def run_nuclei(self, target: str) -> list[dict]:
    from scanners.nuclei_scanner import NucleiScanner
    logger.info(f"Task: nuclei on {target}")
    self.update_state(state="RUNNING", meta={"stage": "vuln_scan", "tool": "nuclei"})
    return NucleiScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_sqlmap")
def run_sqlmap(self, target: str) -> list[dict]:
    from scanners.sqlmap_scanner import SqlmapScanner
    logger.info(f"Task: sqlmap on {target}")
    self.update_state(state="RUNNING", meta={"stage": "vuln_scan", "tool": "sqlmap"})
    return SqlmapScanner().scan(target)


@celery_app.task(bind=True, name="tasks.run_full_scan")
def run_full_scan(self, scan_id: int, domain: str) -> dict:
    """
    Full pipeline scan — chains all stages in order.
    """
    from services.orchestrator import Orchestrator
    logger.info(f"Starting full scan for domain: {domain} (scan_id: {scan_id})")
    self.update_state(state="RUNNING", meta={"stage": "starting", "domain": domain})
    orchestrator = Orchestrator(scan_id=scan_id, domain=domain)
    return orchestrator.run()
