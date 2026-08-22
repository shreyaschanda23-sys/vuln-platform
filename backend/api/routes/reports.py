from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from api.deps import get_db, get_current_user
from models.scan import Scan
from models.user import User
from services.reporter import (
    generate_json_report, generate_csv_report,
    generate_html_report, generate_pdf_report,
)

router = APIRouter(prefix="/api/reports", tags=["reports"])

CONTENT_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "html": "text/html",
    "pdf": "application/pdf",
}

GENERATORS = {
    "json": generate_json_report,
    "csv": generate_csv_report,
    "html": generate_html_report,
    "pdf": generate_pdf_report,
}


@router.get("/{scan_id}/{fmt}")
def download_report(
    scan_id: int,
    fmt: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if fmt not in GENERATORS:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    content = GENERATORS[fmt](scan_id, db)
    filename = f"scan_{scan_id}_report.{fmt}"

    return Response(
        content=content,
        media_type=CONTENT_TYPES[fmt],
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )