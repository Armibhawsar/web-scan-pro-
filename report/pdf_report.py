# report/pdf_report.py
import pdfkit
import os

def html_to_pdf(html_path, pdf_path):
    # Use default pdfkit.from_file; ensure wkhtmltopdf is installed
    if not os.path.exists(html_path):
        raise FileNotFoundError("HTML report not found: " + html_path)
    # basic options
    options = {
        'page-size': 'A4',
        'encoding': "UTF-8",
        'margin-top': '10mm',
        'margin-bottom': '10mm',
        'margin-left': '10mm',
        'margin-right': '10mm'
    }
    pdfkit.from_file(html_path, pdf_path, options=options)
    return pdf_path
