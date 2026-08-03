from app.database import get_connection


def save_scan(
    url,
    risk_score,
    status,
    registrar,
    domain_age,
    vt_malicious,
    vt_suspicious
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (
            url,
            risk_score,
            status,
            registrar,
            domain_age,
            vt_malicious,
            vt_suspicious
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        risk_score,
        status,
        registrar,
        domain_age,
        vt_malicious,
        vt_suspicious
    ))

    conn.commit()
    conn.close()


def get_scan_history(limit=50, search=""):

    conn = get_connection()
    cursor = conn.cursor()

    if search:

        cursor.execute("""
            SELECT *
            FROM scan_history
            WHERE url LIKE ?
            ORDER BY scan_time DESC
            LIMIT ?
        """, (f"%{search}%", limit))

    else:

        cursor.execute("""
            SELECT *
            FROM scan_history
            ORDER BY scan_time DESC
            LIMIT ?
        """, (limit,))

    history = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Safe'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Suspicious'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Dangerous'")
    dangerous = cursor.fetchone()[0]

    conn.close()

    return {
        "history": history,
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "dangerous": dangerous
    }


def get_dashboard_stats():

    conn = get_connection()
    cursor = conn.cursor()

    # Summary
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Safe'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Suspicious'")
    suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status='Dangerous'")
    dangerous = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ROUND(AVG(risk_score),2)
        FROM scan_history
    """)
    avg_risk = cursor.fetchone()[0] or 0

    # Highest Risk URLs
    cursor.execute("""
        SELECT url,risk_score,status
        FROM scan_history
        ORDER BY risk_score DESC
        LIMIT 5
    """)

    top_threats = [dict(row) for row in cursor.fetchall()]

    # Recent Activity
    cursor.execute("""
        SELECT
            url,
            risk_score,
            status,
            scan_time
        FROM scan_history
        ORDER BY scan_time DESC
        LIMIT 5
    """)

    recent = [dict(row) for row in cursor.fetchall()]

    from urllib.parse import urlparse

    cursor.execute("""
        SELECT url
        FROM scan_history
    """)

    domain_count = {}

    for row in cursor.fetchall():

        domain = urlparse(row["url"]).netloc

        if domain.startswith("www."):
            domain = domain[4:]

        if domain:
            domain_count[domain] = domain_count.get(domain, 0) + 1

    top_domains = [
        {
           "domain": domain,
           "count": count
        }
        for domain, count in sorted(
            domain_count.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
    ]

    cursor.execute("""
        SELECT DATE(scan_time) AS day,
               COUNT(*) AS scans
        FROM scan_history
        GROUP BY DATE(scan_time)
        ORDER BY DATE(scan_time)
    """)

    scan_trends = [dict(row) for row in cursor.fetchall()]


    conn.close()

    return {

         "total": total,
         "safe": safe,
         "suspicious": suspicious,
         "dangerous": dangerous,
         "avg_risk": avg_risk,

         "top_threats": top_threats,
         "scan_trends": scan_trends,
         "recent": recent,
         "top_domains": top_domains

    }