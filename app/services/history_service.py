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

    conn.close()

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "dangerous": dangerous,
        "avg_risk": avg_risk
    }